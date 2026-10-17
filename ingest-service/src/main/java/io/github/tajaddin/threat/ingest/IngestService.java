package io.github.tajaddin.threat.ingest;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.tajaddin.threat.common.Event;
import io.github.tajaddin.threat.common.Json;
import io.github.tajaddin.threat.common.Topics;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.errors.TimeoutException;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

/**
 * The one path every event takes into the pipeline: duplicate suppression by event id, then an
 * idempotent produce to events.raw keyed by source so one source's events stay ordered. The ingest
 * timestamp travels as a record header; the detect stage measures its latency from it.
 */
@Service
public class IngestService {
  public record Result(int accepted, int duplicates) {}

  private final KafkaTemplate<String, String> kafka;
  private final Cache<String, Boolean> seen;
  private final Counter accepted;
  private final Counter duplicates;
  private final Counter failed;
  private final Timer produceTimer;

  public IngestService(
      KafkaTemplate<String, String> kafka, IngestProperties props, MeterRegistry registry) {
    this.kafka = kafka;
    this.seen =
        Caffeine.newBuilder()
            .expireAfterWrite(props.dedupWindow())
            .maximumSize(props.dedupMaxEntries())
            .build();
    this.accepted = Counter.builder("ingest.events").tag("outcome", "accepted").register(registry);
    this.duplicates =
        Counter.builder("ingest.events").tag("outcome", "duplicate").register(registry);
    this.failed = Counter.builder("ingest.events").tag("outcome", "failed").register(registry);
    this.produceTimer =
        Timer.builder("ingest.produce").publishPercentileHistogram().register(registry);
  }

  /**
   * Records are keyed by source address, then host, then feed name: that spreads one feed over all
   * partitions (keying by feed put a whole generator run on one partition) and keeps the events a
   * threshold rule groups by, mostly the source address, in order on one partition.
   */
  public static String partitionKey(Event e) {
    if (e.srcIp() != null && !e.srcIp().isBlank()) {
      return e.srcIp();
    }
    if (e.host() != null && !e.host().isBlank()) {
      return e.host();
    }
    return e.source();
  }

  /**
   * Produces the batch; returns once every record is acknowledged (acks=all) or throws on failure.
   */
  public Result accept(List<Event> events) {
    Instant now = Instant.now();
    byte[] ingestedAt = now.toString().getBytes(StandardCharsets.UTF_8);
    List<CompletableFuture<?>> futures = new ArrayList<>(events.size());
    int dup = 0;
    Timer.Sample sample = Timer.start();
    for (Event e : events) {
      if (seen.asMap().putIfAbsent(e.id(), Boolean.TRUE) != null) {
        dup++;
        continue;
      }
      ProducerRecord<String, String> record =
          new ProducerRecord<>(Topics.RAW, partitionKey(e), Json.write(e));
      record.headers().add(Topics.HEADER_INGESTED_AT, ingestedAt);
      futures.add(kafka.send(record));
    }
    try {
      CompletableFuture.allOf(futures.toArray(CompletableFuture[]::new)).join();
    } catch (RuntimeException ex) {
      failed.increment(futures.size());
      Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
      if (cause instanceof TimeoutException || cause.getCause() instanceof TimeoutException) {
        throw new ProducerBackpressureException(cause);
      }
      throw ex;
    } finally {
      sample.stop(produceTimer);
    }
    accepted.increment(futures.size());
    duplicates.increment(dup);
    return new Result(futures.size(), dup);
  }

  /** Raised when the producer cannot keep up (buffer full or broker slow): the API answers 503. */
  public static final class ProducerBackpressureException extends RuntimeException {
    public ProducerBackpressureException(Throwable cause) {
      super("producer backpressure: " + cause.getMessage(), cause);
    }
  }
}
