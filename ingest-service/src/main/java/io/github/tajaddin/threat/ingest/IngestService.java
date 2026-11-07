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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
   * An id is remembered for de-duplication only once its record is acknowledged, so a batch that
   * failed can be retried in full: the records that did reach Kafka count as duplicates, the rest
   * are produced. When a send throws, the ones issued before it are still in flight, so they are
   * awaited (no longer than the producer's delivery timeout) before the acknowledged ids are read.
   */
  public Result accept(List<Event> events) {
    Instant now = Instant.now();
    byte[] ingestedAt = now.toString().getBytes(StandardCharsets.UTF_8);
    Map<String, CompletableFuture<?>> sends = new LinkedHashMap<>();
    int dup = 0;
    Timer.Sample sample = Timer.start();
    try {
      for (Event e : events) {
        if (sends.containsKey(e.id()) || seen.getIfPresent(e.id()) != null) {
          dup++;
          continue;
        }
        ProducerRecord<String, String> record =
            new ProducerRecord<>(Topics.RAW, partitionKey(e), Json.write(e));
        record.headers().add(Topics.HEADER_INGESTED_AT, ingestedAt);
        sends.put(e.id(), kafka.send(record));
      }
      CompletableFuture.allOf(sends.values().toArray(CompletableFuture[]::new)).join();
    } catch (RuntimeException ex) {
      CompletableFuture.allOf(sends.values().toArray(CompletableFuture[]::new))
          .handle((ignored, failure) -> null)
          .join();
      int acknowledged = 0;
      for (var send : sends.entrySet()) {
        if (!send.getValue().isCompletedExceptionally()) {
          seen.put(send.getKey(), Boolean.TRUE);
          acknowledged++;
        }
      }
      failed.increment(events.size() - dup - acknowledged);
      if (isTimeout(ex)) {
        throw new ProducerBackpressureException(ex);
      }
      throw ex;
    } finally {
      sample.stop(produceTimer);
    }
    sends.keySet().forEach(id -> seen.put(id, Boolean.TRUE));
    accepted.increment(sends.size());
    duplicates.increment(dup);
    return new Result(sends.size(), dup);
  }

  /**
   * Metadata or buffer space not available within max.block.ms (thrown by send) and records expired
   * after delivery.timeout.ms (failed futures) are both Kafka TimeoutExceptions somewhere in the
   * cause chain; BufferExhaustedException is one too.
   */
  private static boolean isTimeout(Throwable ex) {
    for (Throwable t = ex; t != null; t = t.getCause()) {
      if (t instanceof TimeoutException) {
        return true;
      }
    }
    return false;
  }

  /** Raised when the producer cannot keep up (buffer full or broker slow): the API answers 503. */
  public static final class ProducerBackpressureException extends RuntimeException {
    public ProducerBackpressureException(Throwable cause) {
      super("producer backpressure: " + cause.getMessage(), cause);
    }
  }
}
