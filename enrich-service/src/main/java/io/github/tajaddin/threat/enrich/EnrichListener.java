package io.github.tajaddin.threat.enrich;

import io.github.tajaddin.threat.common.EnrichedEvent;
import io.github.tajaddin.threat.common.Event;
import io.github.tajaddin.threat.common.IpAddress;
import io.github.tajaddin.threat.common.Json;
import io.github.tajaddin.threat.common.Topics;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.header.Header;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.InvalidDataAccessResourceUsageException;
import org.springframework.dao.RecoverableDataAccessException;
import org.springframework.dao.TransientDataAccessException;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

/**
 * Consume-transform-produce inside one Kafka transaction per poll (up to {@code max.poll.records}
 * records): the output records and the consumed offsets commit together, so a crash mid-way replays
 * the input and never leaves a duplicate output visible to read_committed consumers.
 *
 * <p>The transaction spans the poll rather than one record because the commit, not the enrichment,
 * is the expensive part: measured on one machine, a transaction per record topped out at about 65
 * events per second per partition; per poll it is the broker's write throughput that limits.
 *
 * <p>A record that fails on its own (malformed JSON, missing fields, an address that is not an IP,
 * a value the database rejects, a bug) goes to the dead-letter topic inside the same transaction,
 * with the error in headers, and the records around it carry on. A failure of the database or the
 * broker rolls the whole poll back instead; {@link KafkaConfig} re-reads it with back-off until it
 * goes through, so an outage dead-letters nothing.
 */
@Component
public class EnrichListener {
  private static final Logger log = LoggerFactory.getLogger(EnrichListener.class);

  private final Enricher enricher;
  private final KafkaTemplate<String, String> kafka;
  private final Counter processed;
  private final Counter deadLettered;
  private final Timer latency;
  private final DistributionSummary batchSize;

  public EnrichListener(
      Enricher enricher, KafkaTemplate<String, String> kafka, MeterRegistry registry) {
    this.enricher = enricher;
    this.kafka = kafka;
    this.processed =
        Counter.builder("enrich.events").tag("outcome", "processed").register(registry);
    this.deadLettered = Counter.builder("enrich.events").tag("outcome", "dlq").register(registry);
    this.latency =
        Timer.builder("enrich.latency")
            .description("ingest to enriched")
            .publishPercentileHistogram()
            .register(registry);
    this.batchSize =
        DistributionSummary.builder("enrich.batch.size")
            .description("records per transaction")
            .register(registry);
  }

  @KafkaListener(
      topics = Topics.RAW,
      groupId = "${spring.kafka.consumer.group-id}",
      concurrency = "${enrich.concurrency:3}")
  public void onBatch(List<ConsumerRecord<String, String>> records) {
    batchSize.record(records.size());
    for (ConsumerRecord<String, String> record : records) {
      try {
        handle(record);
      } catch (RuntimeException ex) {
        if (environmental(ex)) {
          throw ex;
        }
        deadLetter(record, ex);
      }
    }
  }

  private void handle(ConsumerRecord<String, String> record) {
    Instant ingestedAt =
        header(record, Topics.HEADER_INGESTED_AT)
            .map(Instant::parse)
            .orElse(Instant.ofEpochMilli(record.timestamp()));
    Event event = Json.read(record.value(), Event.class);
    if (event.id() == null || event.timestamp() == null || event.type() == null) {
      throw new IllegalArgumentException("missing id, timestamp or type");
    }
    if (!isAddressOrAbsent(event.srcIp()) || !isAddressOrAbsent(event.dstIp())) {
      throw new IllegalArgumentException("srcIp or dstIp is not an IP address");
    }
    EnrichedEvent enriched = enricher.enrich(event, ingestedAt);
    ProducerRecord<String, String> out =
        new ProducerRecord<>(Topics.ENRICHED, record.key(), Json.write(enriched));
    out.headers()
        .add(Topics.HEADER_INGESTED_AT, ingestedAt.toString().getBytes(StandardCharsets.UTF_8));
    kafka.send(out);
    processed.increment();
    latency.record(java.time.Duration.between(ingestedAt, enriched.enrichedAt()).abs());
  }

  private void deadLetter(ConsumerRecord<String, String> record, RuntimeException ex) {
    String error = ex.getClass().getSimpleName() + ": " + ex.getMessage();
    ProducerRecord<String, String> dlq =
        new ProducerRecord<>(Topics.DLQ, record.key(), record.value());
    dlq.headers().add(Topics.HEADER_ERROR, error.getBytes(StandardCharsets.UTF_8));
    dlq.headers().add(Topics.HEADER_ERROR_STAGE, "enrich".getBytes(StandardCharsets.UTF_8));
    kafka.send(dlq);
    deadLettered.increment();
    log.warn(
        "dead-lettered record from partition {} offset {}: {}",
        record.partition(),
        record.offset(),
        error);
  }

  /** Blank counts as absent, as in {@link Lookups#ip}; anything else must parse as an address. */
  private static boolean isAddressOrAbsent(String ip) {
    return ip == null || ip.isBlank() || IpAddress.Validator.isLiteral(ip);
  }

  /**
   * Failures of the database or the broker rather than of the record: the poll is rolled back and
   * retried, never dead-lettered. A value the database rejects surfaces as a
   * DataIntegrityViolationException, which is not in this list.
   */
  private static boolean environmental(Throwable ex) {
    for (Throwable t = ex; t != null; t = t.getCause()) {
      if (t instanceof TransientDataAccessException
          || t instanceof RecoverableDataAccessException
          || t instanceof DataAccessResourceFailureException
          || t instanceof InvalidDataAccessResourceUsageException
          || t instanceof org.apache.kafka.common.KafkaException
          || t instanceof org.springframework.kafka.KafkaException) {
        return true;
      }
    }
    return false;
  }

  private static java.util.Optional<String> header(ConsumerRecord<?, ?> record, String name) {
    Header h = record.headers().lastHeader(name);
    return h == null
        ? java.util.Optional.empty()
        : java.util.Optional.of(new String(h.value(), StandardCharsets.UTF_8));
  }
}
