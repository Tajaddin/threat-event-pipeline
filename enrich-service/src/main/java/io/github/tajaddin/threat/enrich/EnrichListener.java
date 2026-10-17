package io.github.tajaddin.threat.enrich;

import io.github.tajaddin.threat.common.EnrichedEvent;
import io.github.tajaddin.threat.common.Event;
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
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.listener.BatchListenerFailedException;
import org.springframework.stereotype.Component;

/**
 * Consume-transform-produce inside one Kafka transaction per poll (up to {@code max.poll.records}
 * records): the output records and the consumed offsets commit together, so a crash mid-way replays
 * the input and never leaves a duplicate output visible to read_committed consumers. Malformed
 * input is routed to the dead-letter topic inside the same transaction, with the error in headers,
 * so it is handled exactly once as well.
 *
 * <p>The transaction spans the poll rather than one record because the commit, not the enrichment,
 * is the expensive part: measured on one machine, a transaction per record topped out at about 65
 * events per second per partition; per poll it is the broker's write throughput that limits.
 *
 * <p>An unexpected failure (database down, bug) is reported with the index of the failing record,
 * so the after-rollback processor commits the records before it, retries it and, after the retries,
 * dead-letters only that record while the rest of the batch is redelivered.
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
    for (int i = 0; i < records.size(); i++) {
      ConsumerRecord<String, String> record = records.get(i);
      try {
        handle(record);
      } catch (RuntimeException ex) {
        throw new BatchListenerFailedException(
            "enrich failed at " + record.partition() + "-" + record.offset(), ex, i);
      }
    }
  }

  private void handle(ConsumerRecord<String, String> record) {
    Instant ingestedAt =
        header(record, Topics.HEADER_INGESTED_AT)
            .map(Instant::parse)
            .orElse(Instant.ofEpochMilli(record.timestamp()));
    Event event;
    try {
      event = Json.read(record.value(), Event.class);
      if (event.id() == null || event.timestamp() == null || event.type() == null) {
        throw new IllegalArgumentException("missing id, timestamp or type");
      }
    } catch (IllegalArgumentException ex) {
      ProducerRecord<String, String> dlq =
          new ProducerRecord<>(Topics.DLQ, record.key(), record.value());
      dlq.headers().add(Topics.HEADER_ERROR, ex.getMessage().getBytes(StandardCharsets.UTF_8));
      dlq.headers().add(Topics.HEADER_ERROR_STAGE, "enrich".getBytes(StandardCharsets.UTF_8));
      kafka.send(dlq);
      deadLettered.increment();
      log.warn(
          "dead-lettered record from partition {} offset {}: {}",
          record.partition(),
          record.offset(),
          ex.getMessage());
      return;
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

  private static java.util.Optional<String> header(ConsumerRecord<?, ?> record, String name) {
    Header h = record.headers().lastHeader(name);
    return h == null
        ? java.util.Optional.empty()
        : java.util.Optional.of(new String(h.value(), StandardCharsets.UTF_8));
  }
}
