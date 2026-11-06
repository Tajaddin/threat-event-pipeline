package io.github.tajaddin.threat.index;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.tajaddin.threat.common.Json;
import io.github.tajaddin.threat.common.Topics;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.core.BulkRequest;
import org.opensearch.client.opensearch.core.BulkResponse;
import org.opensearch.client.opensearch.core.bulk.BulkOperation;
import org.opensearch.client.opensearch.core.bulk.BulkResponseItem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.stereotype.Component;

/**
 * Batch consumer: one bulk request per poll, documents keyed by their own ids so a redelivered
 * batch overwrites rather than duplicates. The offset is acknowledged only after every document is
 * either indexed or dead-lettered. A document refused with 429 or a 5xx may go in later, so the
 * batch throws and the container redelivers it with back-off; once only other refusals remain (a
 * 400 mapping conflict, say, which no retry fixes), those documents go to events.dlq with the
 * reason in headers and the batch is acknowledged.
 */
@Component
public class IndexListener {
  private static final Logger log = LoggerFactory.getLogger(IndexListener.class);
  private static final DateTimeFormatter DAY =
      DateTimeFormatter.ofPattern("yyyy.MM.dd").withZone(ZoneOffset.UTC);

  private final OpenSearchClient client;
  private final OpenSearchConfig.IndexProperties props;
  private final KafkaTemplate<String, String> kafka;
  private final Counter indexedEvents;
  private final Counter indexedAlerts;
  private final Counter failed;
  private final Timer bulkTimer;

  public IndexListener(
      OpenSearchClient client,
      OpenSearchConfig.IndexProperties props,
      KafkaTemplate<String, String> kafka,
      MeterRegistry registry) {
    this.client = client;
    this.props = props;
    this.kafka = kafka;
    this.indexedEvents = Counter.builder("index.documents").tag("kind", "event").register(registry);
    this.indexedAlerts = Counter.builder("index.documents").tag("kind", "alert").register(registry);
    this.failed = Counter.builder("index.failures").register(registry);
    this.bulkTimer = Timer.builder("index.bulk").publishPercentileHistogram().register(registry);
  }

  @KafkaListener(
      topics = Topics.ENRICHED,
      groupId = "index-events",
      batch = "true",
      concurrency = "${index.concurrency:2}")
  public void onEvents(List<ConsumerRecord<String, String>> records, Acknowledgment ack)
      throws IOException {
    indexedEvents.increment(bulk(records, props.eventsIndexPrefix(), "timestamp", true));
    ack.acknowledge();
  }

  @KafkaListener(
      topics = Topics.ALERTS,
      groupId = "index-alerts",
      batch = "true",
      concurrency = "1")
  public void onAlerts(List<ConsumerRecord<String, String>> records, Acknowledgment ack)
      throws IOException {
    indexedAlerts.increment(bulk(records, props.alertsIndexPrefix(), "detectedAt", false));
    ack.acknowledge();
  }

  /** Returns how many documents were indexed. */
  private int bulk(
      List<ConsumerRecord<String, String>> records,
      String prefix,
      String dateField,
      boolean nestedEvent)
      throws IOException {
    List<BulkOperation> ops = new ArrayList<>(records.size());
    List<ConsumerRecord<String, String>> sources = new ArrayList<>(records.size());
    for (ConsumerRecord<String, String> r : records) {
      JsonNode doc;
      try {
        doc = Json.MAPPER.readTree(r.value());
      } catch (IOException e) {
        log.warn("skipping unparsable record at {}-{}", r.partition(), r.offset());
        continue;
      }
      JsonNode idNode = nestedEvent ? doc.path("event").path("id") : doc.path("id");
      String id =
          idNode.isMissingNode() || idNode.isNull()
              ? r.topic() + "-" + r.partition() + "-" + r.offset()
              : idNode.asText();
      JsonNode dateNode = nestedEvent ? doc.path("event").path(dateField) : doc.path(dateField);
      Instant day = dateNode.isTextual() ? safeInstant(dateNode.asText()) : Instant.now();
      String index = prefix + "-" + DAY.format(day);
      ops.add(BulkOperation.of(b -> b.index(i -> i.index(index).id(id).document(doc))));
      sources.add(r);
    }
    if (ops.isEmpty()) {
      return 0;
    }
    Timer.Sample sample = Timer.start();
    BulkResponse response = client.bulk(new BulkRequest.Builder().operations(ops).build());
    sample.stop(bulkTimer);
    if (!response.errors()) {
      return ops.size();
    }
    List<BulkResponseItem> items = response.items();
    List<BulkResponseItem> refused = items.stream().filter(i -> i.error() != null).toList();
    failed.increment(refused.size());
    List<BulkResponseItem> retryable = refused.stream().filter(i -> retryable(i.status())).toList();
    if (!retryable.isEmpty()) {
      throw new IOException(
          retryable.size()
              + " documents refused for now, first: "
              + retryable.get(0).status()
              + " "
              + retryable.get(0).error().reason());
    }
    List<CompletableFuture<?>> sends = new ArrayList<>(refused.size());
    for (int k = 0; k < items.size(); k++) {
      if (items.get(k).error() != null) {
        sends.add(deadLetter(sources.get(k), items.get(k)));
      }
    }
    CompletableFuture.allOf(sends.toArray(CompletableFuture[]::new)).join();
    return ops.size() - refused.size();
  }

  private static boolean retryable(int status) {
    return status == 429 || status >= 500;
  }

  private CompletableFuture<?> deadLetter(
      ConsumerRecord<String, String> record, BulkResponseItem item) {
    String error = item.status() + " " + item.error().type() + ": " + item.error().reason();
    ProducerRecord<String, String> dlq =
        new ProducerRecord<>(Topics.DLQ, record.key(), record.value());
    dlq.headers().add(Topics.HEADER_ERROR, error.getBytes(StandardCharsets.UTF_8));
    dlq.headers().add(Topics.HEADER_ERROR_STAGE, "index".getBytes(StandardCharsets.UTF_8));
    log.warn(
        "dead-lettered document from {} partition {} offset {}: {}",
        record.topic(),
        record.partition(),
        record.offset(),
        error);
    return kafka.send(dlq);
  }

  private static Instant safeInstant(String text) {
    try {
      return Instant.parse(text);
    } catch (RuntimeException e) {
      return Instant.now();
    }
  }
}
