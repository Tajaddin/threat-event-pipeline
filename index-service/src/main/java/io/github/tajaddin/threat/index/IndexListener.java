package io.github.tajaddin.threat.index;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.tajaddin.threat.common.Json;
import io.github.tajaddin.threat.common.Topics;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.io.IOException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.core.BulkRequest;
import org.opensearch.client.opensearch.core.BulkResponse;
import org.opensearch.client.opensearch.core.bulk.BulkOperation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.stereotype.Component;

/**
 * Batch consumer: one bulk request per poll, documents keyed by their own ids so a redelivered
 * batch overwrites rather than duplicates. The offset is acknowledged only after OpenSearch
 * accepted every document; a failed bulk throws, the batch is redelivered, and the container's
 * back-off applies.
 */
@Component
public class IndexListener {
  private static final Logger log = LoggerFactory.getLogger(IndexListener.class);
  private static final DateTimeFormatter DAY =
      DateTimeFormatter.ofPattern("yyyy.MM.dd").withZone(ZoneOffset.UTC);

  private final OpenSearchClient client;
  private final OpenSearchConfig.IndexProperties props;
  private final Counter indexedEvents;
  private final Counter indexedAlerts;
  private final Counter failed;
  private final Timer bulkTimer;

  public IndexListener(
      OpenSearchClient client, OpenSearchConfig.IndexProperties props, MeterRegistry registry) {
    this.client = client;
    this.props = props;
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
    bulk(records, props.eventsIndexPrefix(), "timestamp", true);
    indexedEvents.increment(records.size());
    ack.acknowledge();
  }

  @KafkaListener(
      topics = Topics.ALERTS,
      groupId = "index-alerts",
      batch = "true",
      concurrency = "1")
  public void onAlerts(List<ConsumerRecord<String, String>> records, Acknowledgment ack)
      throws IOException {
    bulk(records, props.alertsIndexPrefix(), "detectedAt", false);
    indexedAlerts.increment(records.size());
    ack.acknowledge();
  }

  private void bulk(
      List<ConsumerRecord<String, String>> records,
      String prefix,
      String dateField,
      boolean nestedEvent)
      throws IOException {
    if (records.isEmpty()) {
      return;
    }
    List<BulkOperation> ops = new ArrayList<>(records.size());
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
    }
    if (ops.isEmpty()) {
      return;
    }
    Timer.Sample sample = Timer.start();
    BulkResponse response = client.bulk(new BulkRequest.Builder().operations(ops).build());
    sample.stop(bulkTimer);
    if (response.errors()) {
      long bad = response.items().stream().filter(i -> i.error() != null).count();
      failed.increment(bad);
      String first =
          response.items().stream()
              .filter(i -> i.error() != null)
              .findFirst()
              .map(i -> i.error().reason())
              .orElse("?");
      throw new IOException("bulk had " + bad + " failed documents, first: " + first);
    }
  }

  private static Instant safeInstant(String text) {
    try {
      return Instant.parse(text);
    } catch (RuntimeException e) {
      return Instant.now();
    }
  }
}
