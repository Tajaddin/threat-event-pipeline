package io.github.tajaddin.threat.ingest;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.tajaddin.threat.common.Event;
import io.github.tajaddin.threat.common.Json;
import io.github.tajaddin.threat.common.SyntheticEvents;
import io.github.tajaddin.threat.common.Topics;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.kafka.KafkaContainer;

/**
 * The HTTP path end to end: validation, auth, rate limit, and the records that land on events.raw.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureObservability
@Testcontainers
@TestPropertySource(
    properties = {
      "ingest.api-keys=test-key,limit-key",
      "ingest.rate-limit-per-minute=1000",
      "ingest.max-batch=50"
    })
class IngestIT {
  @Container @ServiceConnection
  static final KafkaContainer KAFKA = new KafkaContainer("apache/kafka:4.3.1");

  @Autowired TestRestTemplate rest;

  private HttpHeaders headers(String key) {
    HttpHeaders h = new HttpHeaders();
    h.setContentType(MediaType.APPLICATION_JSON);
    if (key != null) h.set("X-API-Key", key);
    return h;
  }

  @Test
  void acceptsValidBatchAndProducesWithIngestHeader() {
    List<Event> events = new SyntheticEvents(11, 0, "it").batch(Instant.now(), 20);
    ResponseEntity<Map> resp =
        rest.postForEntity(
            "/api/events", new HttpEntity<>(Json.write(events), headers("test-key")), Map.class);
    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
    assertThat(resp.getBody()).containsEntry("accepted", 20).containsEntry("duplicates", 0);

    ResponseEntity<Map> again =
        rest.postForEntity(
            "/api/events", new HttpEntity<>(Json.write(events), headers("test-key")), Map.class);
    assertThat(again.getBody()).containsEntry("accepted", 0).containsEntry("duplicates", 20);

    Properties p = new Properties();
    p.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, KAFKA.getBootstrapServers());
    p.put(ConsumerConfig.GROUP_ID_CONFIG, "it-" + System.nanoTime());
    p.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
    try (KafkaConsumer<String, String> consumer =
        new KafkaConsumer<>(p, new StringDeserializer(), new StringDeserializer())) {
      consumer.subscribe(List.of(Topics.RAW));
      int seen = 0;
      long deadline = System.currentTimeMillis() + 20_000;
      boolean headerSeen = false;
      while (seen < 20 && System.currentTimeMillis() < deadline) {
        ConsumerRecords<String, String> records = consumer.poll(Duration.ofMillis(500));
        for (var r : records) {
          Event e = Json.read(r.value(), Event.class);
          if (!"it".equals(e.source())) {
            continue; // records from the other tests share the topic
          }
          seen++;
          headerSeen |= r.headers().lastHeader(Topics.HEADER_INGESTED_AT) != null;
          assertThat(r.key()).isEqualTo(IngestService.partitionKey(e));
        }
      }
      assertThat(seen).isEqualTo(20);
      assertThat(headerSeen).isTrue();
    }
  }

  @Test
  void rejectsMissingKeyBadJsonOversizedBatchAndValidationFailures() {
    List<Event> one = new SyntheticEvents(2, 0, "it").batch(Instant.now(), 1);
    assertThat(
            rest.postForEntity(
                    "/api/events", new HttpEntity<>(Json.write(one), headers(null)), String.class)
                .getStatusCode())
        .isEqualTo(HttpStatus.UNAUTHORIZED);
    assertThat(
            rest.postForEntity(
                    "/api/events",
                    new HttpEntity<>(Json.write(one), headers("wrong")),
                    String.class)
                .getStatusCode())
        .isEqualTo(HttpStatus.UNAUTHORIZED);
    assertThat(
            rest.postForEntity(
                    "/api/events", new HttpEntity<>("{not json", headers("test-key")), String.class)
                .getStatusCode())
        .isEqualTo(HttpStatus.BAD_REQUEST);
    assertThat(
            rest.postForEntity(
                    "/api/events", new HttpEntity<>("[]", headers("test-key")), String.class)
                .getStatusCode())
        .isEqualTo(HttpStatus.BAD_REQUEST);
    String invalid =
        "[{\"id\":\"has space\",\"timestamp\":\"2026-01-01T00:00:00Z\",\"type\":\"AUTH\",\"source\":\"s\"}]";
    assertThat(
            rest.postForEntity(
                    "/api/events", new HttpEntity<>(invalid, headers("test-key")), String.class)
                .getStatusCode())
        .isEqualTo(HttpStatus.BAD_REQUEST);
    List<Event> big = new SyntheticEvents(3, 0, "it").batch(Instant.now(), 51);
    assertThat(
            rest.postForEntity(
                    "/api/events",
                    new HttpEntity<>(Json.write(big), headers("test-key")),
                    String.class)
                .getStatusCode())
        .isEqualTo(HttpStatus.BAD_REQUEST);
  }

  @Test
  void rateLimitAnswers429() {
    List<Event> batch = new SyntheticEvents(4, 0, "limited").batch(Instant.now(), 50);
    HttpStatus last = null;
    for (int i = 0; i < 25; i++) {
      List<Event> fresh = new SyntheticEvents(100 + i, 0, "limited").batch(Instant.now(), 50);
      last =
          (HttpStatus)
              rest.postForEntity(
                      "/api/events",
                      new HttpEntity<>(Json.write(fresh), headers("limit-key")),
                      String.class)
                  .getStatusCode();
      if (last == HttpStatus.TOO_MANY_REQUESTS) break;
    }
    assertThat(last).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    assertThat(batch).isNotEmpty();
  }

  @Test
  void healthAndMetricsAreOpen() {
    assertThat(rest.getForEntity("/actuator/health/liveness", String.class).getStatusCode())
        .isEqualTo(HttpStatus.OK);
    assertThat(rest.getForEntity("/actuator/prometheus", String.class).getBody())
        .contains("ingest_events_total");
  }
}
