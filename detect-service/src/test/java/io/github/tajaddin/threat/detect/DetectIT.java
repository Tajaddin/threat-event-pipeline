package io.github.tajaddin.threat.detect;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import io.github.tajaddin.threat.common.Alert;
import io.github.tajaddin.threat.common.EnrichedEvent;
import io.github.tajaddin.threat.common.Event;
import io.github.tajaddin.threat.common.Json;
import io.github.tajaddin.threat.common.SyntheticEvents;
import io.github.tajaddin.threat.common.Topics;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.StringSerializer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.HttpStatus;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.kafka.KafkaContainer;

/**
 * A brute-force burst on events.enriched becomes exactly one stored alert, visible through the API.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureObservability
@Testcontainers
class DetectIT {
  @Container @ServiceConnection
  static final KafkaContainer KAFKA = new KafkaContainer("apache/kafka:4.3.1");

  @Container @ServiceConnection
  static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

  @Autowired TestRestTemplate rest;
  @Autowired AlertRepository alerts;

  @BeforeAll
  static void topics() throws Exception {
    try (AdminClient admin =
        AdminClient.create(Map.of("bootstrap.servers", KAFKA.getBootstrapServers()))) {
      admin
          .createTopics(
              List.of(
                  new NewTopic(Topics.ENRICHED, 3, (short) 1),
                  new NewTopic(Topics.ALERTS, 1, (short) 1)))
          .all()
          .get();
    }
  }

  @Test
  void bruteForceBurstRaisesOneAlert() throws Exception {
    SyntheticEvents s = new SyntheticEvents(31, 0, "it");
    Instant now = Instant.now();
    List<Event> burst = s.scenario(SyntheticEvents.Scenario.BRUTE_FORCE, now);
    Properties pp = new Properties();
    pp.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, KAFKA.getBootstrapServers());
    try (KafkaProducer<String, String> producer =
        new KafkaProducer<>(pp, new StringSerializer(), new StringSerializer())) {
      for (Event e : burst) {
        EnrichedEvent enriched =
            new EnrichedEvent(
                e, "US", "AS64500-docnet", false, null, false, "finance", "medium", now, now);
        producer
            .send(new ProducerRecord<>(Topics.ENRICHED, e.source(), Json.write(enriched)))
            .get();
      }
      // a redelivery of the same burst must not create a second alert
      for (Event e : burst) {
        EnrichedEvent enriched =
            new EnrichedEvent(
                e, "US", "AS64500-docnet", false, null, false, "finance", "medium", now, now);
        producer
            .send(new ProducerRecord<>(Topics.ENRICHED, e.source(), Json.write(enriched)))
            .get();
      }
    }

    await()
        .atMost(Duration.ofSeconds(60))
        .untilAsserted(
            () -> assertThat(alerts.count(now.minusSeconds(60))).isGreaterThanOrEqualTo(1));
    Thread.sleep(2000);
    List<Alert> found = alerts.list(null, "auth-brute-force", null, 100, 0);
    assertThat(found).hasSize(1);
    Alert a = found.get(0);
    assertThat(a.eventCount()).isGreaterThanOrEqualTo(10);
    assertThat(a.severity()).isEqualTo(Alert.Severity.HIGH);
    assertThat(a.detectionLatencyMs()).isGreaterThanOrEqualTo(0);

    var resp = rest.getForEntity("/api/alerts?ruleId=auth-brute-force", Alert[].class);
    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(resp.getBody()).hasSize(1);
    assertThat(rest.getForEntity("/api/alerts/" + a.id(), Alert.class).getBody().ruleId())
        .isEqualTo("auth-brute-force");
    assertThat(
            rest.getForEntity("/api/alerts/00000000-0000-0000-0000-000000000000", String.class)
                .getStatusCode())
        .isEqualTo(HttpStatus.NOT_FOUND);

    Map stats = rest.getForEntity("/api/stats?minutes=10", Map.class).getBody();
    assertThat(((Number) stats.get("alerts")).longValue()).isGreaterThanOrEqualTo(1);
    assertThat(((Number) stats.get("rulesLoaded")).intValue()).isGreaterThanOrEqualTo(7);

    Map rules = rest.getForEntity("/api/rules", Map.class).getBody();
    assertThat((List<?>) rules.get("rules")).hasSizeGreaterThanOrEqualTo(7);
    Map reload = rest.postForEntity("/api/rules/reload", null, Map.class).getBody();
    assertThat(((Number) reload.get("loaded")).intValue()).isGreaterThanOrEqualTo(7);
    assertThat(rest.getForEntity("/api/rules/auth-brute-force/yaml", String.class).getBody())
        .contains("threshold");
    assertThat(rest.getForEntity("/actuator/prometheus", String.class).getBody())
        .contains("detect_alerts_total");
  }
}
