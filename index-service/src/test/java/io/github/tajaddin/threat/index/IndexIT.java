package io.github.tajaddin.threat.index;

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
import org.opensearch.client.opensearch.OpenSearchClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.kafka.KafkaContainer;

/**
 * Enriched events and alerts from Kafka end up as documents in daily indices, keyed by their ids.
 */
@SpringBootTest
@Testcontainers
class IndexIT {
  @Container @ServiceConnection
  static final KafkaContainer KAFKA = new KafkaContainer("apache/kafka:4.3.1");

  @Container
  static final GenericContainer<?> OPENSEARCH =
      new GenericContainer<>("opensearchproject/opensearch:2.19.6")
          .withEnv("discovery.type", "single-node")
          .withEnv("DISABLE_SECURITY_PLUGIN", "true")
          .withEnv("DISABLE_INSTALL_DEMO_CONFIG", "true")
          .withEnv("OPENSEARCH_JAVA_OPTS", "-Xms512m -Xmx512m")
          .withExposedPorts(9200)
          .waitingFor(
              Wait.forHttp("/_cluster/health")
                  .forPort(9200)
                  .forStatusCode(200)
                  .withStartupTimeout(Duration.ofMinutes(3)));

  @DynamicPropertySource
  static void props(DynamicPropertyRegistry r) {
    r.add(
        "index.url", () -> "http://" + OPENSEARCH.getHost() + ":" + OPENSEARCH.getMappedPort(9200));
  }

  @Autowired OpenSearchClient client;

  @BeforeAll
  static void topics() throws Exception {
    try (AdminClient admin =
        AdminClient.create(Map.of("bootstrap.servers", KAFKA.getBootstrapServers()))) {
      admin
          .createTopics(
              List.of(
                  new NewTopic(Topics.ENRICHED, 2, (short) 1),
                  new NewTopic(Topics.ALERTS, 1, (short) 1)))
          .all()
          .get();
    }
  }

  @Test
  void indexesEventsAndAlertsIdempotently() throws Exception {
    Instant now = Instant.parse("2026-10-17T12:00:00Z");
    List<Event> events = new SyntheticEvents(41, 0, "it").batch(now, 25);
    Alert alert =
        new Alert(
            "11111111-1111-1111-1111-111111111111",
            "auth-brute-force",
            "Brute force",
            Alert.Severity.HIGH,
            "k",
            List.of(events.get(0).id()),
            10,
            now,
            now,
            now,
            42,
            "summary");
    Properties pp = new Properties();
    pp.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, KAFKA.getBootstrapServers());
    try (KafkaProducer<String, String> producer =
        new KafkaProducer<>(pp, new StringSerializer(), new StringSerializer())) {
      for (int round = 0; round < 2; round++) { // the second round is a redelivery
        for (Event e : events) {
          producer
              .send(
                  new ProducerRecord<>(
                      Topics.ENRICHED,
                      e.source(),
                      Json.write(
                          new EnrichedEvent(
                              e, "US", "AS1", true, null, false, null, null, now, now))))
              .get();
        }
        producer.send(new ProducerRecord<>(Topics.ALERTS, alert.key(), Json.write(alert))).get();
      }
    }

    await()
        .ignoreExceptions() // the daily index does not exist until the first bulk lands
        .atMost(Duration.ofSeconds(90))
        .untilAsserted(
            () -> {
              client.indices().refresh(r -> r.index("events-*,alerts-*"));
              long eventDocs = client.count(c -> c.index("events-2026.10.17")).count();
              long alertDocs = client.count(c -> c.index("alerts-2026.10.17")).count();
              assertThat(eventDocs).isEqualTo(25);
              assertThat(alertDocs).isEqualTo(1);
            });
    var doc = client.get(g -> g.index("alerts-2026.10.17").id(alert.id()), Map.class);
    assertThat(doc.found()).isTrue();
    assertThat(doc.source()).containsEntry("ruleId", "auth-brute-force");
    var template = client.indices().getIndexTemplate(t -> t.name("events-template"));
    assertThat(template.indexTemplates()).isNotEmpty();
  }
}
