package io.github.tajaddin.threat.index;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import io.github.tajaddin.threat.common.Alert;
import io.github.tajaddin.threat.common.EnrichedEvent;
import io.github.tajaddin.threat.common.Event;
import io.github.tajaddin.threat.common.Json;
import io.github.tajaddin.threat.common.SyntheticEvents;
import io.github.tajaddin.threat.common.Topics;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.StringDeserializer;
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
                  new NewTopic(Topics.ALERTS, 1, (short) 1),
                  new NewTopic(Topics.DLQ, 1, (short) 1)))
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

  @Test
  void documentOpenSearchRefusesIsDeadLetteredAndTheNextOneIsIndexed() throws Exception {
    Instant day = Instant.parse("2026-10-18T12:00:00Z");
    List<Event> events = new SyntheticEvents(43, 0, "it").batch(day, 3);
    // dynamic mapping turns attributes.note into a date field; "abc" then fails to parse (400)
    Event dated = withNote(events.get(0), "2026-01-01");
    Event notADate = withNote(events.get(1), "abc");
    Event plain = events.get(2);
    Properties pp = new Properties();
    pp.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, KAFKA.getBootstrapServers());
    try (KafkaProducer<String, String> producer =
        new KafkaProducer<>(pp, new StringSerializer(), new StringSerializer())) {
      produce(producer, dated, day);
      await()
          .ignoreExceptions()
          .atMost(Duration.ofSeconds(90))
          .untilAsserted(
              () -> {
                client.indices().refresh(r -> r.index("events-2026.10.18"));
                assertThat(client.count(c -> c.index("events-2026.10.18")).count()).isEqualTo(1);
              });
      produce(producer, notADate, day);
      produce(producer, plain, day);
    }

    await()
        .atMost(Duration.ofSeconds(90))
        .untilAsserted(
            () -> {
              client.indices().refresh(r -> r.index("events-2026.10.18"));
              assertThat(client.count(c -> c.index("events-2026.10.18")).count()).isEqualTo(2);
            });
    List<ConsumerRecord<String, String>> dlq = consumeDeadLetters(1);
    assertThat(dlq).hasSize(1);
    ConsumerRecord<String, String> dead = dlq.get(0);
    assertThat(Json.read(dead.value(), EnrichedEvent.class).event().id()).isEqualTo(notADate.id());
    assertThat(
            new String(
                dead.headers().lastHeader(Topics.HEADER_ERROR_STAGE).value(),
                StandardCharsets.UTF_8))
        .isEqualTo("index");
    assertThat(
            new String(
                dead.headers().lastHeader(Topics.HEADER_ERROR).value(), StandardCharsets.UTF_8))
        .startsWith("400");
  }

  private static Event withNote(Event e, String note) {
    return new Event(
        e.id(),
        e.timestamp(),
        e.type(),
        e.source(),
        e.host(),
        e.user(),
        e.srcIp(),
        e.dstIp(),
        e.dstPort(),
        e.action(),
        e.eventCode(),
        e.logonType(),
        e.bytesOut(),
        Map.of("note", note));
  }

  private static void produce(KafkaProducer<String, String> producer, Event e, Instant at)
      throws Exception {
    EnrichedEvent enriched =
        new EnrichedEvent(e, "US", "AS1", true, null, false, null, null, at, at);
    producer.send(new ProducerRecord<>(Topics.ENRICHED, e.source(), Json.write(enriched))).get();
  }

  private static List<ConsumerRecord<String, String>> consumeDeadLetters(int expected) {
    Properties p = new Properties();
    p.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, KAFKA.getBootstrapServers());
    p.put(ConsumerConfig.GROUP_ID_CONFIG, "it-dlq-" + System.nanoTime());
    p.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
    List<ConsumerRecord<String, String>> out = new ArrayList<>();
    try (KafkaConsumer<String, String> consumer =
        new KafkaConsumer<>(p, new StringDeserializer(), new StringDeserializer())) {
      consumer.subscribe(List.of(Topics.DLQ));
      long deadline = System.currentTimeMillis() + 30_000;
      while (out.size() < expected && System.currentTimeMillis() < deadline) {
        consumer.poll(Duration.ofMillis(500)).forEach(out::add);
      }
    }
    return out;
  }
}
