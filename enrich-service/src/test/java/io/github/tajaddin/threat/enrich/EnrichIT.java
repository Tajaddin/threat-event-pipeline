package io.github.tajaddin.threat.enrich;

import static org.assertj.core.api.Assertions.assertThat;

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
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.kafka.KafkaContainer;

/**
 * Transactional consume-transform-produce: one enriched record per input, malformed input to the
 * DLQ.
 */
@SpringBootTest
@Testcontainers
class EnrichIT {
  @Container @ServiceConnection
  static final KafkaContainer KAFKA = new KafkaContainer("apache/kafka:4.3.1");

  @Container @ServiceConnection
  static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

  @BeforeAll
  static void topics() throws Exception {
    try (AdminClient admin =
        AdminClient.create(Map.of("bootstrap.servers", KAFKA.getBootstrapServers()))) {
      admin
          .createTopics(
              List.of(
                  new NewTopic(Topics.RAW, 3, (short) 1),
                  new NewTopic(Topics.ENRICHED, 3, (short) 1),
                  new NewTopic(Topics.DLQ, 1, (short) 1)))
          .all()
          .get();
    }
  }

  @Test
  void enrichesGoodEventsExactlyOnceAndDeadLettersBadOnes() throws Exception {
    List<Event> events = new SyntheticEvents(21, 0, "it").batch(Instant.now(), 30);
    Event hostile =
        new Event(
            "hostile-1",
            Instant.now(),
            Event.EventType.AUTH,
            "it",
            "srv-dc-01",
            "a.khan",
            "185.220.101.7",
            null,
            null,
            "success",
            "4624",
            3,
            null,
            null);
    Properties pp = new Properties();
    pp.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, KAFKA.getBootstrapServers());
    try (KafkaProducer<String, String> producer =
        new KafkaProducer<>(pp, new StringSerializer(), new StringSerializer())) {
      for (Event e : events) {
        ProducerRecord<String, String> r =
            new ProducerRecord<>(Topics.RAW, e.source(), Json.write(e));
        r.headers()
            .add(
                Topics.HEADER_INGESTED_AT,
                Instant.now().toString().getBytes(StandardCharsets.UTF_8));
        producer.send(r).get();
      }
      producer.send(new ProducerRecord<>(Topics.RAW, "it", Json.write(hostile))).get();
      producer.send(new ProducerRecord<>(Topics.RAW, "it", "{\"this\":\"is not an event\"}")).get();
      producer.send(new ProducerRecord<>(Topics.RAW, "it", "not even json")).get();
    }

    List<ConsumerRecord<String, String>> enriched =
        consume(Topics.ENRICHED, 31, Duration.ofSeconds(60));
    List<ConsumerRecord<String, String>> dlq = consume(Topics.DLQ, 2, Duration.ofSeconds(30));

    assertThat(enriched).hasSize(31);
    assertThat(
            enriched.stream()
                .map(r -> Json.read(r.value(), EnrichedEvent.class).event().id())
                .distinct())
        .hasSize(31);
    EnrichedEvent h =
        enriched.stream()
            .map(r -> Json.read(r.value(), EnrichedEvent.class))
            .filter(e -> e.event().id().equals("hostile-1"))
            .findFirst()
            .orElseThrow();
    assertThat(h.srcCountry()).isEqualTo("NL");
    assertThat(h.srcAsn()).contains("exitnode");
    assertThat(h.srcInternal()).isFalse();
    assertThat(h.assetCriticality()).isEqualTo("critical");
    assertThat(h.assetOwner()).isEqualTo("infrastructure");
    assertThat(h.ingestedAt()).isNotNull();
    EnrichedEvent internal =
        enriched.stream()
            .map(r -> Json.read(r.value(), EnrichedEvent.class))
            .filter(e -> e.event().srcIp() != null && e.event().srcIp().startsWith("10."))
            .findFirst()
            .orElseThrow();
    assertThat(internal.srcInternal()).isTrue();

    assertThat(dlq).hasSize(2);
    assertThat(dlq).allMatch(r -> r.headers().lastHeader(Topics.HEADER_ERROR) != null);
    assertThat(dlq)
        .allMatch(
            r ->
                new String(
                        r.headers().lastHeader(Topics.HEADER_ERROR_STAGE).value(),
                        StandardCharsets.UTF_8)
                    .equals("enrich"));
  }

  private static List<ConsumerRecord<String, String>> consume(
      String topic, int expected, Duration timeout) {
    Properties p = new Properties();
    p.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, KAFKA.getBootstrapServers());
    p.put(ConsumerConfig.GROUP_ID_CONFIG, "it-" + topic + "-" + System.nanoTime());
    p.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
    p.put(ConsumerConfig.ISOLATION_LEVEL_CONFIG, "read_committed");
    List<ConsumerRecord<String, String>> out = new ArrayList<>();
    try (KafkaConsumer<String, String> consumer =
        new KafkaConsumer<>(p, new StringDeserializer(), new StringDeserializer())) {
      consumer.subscribe(List.of(topic));
      long deadline = System.currentTimeMillis() + timeout.toMillis();
      while (System.currentTimeMillis() < deadline) {
        consumer.poll(Duration.ofMillis(500)).forEach(out::add);
        if (out.size() >= expected) {
          // drain a little longer to catch duplicates
          consumer.poll(Duration.ofSeconds(2)).forEach(out::add);
          break;
        }
      }
    }
    return out;
  }
}
