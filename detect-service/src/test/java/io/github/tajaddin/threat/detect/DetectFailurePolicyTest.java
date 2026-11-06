package io.github.tajaddin.threat.detect;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

import io.github.tajaddin.threat.common.Alert;
import io.github.tajaddin.threat.common.EnrichedEvent;
import io.github.tajaddin.threat.common.Event;
import io.github.tajaddin.threat.common.Json;
import io.github.tajaddin.threat.common.Topics;
import io.github.tajaddin.threat.detect.engine.DetectionEngine;
import io.github.tajaddin.threat.detect.rules.CompiledRule;
import io.github.tajaddin.threat.detect.rules.RuleLoader;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.CannotGetJdbcConnectionException;
import org.springframework.kafka.test.EmbeddedKafkaBroker;
import org.springframework.kafka.test.context.EmbeddedKafka;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/**
 * The detect failure policy against a real (in-process) broker, with storage mocked: an event that
 * makes a rule throw is retried a few times and then dead-lettered while the next event's alert
 * still goes out; a database outage longer than those retries is waited out and the alert it held
 * up is stored and produced, not lost.
 */
@SpringBootTest(
    properties = {
      "spring.kafka.bootstrap-servers=${spring.embedded.kafka.brokers}",
      "spring.flyway.enabled=false"
    })
@EmbeddedKafka(
    kraft = true,
    partitions = 1,
    topics = {Topics.ENRICHED, Topics.ALERTS, Topics.DLQ})
class DetectFailurePolicyTest {
  private static final String BROKEN_RULE =
      """
      id: fw-broken
      title: A rule whose threshold is not a number
      logsource: { category: FIREWALL }
      detection:
        selection:
          bytes_out|gt: lots
        condition: selection
      """;

  @Autowired EmbeddedKafkaBroker broker;
  @MockitoBean RuleService rules;
  @MockitoBean AlertRepository alerts;

  @Test
  void poisonEventIsDeadLetteredAndADatabaseOutageIsWaitedOut() throws Exception {
    List<CompiledRule> loaded = new ArrayList<>(RuleLoader.load(null).rules());
    loaded.add(RuleLoader.compile(BROKEN_RULE));
    DetectionEngine engine = new DetectionEngine(Duration.ofMinutes(5), 1000, 50);
    engine.setRules(loaded);
    when(rules.engine()).thenReturn(engine);
    AtomicInteger outageStores = new AtomicInteger();
    doAnswer(
            inv -> {
              Alert a = inv.getArgument(0);
              if (a.eventIds().contains("priv-2") && outageStores.incrementAndGet() <= 3) {
                throw new CannotGetJdbcConnectionException("database unavailable");
              }
              return null;
            })
        .when(alerts)
        .upsert(any());

    Properties pp = new Properties();
    pp.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, broker.getBrokersAsString());
    try (KafkaProducer<String, String> producer =
        new KafkaProducer<>(pp, new StringSerializer(), new StringSerializer())) {
      for (Event e :
          List.of(firewall("poison-1"), privilegeUse("priv-1"), privilegeUse("priv-2"))) {
        EnrichedEvent enriched =
            new EnrichedEvent(
                e, "US", "AS0", true, null, false, "infrastructure", "critical", null, null);
        producer.send(new ProducerRecord<>(Topics.ENRICHED, "k", Json.write(enriched))).get();
      }
    }

    List<ConsumerRecord<String, String>> produced = consume(Topics.ALERTS, 2);
    List<ConsumerRecord<String, String>> dlq = consume(Topics.DLQ, 1);

    assertThat(produced)
        .map(r -> Json.read(r.value(), Alert.class).eventIds())
        .containsExactly(List.of("priv-1"), List.of("priv-2"));
    assertThat(outageStores.get()).isEqualTo(4);
    assertThat(dlq).hasSize(1);
    ConsumerRecord<String, String> dead = dlq.get(0);
    assertThat(Json.read(dead.value(), EnrichedEvent.class).event().id()).isEqualTo("poison-1");
    assertThat(header(dead, Topics.HEADER_ERROR_STAGE)).isEqualTo("detect");
    assertThat(header(dead, Topics.HEADER_ERROR)).contains("not numeric");
  }

  private static Event firewall(String id) {
    return new Event(
        id,
        Instant.parse("2026-11-01T12:00:00Z"),
        Event.EventType.FIREWALL,
        "test",
        "fw-edge-01",
        null,
        "10.0.0.9",
        "203.0.113.5",
        443,
        "allow",
        null,
        null,
        100L,
        null);
  }

  private static Event privilegeUse(String id) {
    return new Event(
        id,
        Instant.parse("2026-11-01T12:00:00Z"),
        Event.EventType.AUTH,
        "test",
        "srv-dc-01",
        "a.khan",
        "10.0.0.5",
        null,
        null,
        "success",
        "4672",
        2,
        null,
        null);
  }

  private static String header(ConsumerRecord<?, ?> record, String name) {
    return new String(record.headers().lastHeader(name).value(), StandardCharsets.UTF_8);
  }

  private List<ConsumerRecord<String, String>> consume(String topic, int expected) {
    Properties p = new Properties();
    p.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, broker.getBrokersAsString());
    p.put(ConsumerConfig.GROUP_ID_CONFIG, "test-" + topic + "-" + System.nanoTime());
    p.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
    List<ConsumerRecord<String, String>> out = new ArrayList<>();
    try (KafkaConsumer<String, String> consumer =
        new KafkaConsumer<>(p, new StringDeserializer(), new StringDeserializer())) {
      consumer.subscribe(List.of(topic));
      long deadline = System.currentTimeMillis() + Duration.ofSeconds(45).toMillis();
      while (out.size() < expected && System.currentTimeMillis() < deadline) {
        consumer.poll(Duration.ofMillis(500)).forEach(out::add);
      }
      consumer.poll(Duration.ofSeconds(2)).forEach(out::add); // anything extra is a duplicate
    }
    return out;
  }
}
