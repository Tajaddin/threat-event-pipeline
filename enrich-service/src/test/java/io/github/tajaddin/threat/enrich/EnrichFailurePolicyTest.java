package io.github.tajaddin.threat.enrich;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import io.github.tajaddin.threat.common.EnrichedEvent;
import io.github.tajaddin.threat.common.Event;
import io.github.tajaddin.threat.common.Json;
import io.github.tajaddin.threat.common.Topics;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
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
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.CannotGetJdbcConnectionException;
import org.springframework.kafka.config.KafkaListenerEndpointRegistry;
import org.springframework.kafka.listener.AbstractMessageListenerContainer;
import org.springframework.kafka.listener.AfterRollbackProcessor;
import org.springframework.kafka.test.EmbeddedKafkaBroker;
import org.springframework.kafka.test.context.EmbeddedKafka;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/**
 * The enrich failure policy against a real (in-process) broker, with the lookups stubbed: a record
 * that fails on its own is dead-lettered and the records around it still commit; a database outage
 * dead-letters nothing and the poll is retried until the database answers.
 */
@SpringBootTest(
    properties = {
      "spring.kafka.bootstrap-servers=${spring.embedded.kafka.brokers}",
      "spring.flyway.enabled=false"
    })
@EmbeddedKafka(
    kraft = true,
    partitions = 1,
    topics = {Topics.RAW, Topics.ENRICHED, Topics.DLQ},
    brokerProperties = {
      "transaction.state.log.replication.factor=1",
      "transaction.state.log.min.isr=1"
    })
class EnrichFailurePolicyTest {
  private static final String POISON_IP = "198.51.100.66";
  private static final String FLAKY_IP = "198.51.100.77";

  @Autowired EmbeddedKafkaBroker broker;
  @Autowired KafkaListenerEndpointRegistry listeners;
  @Autowired AfterRollbackProcessor<?, ?> afterRollback;
  @MockitoBean Lookups lookups;

  @Test
  void listenerUsesTheConfiguredAfterRollbackProcessor() {
    assertThat(listeners.getListenerContainers())
        .isNotEmpty()
        .allSatisfy(
            c ->
                assertThat(((AbstractMessageListenerContainer<?, ?>) c).getAfterRollbackProcessor())
                    .isSameAs(afterRollback));
  }

  @Test
  void poisonRecordIsDeadLetteredAloneAndDatabaseOutageIsRetried() throws Exception {
    AtomicInteger flakyCalls = new AtomicInteger();
    when(lookups.asset(any())).thenReturn(Optional.empty());
    when(lookups.ip(any()))
        .thenAnswer(
            inv -> {
              String ip = inv.getArgument(0);
              if (POISON_IP.equals(ip)) {
                throw new DataIntegrityViolationException("value rejected by the database");
              }
              if (FLAKY_IP.equals(ip) && flakyCalls.incrementAndGet() <= 2) {
                throw new CannotGetJdbcConnectionException("database unavailable");
              }
              return Lookups.IpInfo.UNKNOWN;
            });

    List<Event> events =
        List.of(
            event("good-1", "10.0.0.1"),
            event("poison-1", POISON_IP),
            event("flaky-1", FLAKY_IP),
            event("good-2", "10.0.0.2"));
    Properties pp = new Properties();
    pp.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, broker.getBrokersAsString());
    try (KafkaProducer<String, String> producer =
        new KafkaProducer<>(pp, new StringSerializer(), new StringSerializer())) {
      for (Event e : events) {
        producer.send(new ProducerRecord<>(Topics.RAW, "k", Json.write(e))).get();
      }
    }

    List<String> enriched =
        consume(Topics.ENRICHED, 3).stream()
            .map(r -> Json.read(r.value(), EnrichedEvent.class).event().id())
            .toList();
    List<ConsumerRecord<String, String>> dlq = consume(Topics.DLQ, 1);

    assertThat(enriched).containsExactly("good-1", "flaky-1", "good-2");
    assertThat(dlq).hasSize(1);
    ConsumerRecord<String, String> dead = dlq.get(0);
    assertThat(Json.read(dead.value(), Event.class).id()).isEqualTo("poison-1");
    assertThat(header(dead, Topics.HEADER_ERROR_STAGE)).isEqualTo("enrich");
    assertThat(header(dead, Topics.HEADER_ERROR)).contains("value rejected by the database");
    assertThat(flakyCalls.get()).isGreaterThanOrEqualTo(3);
  }

  private static Event event(String id, String srcIp) {
    return new Event(
        id,
        Instant.parse("2026-11-01T12:00:00Z"),
        Event.EventType.AUTH,
        "test",
        "ws-0101",
        "a.khan",
        srcIp,
        null,
        null,
        "failure",
        "4625",
        3,
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
    p.put(ConsumerConfig.ISOLATION_LEVEL_CONFIG, "read_committed");
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
