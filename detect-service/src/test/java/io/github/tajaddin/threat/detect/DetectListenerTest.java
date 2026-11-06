package io.github.tajaddin.threat.detect;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.tajaddin.threat.common.Alert;
import io.github.tajaddin.threat.common.EnrichedEvent;
import io.github.tajaddin.threat.common.Event;
import io.github.tajaddin.threat.common.Json;
import io.github.tajaddin.threat.common.SyntheticEvents;
import io.github.tajaddin.threat.common.Topics;
import io.github.tajaddin.threat.detect.engine.DetectionEngine;
import io.github.tajaddin.threat.detect.rules.RuleLoader;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.CannotGetJdbcConnectionException;
import org.springframework.kafka.core.KafkaProducerException;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.kafka.support.SendResult;

class DetectListenerTest {
  private final AlertRepository alerts = mock(AlertRepository.class);

  @SuppressWarnings("unchecked")
  private final KafkaTemplate<String, String> kafka = mock(KafkaTemplate.class);

  private DetectListener listener;

  @BeforeEach
  void setUp() {
    DetectionEngine engine = new DetectionEngine(Duration.ofMinutes(5), 1000, 50);
    engine.setRules(RuleLoader.load(null).rules());
    RuleService rules = mock(RuleService.class);
    when(rules.engine()).thenReturn(engine);
    listener = new DetectListener(rules, alerts, kafka, new SimpleMeterRegistry());
  }

  private static ConsumerRecord<String, String> record(Event e, long offset) {
    boolean internal = e.srcIp().startsWith("10.");
    EnrichedEvent enriched =
        new EnrichedEvent(
            e, "NL", "AS64503", internal, null, false, "x", "medium", e.timestamp(), e.timestamp());
    return new ConsumerRecord<>(Topics.ENRICHED, 0, offset, e.srcIp(), Json.write(enriched));
  }

  @SuppressWarnings("unchecked")
  private static CompletableFuture<SendResult<String, String>> sent() {
    return CompletableFuture.completedFuture(mock(SendResult.class));
  }

  @Test
  void thresholdAlertIsStoredWhenTheFirstAttemptToStoreItFails() {
    when(kafka.send(anyString(), anyString(), anyString())).thenReturn(sent());
    doThrow(new CannotGetJdbcConnectionException("database unavailable"))
        .doNothing()
        .when(alerts)
        .upsert(any());
    // starts on a minute boundary, so all ten land in one 60 s window
    List<Event> burst =
        new SyntheticEvents(7, 0, "t")
            .scenario(SyntheticEvents.Scenario.BRUTE_FORCE, Instant.parse("2026-11-01T12:00:00Z"))
            .subList(0, 10);
    for (int i = 0; i < 9; i++) {
      listener.onRecord(record(burst.get(i), i), mock(Acknowledgment.class));
    }
    ConsumerRecord<String, String> tenth = record(burst.get(9), 9);

    Acknowledgment firstAck = mock(Acknowledgment.class);
    assertThatThrownBy(() -> listener.onRecord(tenth, firstAck))
        .isInstanceOf(CannotGetJdbcConnectionException.class);
    verify(firstAck, never()).acknowledge();

    Acknowledgment retryAck = mock(Acknowledgment.class);
    listener.onRecord(tenth, retryAck); // the container redelivers the same record

    ArgumentCaptor<Alert> stored = ArgumentCaptor.forClass(Alert.class);
    verify(alerts, times(2)).upsert(stored.capture());
    assertThat(stored.getAllValues()).extracting(Alert::ruleId).containsOnly("auth-brute-force");
    assertThat(stored.getAllValues().get(1)).isEqualTo(stored.getAllValues().get(0));
    verify(kafka).send(eq(Topics.ALERTS), anyString(), anyString());
    verify(retryAck).acknowledge();
  }

  @Test
  void offsetIsNotAcknowledgedUntilTheAlertIsProduced() {
    CompletableFuture<SendResult<String, String>> failed = new CompletableFuture<>();
    failed.completeExceptionally(
        new KafkaProducerException(null, "Failed to send", new RuntimeException("broker gone")));
    when(kafka.send(anyString(), anyString(), anyString())).thenReturn(failed);
    doNothing().when(alerts).upsert(any());
    Event exfiltration =
        new SyntheticEvents(8, 0, "t")
            .scenario(SyntheticEvents.Scenario.EXFILTRATION, Instant.now())
            .get(0);
    Acknowledgment ack = mock(Acknowledgment.class);

    assertThatThrownBy(() -> listener.onRecord(record(exfiltration, 0), ack))
        .hasRootCauseMessage("broker gone");
    verify(ack, never()).acknowledge();
  }
}
