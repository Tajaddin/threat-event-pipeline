package io.github.tajaddin.threat.ingest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.tajaddin.threat.common.Event;
import io.github.tajaddin.threat.common.SyntheticEvents;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.apache.kafka.clients.producer.BufferExhaustedException;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.errors.TimeoutException;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.BindException;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.springframework.kafka.KafkaException;
import org.springframework.kafka.core.KafkaProducerException;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;

class IngestUnitTest {

  @Test
  @SuppressWarnings("unchecked")
  void duplicatesAreDroppedAndCounted() {
    KafkaTemplate<String, String> kafka = mock(KafkaTemplate.class);
    when(kafka.send(any(ProducerRecord.class)))
        .thenReturn(CompletableFuture.completedFuture(mock(SendResult.class)));
    IngestProperties props =
        new IngestProperties(List.of(), false, 1000, 100, Duration.ofMinutes(1), 1000);
    IngestService service = new IngestService(kafka, props, new SimpleMeterRegistry());
    List<Event> events = new SyntheticEvents(1, 0, "t").batch(Instant.now(), 5);

    IngestService.Result first = service.accept(events);
    IngestService.Result second = service.accept(events);

    assertThat(first.accepted()).isEqualTo(5);
    assertThat(first.duplicates()).isZero();
    assertThat(second.accepted()).isZero();
    assertThat(second.duplicates()).isEqualTo(5);
    verify(kafka, times(5)).send(any(ProducerRecord.class));
  }

  private static IngestService service(KafkaTemplate<String, String> kafka) {
    IngestProperties props =
        new IngestProperties(List.of(), false, 1000, 100, Duration.ofMinutes(1), 1000);
    return new IngestService(kafka, props, new SimpleMeterRegistry());
  }

  @SuppressWarnings("unchecked")
  private static CompletableFuture<SendResult<String, String>> sent() {
    return CompletableFuture.completedFuture(mock(SendResult.class));
  }

  @Test
  @SuppressWarnings("unchecked")
  void sendThatFailsBeforeReturningIsBackpressureAndTheIdIsNotRemembered() {
    KafkaTemplate<String, String> kafka = mock(KafkaTemplate.class);
    when(kafka.send(any(ProducerRecord.class)))
        .thenThrow(new KafkaException("Send failed", new TimeoutException("no metadata")))
        .thenThrow(new KafkaException("Send failed", new BufferExhaustedException("buffer full")))
        .thenReturn(sent());
    IngestService service = service(kafka);
    List<Event> events = new SyntheticEvents(2, 0, "t").batch(Instant.now(), 1);

    assertThatThrownBy(() -> service.accept(events))
        .isInstanceOf(IngestService.ProducerBackpressureException.class);
    assertThatThrownBy(() -> service.accept(events))
        .isInstanceOf(IngestService.ProducerBackpressureException.class);
    IngestService.Result retry = service.accept(events);

    assertThat(retry.accepted()).isEqualTo(1);
    assertThat(retry.duplicates()).isZero();
  }

  @Test
  @SuppressWarnings("unchecked")
  void deliveryTimeoutKeepsTheFailedIdsAndRemembersTheAcknowledgedOnes() {
    KafkaTemplate<String, String> kafka = mock(KafkaTemplate.class);
    CompletableFuture<SendResult<String, String>> expired = new CompletableFuture<>();
    expired.completeExceptionally(
        new KafkaProducerException(null, "Failed to send", new TimeoutException("expired")));
    when(kafka.send(any(ProducerRecord.class)))
        .thenReturn(sent())
        .thenReturn(expired)
        .thenReturn(sent());
    IngestService service = service(kafka);
    List<Event> events = new SyntheticEvents(3, 0, "t").batch(Instant.now(), 2);

    assertThatThrownBy(() -> service.accept(events))
        .isInstanceOf(IngestService.ProducerBackpressureException.class);
    IngestService.Result retry = service.accept(events);

    assertThat(retry.accepted()).isEqualTo(1);
    assertThat(retry.duplicates()).isEqualTo(1);
    verify(kafka, times(3)).send(any(ProducerRecord.class));
  }

  @Test
  @SuppressWarnings("unchecked")
  void sendThatThrowsMidBatchWaitsForTheEarlierOnesAndRemembersThem() {
    KafkaTemplate<String, String> kafka = mock(KafkaTemplate.class);
    CompletableFuture<SendResult<String, String>> inFlight =
        CompletableFuture.supplyAsync(
            () -> mock(SendResult.class),
            CompletableFuture.delayedExecutor(300, TimeUnit.MILLISECONDS));
    when(kafka.send(any(ProducerRecord.class)))
        .thenReturn(inFlight)
        .thenThrow(new KafkaException("Send failed", new BufferExhaustedException("buffer full")))
        .thenReturn(sent());
    IngestService service = service(kafka);
    List<Event> events = new SyntheticEvents(6, 0, "t").batch(Instant.now(), 2);

    assertThatThrownBy(() -> service.accept(events))
        .isInstanceOf(IngestService.ProducerBackpressureException.class);
    IngestService.Result retry = service.accept(events);

    assertThat(retry.accepted()).isEqualTo(1);
    assertThat(retry.duplicates()).isEqualTo(1);
    verify(kafka, times(3)).send(any(ProducerRecord.class));
  }

  @Test
  @SuppressWarnings("unchecked")
  void anIdRepeatedInsideOneBatchIsProducedOnce() {
    KafkaTemplate<String, String> kafka = mock(KafkaTemplate.class);
    when(kafka.send(any(ProducerRecord.class))).thenReturn(sent());
    Event e = new SyntheticEvents(4, 0, "t").batch(Instant.now(), 1).get(0);

    IngestService.Result r = service(kafka).accept(List.of(e, e));

    assertThat(r.accepted()).isEqualTo(1);
    assertThat(r.duplicates()).isEqualTo(1);
    verify(kafka, times(1)).send(any(ProducerRecord.class));
  }

  @Test
  void rateLimiterCountsEventsNotRequests() {
    RateLimiter limiter =
        new RateLimiter(
            new IngestProperties(List.of("k"), false, 100, 100, Duration.ofMinutes(1), 1000));
    assertThat(limiter.tryConsume("k", 60)).isTrue();
    assertThat(limiter.tryConsume("k", 60)).isFalse();
    assertThat(limiter.tryConsume("other", 60)).isTrue();
  }

  @Test
  void apiKeyComparisonIsConstantTimeAndExact() {
    assertThat(ApiKeyFilter.constantTimeEquals("abc", "abc")).isTrue();
    assertThat(ApiKeyFilter.constantTimeEquals("abc", "abd")).isFalse();
    assertThat(ApiKeyFilter.constantTimeEquals("abc", "ab")).isFalse();
  }

  @Test
  void propertiesHaveSafeDefaults() {
    IngestProperties p = new IngestProperties(null, false, 0, 0, null, 0);
    assertThat(p.apiKeys()).isEmpty();
    assertThat(p.maxBatch()).isEqualTo(1000);
    assertThat(p.dedupWindow()).isEqualTo(Duration.ofMinutes(10));
  }

  private static IngestProperties bind(Map<String, String> source) {
    return new Binder(new MapConfigurationPropertySource(source))
        .bindOrCreate("ingest", IngestProperties.class);
  }

  @Test
  void blankEntriesInTheKeyListAreNotKeys() {
    assertThat(bind(Map.of("ingest.api-keys", "k1, ,k2,")).apiKeys()).containsExactly("k1", "k2");
  }

  @Test
  void requiredKeysStopStartUpWhenNoneIsSet() {
    for (String keys : List.of("", " , ")) {
      assertThatThrownBy(
              () -> bind(Map.of("ingest.require-api-keys", "true", "ingest.api-keys", keys)))
          .isInstanceOf(BindException.class)
          .hasRootCauseMessage("ingest.require-api-keys is set but ingest.api-keys holds no key");
    }
    assertThat(bind(Map.of("ingest.require-api-keys", "true", "ingest.api-keys", "k1")).apiKeys())
        .containsExactly("k1");
  }
}
