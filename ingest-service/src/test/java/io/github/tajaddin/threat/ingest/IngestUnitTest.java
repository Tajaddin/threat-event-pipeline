package io.github.tajaddin.threat.ingest;

import static org.assertj.core.api.Assertions.assertThat;
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
import java.util.concurrent.CompletableFuture;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.junit.jupiter.api.Test;
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
        new IngestProperties(List.of(), 1000, 100, Duration.ofMinutes(1), 1000);
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

  @Test
  void rateLimiterCountsEventsNotRequests() {
    RateLimiter limiter =
        new RateLimiter(new IngestProperties(List.of("k"), 100, 100, Duration.ofMinutes(1), 1000));
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
    IngestProperties p = new IngestProperties(null, 0, 0, null, 0);
    assertThat(p.apiKeys()).isEmpty();
    assertThat(p.maxBatch()).isEqualTo(1000);
    assertThat(p.dedupWindow()).isEqualTo(Duration.ofMinutes(10));
  }
}
