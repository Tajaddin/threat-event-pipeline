package io.github.tajaddin.threat.detect;

import io.github.tajaddin.threat.common.Topics;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.nio.charset.StandardCharsets;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.header.internals.RecordHeaders;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.NestedExceptionUtils;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.InvalidDataAccessResourceUsageException;
import org.springframework.dao.RecoverableDataAccessException;
import org.springframework.dao.TransientDataAccessException;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.listener.DeadLetterPublishingRecoverer;
import org.springframework.kafka.listener.DefaultErrorHandler;
import org.springframework.kafka.listener.ListenerExecutionFailedException;
import org.springframework.kafka.listener.RetryListener;
import org.springframework.util.backoff.BackOff;
import org.springframework.util.backoff.ExponentialBackOff;
import org.springframework.util.backoff.FixedBackOff;

/**
 * Error policy for the detect listener. When the database or the broker fails, the record is
 * redelivered after a pause that grows from one second to thirty and never gives up, so an outage
 * delays alerts rather than dropping them, as long as the threshold window the record fired is
 * still in memory: an outage that outlasts {@code detect.window-retention}, or a restart during it,
 * loses that alert (see the README's Limitations). Any other failure belongs to the record (or to a
 * rule it trips): it is tried three times a second apart, then published to events.dlq with the
 * error and stage in headers, counted as {@code detect.events{outcome=dlq}}, and the partition
 * moves on.
 */
@Configuration
public class KafkaConfig {

  @Bean
  public DefaultErrorHandler errorHandler(
      KafkaTemplate<String, String> template, MeterRegistry registry) {
    DeadLetterPublishingRecoverer recoverer =
        new DeadLetterPublishingRecoverer(
            template, (record, ex) -> new TopicPartition(Topics.DLQ, -1));
    recoverer.setHeadersFunction(
        (record, ex) -> {
          Throwable cause = NestedExceptionUtils.getMostSpecificCause(ex);
          String error = cause.getClass().getSimpleName() + ": " + cause.getMessage();
          RecordHeaders headers = new RecordHeaders();
          headers.add(Topics.HEADER_ERROR, error.getBytes(StandardCharsets.UTF_8));
          headers.add(Topics.HEADER_ERROR_STAGE, "detect".getBytes(StandardCharsets.UTF_8));
          return headers;
        });
    DefaultErrorHandler handler = new DefaultErrorHandler(recoverer, new FixedBackOff(1000L, 2));
    BackOff untilAvailable = untilAvailable();
    handler.setBackOffFunction((record, ex) -> environmental(ex) ? untilAvailable : null);
    Counter deadLettered =
        Counter.builder("detect.events").tag("outcome", "dlq").register(registry);
    handler.setRetryListeners(
        new RetryListener() {
          @Override
          public void failedDelivery(ConsumerRecord<?, ?> record, Exception ex, int attempt) {}

          @Override
          public void recovered(ConsumerRecord<?, ?> record, Exception ex) {
            deadLettered.increment();
          }
        });
    return handler;
  }

  private static BackOff untilAvailable() {
    ExponentialBackOff backOff = new ExponentialBackOff(1000L, 2.0);
    backOff.setMaxInterval(30_000L);
    return backOff;
  }

  /**
   * Failures of the database or the broker rather than of the record. The container wraps what the
   * listener threw in a ListenerExecutionFailedException, itself a KafkaException, so the search
   * starts below it.
   */
  private static boolean environmental(Throwable ex) {
    Throwable start = ex instanceof ListenerExecutionFailedException ? ex.getCause() : ex;
    for (Throwable t = start; t != null; t = t.getCause()) {
      if (t instanceof TransientDataAccessException
          || t instanceof RecoverableDataAccessException
          || t instanceof DataAccessResourceFailureException
          || t instanceof InvalidDataAccessResourceUsageException
          || t instanceof org.apache.kafka.common.KafkaException
          || t instanceof org.springframework.kafka.KafkaException) {
        return true;
      }
    }
    return false;
  }
}
