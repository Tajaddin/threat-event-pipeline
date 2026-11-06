package io.github.tajaddin.threat.index;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.listener.DefaultErrorHandler;
import org.springframework.kafka.support.ExponentialBackOffWithMaxRetries;

/**
 * A failed bulk (OpenSearch down, or documents refused with 429 or a 5xx) is retried with
 * exponential back-off; the batch is never dropped. Documents refused for any other reason are
 * dead-lettered by the listener instead.
 */
@Configuration
public class KafkaConfig {
  @Bean
  public DefaultErrorHandler errorHandler() {
    ExponentialBackOffWithMaxRetries backOff =
        new ExponentialBackOffWithMaxRetries(Integer.MAX_VALUE);
    backOff.setInitialInterval(1000L);
    backOff.setMultiplier(2.0);
    backOff.setMaxInterval(30_000L);
    return new DefaultErrorHandler(backOff);
  }
}
