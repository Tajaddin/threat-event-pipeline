package io.github.tajaddin.threat.enrich;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.listener.AfterRollbackProcessor;
import org.springframework.kafka.listener.DefaultAfterRollbackProcessor;
import org.springframework.util.backoff.ExponentialBackOff;

/**
 * What happens after the listener rolls a poll back, which it does only for database and broker
 * failures (see {@link EnrichListener}): the whole poll is re-read after a pause that grows from
 * one second to thirty and never gives up, so nothing is skipped or dead-lettered during an outage.
 *
 * <p>The bean is typed {@code <Object, Object>} because that is the type Spring Boot injects into
 * the listener container factory; a processor declared with narrower generics is silently ignored.
 */
@Configuration
public class KafkaConfig {

  @Bean
  public AfterRollbackProcessor<Object, Object> afterRollbackProcessor() {
    ExponentialBackOff backOff = new ExponentialBackOff(1000L, 2.0);
    backOff.setMaxInterval(30_000L);
    return new DefaultAfterRollbackProcessor<>(backOff);
  }
}
