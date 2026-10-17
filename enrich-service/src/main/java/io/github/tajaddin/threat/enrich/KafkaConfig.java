package io.github.tajaddin.threat.enrich;

import io.github.tajaddin.threat.common.Topics;
import org.apache.kafka.common.TopicPartition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.listener.DeadLetterPublishingRecoverer;
import org.springframework.kafka.listener.DefaultAfterRollbackProcessor;
import org.springframework.util.backoff.FixedBackOff;

/**
 * Error policy for the transactional batch listener. Spring Boot wires the KafkaTransactionManager
 * (from the transaction-id-prefix) and this AfterRollbackProcessor into the listener container: an
 * unexpected failure (database down, bug) rolls the transaction back; the listener reports the
 * index of the failing record, so the records before it are committed and the failing one is
 * retried three times a second apart, then published to events.dlq with the exception in headers
 * and its offset committed, so one poison record cannot stall a partition.
 */
@Configuration
public class KafkaConfig {

  @Bean
  public DeadLetterPublishingRecoverer deadLetterRecoverer(KafkaTemplate<String, String> template) {
    return new DeadLetterPublishingRecoverer(
        template, (record, ex) -> new TopicPartition(Topics.DLQ, -1));
  }

  @Bean
  public DefaultAfterRollbackProcessor<String, String> afterRollbackProcessor(
      DeadLetterPublishingRecoverer recoverer, KafkaTemplate<String, String> template) {
    return new DefaultAfterRollbackProcessor<>(
        recoverer, new FixedBackOff(1000L, 3), template, true);
  }
}
