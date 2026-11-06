package io.github.tajaddin.threat.detect;

import io.github.tajaddin.threat.common.Alert;
import io.github.tajaddin.threat.common.EnrichedEvent;
import io.github.tajaddin.threat.common.Json;
import io.github.tajaddin.threat.common.Topics;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.stereotype.Component;

/**
 * At-least-once: the offset is acknowledged only after every alert the event raised is stored and
 * its send to the alerts topic is acknowledged. If either fails the listener throws, {@link
 * KafkaConfig}'s error handler redelivers the record, and the engine, which does not count a
 * redelivered event twice, returns the same alert again; ids are deterministic and the store
 * upserts, so the retry is harmless.
 */
@Component
public class DetectListener {
  private static final Logger log = LoggerFactory.getLogger(DetectListener.class);

  private final RuleService rules;
  private final AlertRepository alerts;
  private final KafkaTemplate<String, String> kafka;
  private final MeterRegistry registry;
  private final Counter evaluated;
  private final Counter malformed;
  private final Timer evalTimer;
  private final Timer detectionLatency;

  public DetectListener(
      RuleService rules,
      AlertRepository alerts,
      KafkaTemplate<String, String> kafka,
      MeterRegistry registry) {
    this.rules = rules;
    this.alerts = alerts;
    this.kafka = kafka;
    this.registry = registry;
    this.evaluated =
        Counter.builder("detect.events").tag("outcome", "evaluated").register(registry);
    this.malformed =
        Counter.builder("detect.events").tag("outcome", "malformed").register(registry);
    this.evalTimer =
        Timer.builder("detect.evaluate").publishPercentileHistogram().register(registry);
    this.detectionLatency =
        Timer.builder("detect.latency")
            .description("ingest timestamp to alert creation")
            .publishPercentileHistogram()
            .maximumExpectedValue(Duration.ofMinutes(5))
            .register(registry);
  }

  @KafkaListener(
      topics = Topics.ENRICHED,
      groupId = "${spring.kafka.consumer.group-id}",
      concurrency = "${detect.concurrency:3}")
  public void onRecord(ConsumerRecord<String, String> record, Acknowledgment ack) {
    EnrichedEvent enriched;
    try {
      enriched = Json.read(record.value(), EnrichedEvent.class);
    } catch (IllegalArgumentException ex) {
      malformed.increment();
      log.warn(
          "skipping malformed enriched event at {}-{}: {}",
          record.partition(),
          record.offset(),
          ex.getMessage());
      ack.acknowledge();
      return;
    }
    Timer.Sample sample = Timer.start();
    List<Alert> found = rules.engine().evaluate(enriched);
    sample.stop(evalTimer);
    evaluated.increment();
    List<CompletableFuture<?>> sends = new ArrayList<>(found.size());
    for (Alert alert : found) {
      alerts.upsert(alert);
      sends.add(kafka.send(Topics.ALERTS, alert.key(), Json.write(alert)));
      registry
          .counter("detect.alerts", "rule", alert.ruleId(), "severity", alert.severity().name())
          .increment();
      detectionLatency.record(Duration.ofMillis(alert.detectionLatencyMs()));
      log.info(
          "alert rule={} severity={} key={} events={} latency_ms={}",
          alert.ruleId(),
          alert.severity(),
          alert.key(),
          alert.eventCount(),
          alert.detectionLatencyMs());
    }
    CompletableFuture.allOf(sends.toArray(CompletableFuture[]::new)).join();
    ack.acknowledge();
  }
}
