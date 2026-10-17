package io.github.tajaddin.threat.detect;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @param rulesDir optional directory of extra rule YAML files (mounted ConfigMap in Kubernetes)
 * @param windowRetention how long threshold windows stay in memory after their last event
 * @param maxWindows bound on concurrently tracked (rule, key, window) states
 * @param maxEventIdsPerAlert how many triggering event ids an alert keeps
 * @param corsOrigins origins allowed to call the alert API (the console)
 */
@ConfigurationProperties(prefix = "detect")
public record DetectProperties(
    String rulesDir,
    Duration windowRetention,
    long maxWindows,
    int maxEventIdsPerAlert,
    List<String> corsOrigins) {
  public DetectProperties {
    if (windowRetention == null) windowRetention = Duration.ofMinutes(30);
    if (maxWindows <= 0) maxWindows = 500_000;
    if (maxEventIdsPerAlert <= 0) maxEventIdsPerAlert = 50;
    if (corsOrigins == null) corsOrigins = List.of();
  }
}
