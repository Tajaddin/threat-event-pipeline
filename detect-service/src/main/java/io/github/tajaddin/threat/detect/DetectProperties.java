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
 * @param apiKeys accepted X-API-Key values for /api/**; blank entries are dropped, and an empty
 *     list means open (local development only)
 * @param requireApiKeys refuse to start with an empty key list (the Helm chart sets it)
 */
@ConfigurationProperties(prefix = "detect")
public record DetectProperties(
    String rulesDir,
    Duration windowRetention,
    long maxWindows,
    int maxEventIdsPerAlert,
    List<String> corsOrigins,
    List<String> apiKeys,
    boolean requireApiKeys) {
  public DetectProperties {
    if (windowRetention == null) windowRetention = Duration.ofMinutes(30);
    if (maxWindows <= 0) maxWindows = 500_000;
    if (maxEventIdsPerAlert <= 0) maxEventIdsPerAlert = 50;
    if (corsOrigins == null) corsOrigins = List.of();
    apiKeys = apiKeys == null ? List.of() : apiKeys.stream().filter(k -> !k.isBlank()).toList();
    if (requireApiKeys && apiKeys.isEmpty()) {
      throw new IllegalArgumentException(
          "detect.require-api-keys is set but detect.api-keys holds no key");
    }
  }
}
