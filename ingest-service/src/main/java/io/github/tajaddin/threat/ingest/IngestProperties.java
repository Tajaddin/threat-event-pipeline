package io.github.tajaddin.threat.ingest;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @param apiKeys accepted X-API-Key values; blank entries are dropped, and an empty list means open
 *     (local development only)
 * @param requireApiKeys refuse to start with an empty key list (the Helm chart sets it)
 * @param rateLimitPerMinute events per minute allowed per API key (batch size counts)
 * @param maxBatch largest batch one request may carry
 * @param dedupWindow how long an event id is remembered for duplicate suppression
 * @param dedupMaxEntries bound on the in-memory duplicate window
 */
@ConfigurationProperties(prefix = "ingest")
public record IngestProperties(
    List<String> apiKeys,
    boolean requireApiKeys,
    long rateLimitPerMinute,
    int maxBatch,
    Duration dedupWindow,
    long dedupMaxEntries) {
  public IngestProperties {
    apiKeys = apiKeys == null ? List.of() : apiKeys.stream().filter(k -> !k.isBlank()).toList();
    if (requireApiKeys && apiKeys.isEmpty()) {
      throw new IllegalArgumentException(
          "ingest.require-api-keys is set but ingest.api-keys holds no key");
    }
    if (rateLimitPerMinute <= 0) rateLimitPerMinute = 600_000;
    if (maxBatch <= 0) maxBatch = 1000;
    if (dedupWindow == null) dedupWindow = Duration.ofMinutes(10);
    if (dedupMaxEntries <= 0) dedupMaxEntries = 2_000_000;
  }
}
