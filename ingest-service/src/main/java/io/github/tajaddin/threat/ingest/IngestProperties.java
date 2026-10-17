package io.github.tajaddin.threat.ingest;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @param apiKeys accepted X-API-Key values; empty means open (local development only)
 * @param rateLimitPerMinute events per minute allowed per API key (batch size counts)
 * @param maxBatch largest batch one request may carry
 * @param dedupWindow how long an event id is remembered for duplicate suppression
 * @param dedupMaxEntries bound on the in-memory duplicate window
 */
@ConfigurationProperties(prefix = "ingest")
public record IngestProperties(
    List<String> apiKeys,
    long rateLimitPerMinute,
    int maxBatch,
    Duration dedupWindow,
    long dedupMaxEntries) {
  public IngestProperties {
    if (apiKeys == null) apiKeys = List.of();
    if (rateLimitPerMinute <= 0) rateLimitPerMinute = 600_000;
    if (maxBatch <= 0) maxBatch = 1000;
    if (dedupWindow == null) dedupWindow = Duration.ofMinutes(10);
    if (dedupMaxEntries <= 0) dedupMaxEntries = 2_000_000;
  }
}
