package io.github.tajaddin.threat.common;

import java.time.Instant;
import java.util.List;

/**
 * A detection. {@code key} is the grouping value (for example the source IP) for threshold rules
 * and the event id for stateless ones; {@code detectionLatencyMs} is detectedAt minus the
 * triggering event's ingestedAt, measured on the same machine's clock.
 */
public record Alert(
    String id,
    String ruleId,
    String ruleTitle,
    Severity severity,
    String key,
    List<String> eventIds,
    int eventCount,
    Instant firstSeen,
    Instant lastSeen,
    Instant detectedAt,
    long detectionLatencyMs,
    String summary) {

  public enum Severity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
  }
}
