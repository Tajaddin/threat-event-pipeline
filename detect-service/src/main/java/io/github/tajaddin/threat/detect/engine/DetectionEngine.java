package io.github.tajaddin.threat.detect.engine;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.tajaddin.threat.common.Alert;
import io.github.tajaddin.threat.common.EnrichedEvent;
import io.github.tajaddin.threat.detect.rules.CompiledRule;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

/**
 * Runs every loaded rule against an event. Stateless rules alert on the event itself. Threshold
 * rules keep a per-(rule, key, window) counter in a bounded, expiring map and alert once when the
 * count (or distinct value count) reaches the threshold within the tumbling window. Windows are
 * keyed by the event's own timestamp, so replayed or out-of-order events land in the right window.
 * The alert id is derived from (rule, key, window), which makes alert storage idempotent across
 * restarts and redeliveries.
 */
public final class DetectionEngine {
  private final AtomicReference<List<CompiledRule>> rules = new AtomicReference<>(List.of());
  private final Cache<String, WindowState> windows;
  private final int maxEventIdsPerAlert;

  public DetectionEngine(Duration windowRetention, long maxWindows, int maxEventIdsPerAlert) {
    this.windows =
        Caffeine.newBuilder().expireAfterWrite(windowRetention).maximumSize(maxWindows).build();
    this.maxEventIdsPerAlert = maxEventIdsPerAlert;
  }

  public void setRules(List<CompiledRule> compiled) {
    rules.set(List.copyOf(compiled));
  }

  public List<CompiledRule> rules() {
    return rules.get();
  }

  public List<Alert> evaluate(EnrichedEvent enriched) {
    Map<String, Object> flat = enriched.flatten();
    Instant eventTime = enriched.event().timestamp();
    Instant ingestedAt = enriched.ingestedAt() != null ? enriched.ingestedAt() : eventTime;
    List<Alert> alerts = new ArrayList<>();
    for (CompiledRule rule : rules.get()) {
      if (!rule.appliesTo(flat) || !rule.matches(flat)) {
        continue;
      }
      Instant now = Instant.now();
      long latency = Math.max(0, Duration.between(ingestedAt, now).toMillis());
      if (rule.threshold() == null) {
        String key = enriched.event().id();
        alerts.add(
            new Alert(
                alertId(rule.id(), key, eventTime),
                rule.id(),
                rule.title(),
                rule.severity(),
                key,
                List.of(enriched.event().id()),
                1,
                eventTime,
                eventTime,
                now,
                latency,
                summary(rule, flat, 1)));
        continue;
      }
      CompiledRule.ThresholdSpec t = rule.threshold();
      String key =
          t.groupBy().stream()
              .map(f -> String.valueOf(flat.get(f)))
              .collect(Collectors.joining("|"));
      long windowMillis = t.window().toMillis();
      Instant windowStart =
          Instant.ofEpochMilli(
              Math.floorDiv(eventTime.toEpochMilli(), windowMillis) * windowMillis);
      String stateKey = rule.id() + "|" + key + "|" + windowStart.toEpochMilli();
      WindowState state = windows.get(stateKey, k -> new WindowState(windowStart));
      boolean fire;
      synchronized (state) {
        state.count++;
        state.lastSeen = eventTime.isAfter(state.lastSeen) ? eventTime : state.lastSeen;
        state.firstSeen = eventTime.isBefore(state.firstSeen) ? eventTime : state.firstSeen;
        state.firstIngestedAt =
            ingestedAt.isBefore(state.firstIngestedAt) ? ingestedAt : state.firstIngestedAt;
        if (state.eventIds.size() < maxEventIdsPerAlert) {
          state.eventIds.add(enriched.event().id());
        }
        if (t.distinct() != null) {
          state.distinct.add(String.valueOf(flat.get(t.distinct())));
        }
        long measure = t.distinct() != null ? state.distinct.size() : state.count;
        fire = !state.fired && measure >= t.count();
        if (fire) {
          state.fired = true;
        }
      }
      if (fire) {
        long thresholdLatency = Math.max(0, Duration.between(ingestedAt, now).toMillis());
        alerts.add(
            new Alert(
                alertId(rule.id(), key, windowStart),
                rule.id(),
                rule.title(),
                rule.severity(),
                key,
                List.copyOf(state.eventIds),
                (int) state.count,
                state.firstSeen,
                state.lastSeen,
                now,
                thresholdLatency,
                summary(rule, flat, state.count)));
      }
    }
    return alerts;
  }

  public static String alertId(String ruleId, String key, Instant windowStart) {
    return UUID.nameUUIDFromBytes(
            (ruleId + "|" + key + "|" + windowStart.toEpochMilli())
                .getBytes(StandardCharsets.UTF_8))
        .toString();
  }

  private static String summary(CompiledRule rule, Map<String, Object> flat, long count) {
    StringBuilder sb = new StringBuilder(rule.title());
    Object src = flat.get("src_ip");
    Object user = flat.get("user");
    Object host = flat.get("host");
    if (src != null) sb.append(" from ").append(src);
    if (user != null) sb.append(" as ").append(user);
    if (host != null) sb.append(" on ").append(host);
    if (count > 1) sb.append(" (").append(count).append(" events)");
    return sb.toString();
  }

  static final class WindowState {
    final Instant windowStart;
    long count;
    Instant firstSeen;
    Instant lastSeen;
    Instant firstIngestedAt = Instant.MAX;
    boolean fired;
    final List<String> eventIds = new ArrayList<>();
    final Set<String> distinct = new HashSet<>();

    WindowState(Instant windowStart) {
      this.windowStart = windowStart;
      this.firstSeen = Instant.MAX;
      this.lastSeen = Instant.MIN;
    }
  }
}
