package io.github.tajaddin.threat.detect;

import io.github.tajaddin.threat.common.Alert;
import io.github.tajaddin.threat.common.Json;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class AlertRepository {
  private final JdbcClient jdbc;

  public AlertRepository(JdbcClient jdbc) {
    this.jdbc = jdbc;
  }

  /** Insert or refresh by deterministic id; a redelivered event never creates a second row. */
  public void upsert(Alert a) {
    jdbc.sql(
            """
            insert into alerts (id, rule_id, rule_title, severity, alert_key, event_ids, event_count, first_seen, last_seen,
                                detected_at, detection_latency_ms, summary)
            values (cast(:id as uuid), :rule, :title, :severity, :key, cast(:eventIds as jsonb), :count, :first, :last, :detected, :latency, :summary)
            on conflict (id) do update set event_count = greatest(alerts.event_count, excluded.event_count),
              last_seen = greatest(alerts.last_seen, excluded.last_seen), event_ids = excluded.event_ids
            """)
        .param("id", a.id())
        .param("rule", a.ruleId())
        .param("title", a.ruleTitle())
        .param("severity", a.severity().name())
        .param("key", a.key())
        .param("eventIds", Json.write(a.eventIds()))
        .param("count", a.eventCount())
        .param("first", Timestamp.from(a.firstSeen()))
        .param("last", Timestamp.from(a.lastSeen()))
        .param("detected", Timestamp.from(a.detectedAt()))
        .param("latency", a.detectionLatencyMs())
        .param("summary", a.summary())
        .update();
  }

  public List<Alert> list(String severity, String ruleId, Instant since, int limit, int offset) {
    StringBuilder sql = new StringBuilder("select * from alerts where 1=1");
    Map<String, Object> params = new java.util.HashMap<>();
    if (severity != null && !severity.isBlank()) {
      sql.append(" and severity = :severity");
      params.put("severity", severity.toUpperCase());
    }
    if (ruleId != null && !ruleId.isBlank()) {
      sql.append(" and rule_id = :rule");
      params.put("rule", ruleId);
    }
    if (since != null) {
      sql.append(" and detected_at >= :since");
      params.put("since", Timestamp.from(since));
    }
    sql.append(" order by detected_at desc limit :limit offset :offset");
    params.put("limit", limit);
    params.put("offset", offset);
    return jdbc.sql(sql.toString()).params(params).query(this::map).list();
  }

  public Optional<Alert> get(String id) {
    return jdbc.sql("select * from alerts where id = cast(:id as uuid)")
        .param("id", id)
        .query(this::map)
        .optional();
  }

  public long count(Instant since) {
    return jdbc.sql("select count(*) from alerts where detected_at >= :since")
        .param("since", Timestamp.from(since))
        .query(Long.class)
        .single();
  }

  public List<Map<String, Object>> countBySeverity(Instant since) {
    return jdbc.sql(
            "select severity, count(*) as count from alerts where detected_at >= :since group by severity")
        .param("since", Timestamp.from(since))
        .query()
        .listOfRows();
  }

  public Map<String, Object> latencyStats(Instant since) {
    return jdbc.sql(
            """
            select count(*) as alerts,
                   coalesce(percentile_cont(0.5) within group (order by detection_latency_ms), 0) as p50_ms,
                   coalesce(percentile_cont(0.95) within group (order by detection_latency_ms), 0) as p95_ms,
                   coalesce(max(detection_latency_ms), 0) as max_ms
            from alerts where detected_at >= :since
            """)
        .param("since", Timestamp.from(since))
        .query()
        .singleRow();
  }

  private Alert map(java.sql.ResultSet rs, int i) throws java.sql.SQLException {
    @SuppressWarnings("unchecked")
    List<String> ids = Json.read(rs.getString("event_ids"), List.class);
    return new Alert(
        rs.getString("id"),
        rs.getString("rule_id"),
        rs.getString("rule_title"),
        Alert.Severity.valueOf(rs.getString("severity")),
        rs.getString("alert_key"),
        new ArrayList<>(ids),
        rs.getInt("event_count"),
        rs.getTimestamp("first_seen").toInstant(),
        rs.getTimestamp("last_seen").toInstant(),
        rs.getTimestamp("detected_at").toInstant(),
        rs.getLong("detection_latency_ms"),
        rs.getString("summary"));
  }
}
