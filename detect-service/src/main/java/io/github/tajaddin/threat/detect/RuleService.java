package io.github.tajaddin.threat.detect;

import io.github.tajaddin.threat.detect.engine.DetectionEngine;
import io.github.tajaddin.threat.detect.rules.CompiledRule;
import io.github.tajaddin.threat.detect.rules.RuleLoader;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Owns the engine and the rule catalogue in Postgres (title, severity, YAML, load errors, hit
 * counts).
 */
@Service
public class RuleService {
  private static final Logger log = LoggerFactory.getLogger(RuleService.class);

  public record RuleView(
      String id,
      String title,
      String severity,
      String category,
      boolean threshold,
      long hits,
      Instant loadedAt,
      List<String> tags) {}

  private final DetectionEngine engine;
  private final DetectProperties props;
  private final JdbcClient jdbc;
  private final AtomicInteger loadedGauge = new AtomicInteger();
  private volatile List<String> lastErrors = List.of();

  public RuleService(DetectProperties props, JdbcClient jdbc, MeterRegistry registry) {
    this.props = props;
    this.jdbc = jdbc;
    this.engine =
        new DetectionEngine(
            props.windowRetention(), props.maxWindows(), props.maxEventIdsPerAlert());
    registry.gauge("detect.rules.loaded", loadedGauge);
  }

  public DetectionEngine engine() {
    return engine;
  }

  @PostConstruct
  public void init() {
    reload();
  }

  @Transactional
  public synchronized RuleLoader.Loaded reload() {
    RuleLoader.Loaded loaded =
        RuleLoader.load(
            props.rulesDir() == null || props.rulesDir().isBlank()
                ? null
                : Path.of(props.rulesDir()));
    for (CompiledRule r : loaded.rules()) {
      jdbc.sql(
              """
              insert into rules (id, title, severity, category, threshold, tags, yaml, loaded_at)
              values (:id, :title, :severity, :category, :threshold, :tags, :yaml, now())
              on conflict (id) do update set title = excluded.title, severity = excluded.severity, category = excluded.category,
                threshold = excluded.threshold, tags = excluded.tags, yaml = excluded.yaml, loaded_at = now()
              """)
          .param("id", r.id())
          .param("title", r.title())
          .param("severity", r.severity().name())
          .param("category", r.category())
          .param("threshold", r.threshold() != null)
          .param("tags", String.join(",", r.tags()))
          .param("yaml", r.yaml())
          .update();
    }
    engine.setRules(loaded.rules());
    loadedGauge.set(loaded.rules().size());
    lastErrors = loaded.errors();
    log.info("rules active: {}", loaded.rules().stream().map(CompiledRule::id).toList());
    return loaded;
  }

  public List<String> lastErrors() {
    return lastErrors;
  }

  public List<RuleView> list() {
    return jdbc.sql(
            """
            select r.id, r.title, r.severity, r.category, r.threshold, r.tags, r.loaded_at,
                   (select count(*) from alerts a where a.rule_id = r.id) as hits
            from rules r order by r.severity desc, r.id
            """)
        .query(
            (rs, i) ->
                new RuleView(
                    rs.getString("id"),
                    rs.getString("title"),
                    rs.getString("severity"),
                    rs.getString("category"),
                    rs.getBoolean("threshold"),
                    rs.getLong("hits"),
                    rs.getTimestamp("loaded_at").toInstant(),
                    rs.getString("tags").isBlank()
                        ? List.of()
                        : List.of(rs.getString("tags").split(","))))
        .list();
  }

  public String yaml(String id) {
    return jdbc.sql("select yaml from rules where id = :id")
        .param("id", id)
        .query(String.class)
        .optional()
        .orElse(null);
  }
}
