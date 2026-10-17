package io.github.tajaddin.threat.detect.api;

import io.github.tajaddin.threat.common.Alert;
import io.github.tajaddin.threat.detect.AlertRepository;
import io.github.tajaddin.threat.detect.RuleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@Validated
@Tag(name = "alerts", description = "Alerts, rules and pipeline statistics")
public class AlertController {
  private final AlertRepository alerts;
  private final RuleService rules;

  public AlertController(AlertRepository alerts, RuleService rules) {
    this.alerts = alerts;
    this.rules = rules;
  }

  @GetMapping("/alerts")
  @Operation(summary = "Recent alerts, newest first")
  public List<Alert> list(
      @RequestParam(required = false) String severity,
      @RequestParam(required = false) String ruleId,
      @RequestParam(required = false) @Min(1) @Max(10080) Integer minutes,
      @RequestParam(defaultValue = "100") @Min(1) @Max(500) int limit,
      @RequestParam(defaultValue = "0") @Min(0) int offset) {
    Instant since = minutes == null ? null : Instant.now().minus(Duration.ofMinutes(minutes));
    return alerts.list(severity, ruleId, since, limit, offset);
  }

  @GetMapping("/alerts/{id}")
  public ResponseEntity<Alert> get(@PathVariable String id) {
    return alerts.get(id).map(ResponseEntity::ok).orElse(ResponseEntity.notFound().build());
  }

  @GetMapping("/rules")
  @Operation(summary = "Loaded rules with hit counts")
  public Map<String, Object> rules() {
    return Map.of("rules", rules.list(), "errors", rules.lastErrors());
  }

  @GetMapping(value = "/rules/{id}/yaml", produces = "text/yaml")
  public ResponseEntity<String> yaml(@PathVariable String id) {
    String y = rules.yaml(id);
    return y == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(y);
  }

  @PostMapping("/rules/reload")
  @Operation(summary = "Re-read rule files and swap the engine's rule set")
  public Map<String, Object> reload() {
    var loaded = rules.reload();
    return Map.of("loaded", loaded.rules().size(), "errors", loaded.errors());
  }

  @GetMapping("/stats")
  @Operation(summary = "Alert counts and detection latency over a window")
  public Map<String, Object> stats(
      @RequestParam(defaultValue = "60") @Min(1) @Max(10080) int minutes) {
    Instant since = Instant.now().minus(Duration.ofMinutes(minutes));
    return Map.of(
        "minutes", minutes,
        "alerts", alerts.count(since),
        "bySeverity", alerts.countBySeverity(since),
        "latency", alerts.latencyStats(since),
        "rulesLoaded", rules.engine().rules().size());
  }
}
