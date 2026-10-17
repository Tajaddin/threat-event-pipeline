package io.github.tajaddin.threat.detect.rules;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.tajaddin.threat.common.Alert;
import io.github.tajaddin.threat.common.EnrichedEvent;
import io.github.tajaddin.threat.common.Event;
import io.github.tajaddin.threat.common.SyntheticEvents;
import io.github.tajaddin.threat.detect.engine.DetectionEngine;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class RuleEngineTest {

  private static EnrichedEvent enriched(Event e, boolean srcInternal, String criticality) {
    return new EnrichedEvent(
        e,
        srcInternal ? "US" : "NL",
        srcInternal ? "AS0-internal" : "AS64503-exitnode",
        srcInternal,
        null,
        false,
        "x",
        criticality,
        e.timestamp(),
        e.timestamp());
  }

  @Test
  void bundledRulesLoadAndCompile() {
    RuleLoader.Loaded loaded = RuleLoader.load(null);
    assertThat(loaded.errors()).isEmpty();
    assertThat(loaded.rules())
        .extracting(CompiledRule::id)
        .contains(
            "auth-brute-force",
            "auth-password-spray",
            "auth-lateral-movement",
            "fw-port-scan",
            "fw-large-outbound-transfer",
            "auth-special-privileges-non-admin",
            "auth-logon-from-hostile-range");
  }

  @Test
  void fieldMatcherModifiers() {
    Map<String, Object> ev =
        Map.of(
            "user", "svc-backup", "bytes_out", 150_000_000L, "src_ip", "10.1.2.3", "code", "4625");
    assertThat(new FieldMatcher("user|startswith", "SVC-").test(ev)).isTrue();
    assertThat(new FieldMatcher("user|contains", List.of("nope", "backup")).test(ev)).isTrue();
    assertThat(new FieldMatcher("user|endswith", "up").test(ev)).isTrue();
    assertThat(new FieldMatcher("user|re", "^svc-[a-z]+$").test(ev)).isTrue();
    assertThat(new FieldMatcher("bytes_out|gte", 100_000_000).test(ev)).isTrue();
    assertThat(new FieldMatcher("bytes_out|lt", 100_000_000).test(ev)).isFalse();
    assertThat(new FieldMatcher("src_ip|cidr", "10.0.0.0/8").test(ev)).isTrue();
    assertThat(new FieldMatcher("src_ip|cidr", "192.168.0.0/16").test(ev)).isFalse();
    assertThat(new FieldMatcher("code", 4625).test(ev)).isTrue();
    assertThat(new FieldMatcher("missing", "null").test(ev)).isTrue();
    assertThatThrownBy(() -> new FieldMatcher("user|bogus", "x").test(ev))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void conditionGrammar() {
    List<String> names = List.of("selection", "filter", "sel_a", "sel_b");
    Map<String, Boolean> r =
        Map.of("selection", true, "filter", false, "sel_a", false, "sel_b", true);
    assertThat(Condition.parse("selection and not filter", names).test(r)).isTrue();
    assertThat(Condition.parse("selection and filter", names).test(r)).isFalse();
    assertThat(Condition.parse("(filter or sel_b) and selection", names).test(r)).isTrue();
    assertThat(Condition.parse("1 of sel_*", names).test(r)).isTrue();
    assertThat(Condition.parse("all of sel_*", names).test(r)).isFalse();
    assertThat(Condition.parse("not 1 of them", names).test(r)).isFalse();
    assertThatThrownBy(() -> Condition.parse("selection and", names))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> Condition.parse("unknown", names))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("unknown selection");
  }

  @Test
  void compileRejectsBadRules() {
    assertThatThrownBy(() -> RuleLoader.compile("id: x\ndetection:\n  selection:\n    a: 1\n"))
        .hasMessageContaining("condition");
    assertThatThrownBy(() -> RuleLoader.compile("id: x\ndetection:\n  condition: selection\n"))
        .hasMessageContaining("no selections");
    assertThatThrownBy(
            () ->
                RuleLoader.compile(
                    "id: x\ndetection:\n  selection:\n    a: 1\n  condition: selection\nthreshold:\n  count: 0\n  window: 60s\n  groupBy: [a]\n"))
        .hasMessageContaining("threshold");
    assertThatThrownBy(() -> RuleLoader.compile("not: [valid"))
        .hasMessageContaining("invalid YAML");
  }

  @Test
  void statelessRuleAlertsOnce() {
    DetectionEngine engine = new DetectionEngine(Duration.ofMinutes(5), 1000, 10);
    engine.setRules(RuleLoader.load(null).rules());
    SyntheticEvents s = new SyntheticEvents(5, 0, "t");
    Event exfil = s.scenario(SyntheticEvents.Scenario.EXFILTRATION, Instant.now()).get(0);
    List<Alert> alerts = engine.evaluate(enriched(exfil, true, "medium"));
    assertThat(alerts).hasSize(1);
    Alert a = alerts.get(0);
    assertThat(a.ruleId()).isEqualTo("fw-large-outbound-transfer");
    assertThat(a.severity()).isEqualTo(Alert.Severity.HIGH);
    assertThat(a.eventIds()).containsExactly(exfil.id());
    assertThat(a.summary()).contains("Large outbound transfer");
  }

  @Test
  void thresholdRuleFiresOnceAtTheCountAndIsDeterministic() {
    DetectionEngine engine = new DetectionEngine(Duration.ofMinutes(5), 1000, 10);
    engine.setRules(RuleLoader.load(null).rules());
    Instant base = Instant.parse("2026-10-17T12:00:00Z");
    List<Alert> all = new ArrayList<>();
    for (int i = 0; i < 12; i++) {
      Event e =
          new Event(
              "e" + i,
              base.plusSeconds(i),
              Event.EventType.AUTH,
              "t",
              "ws-0101",
              "a.khan",
              "203.0.113.9",
              null,
              null,
              "failure",
              "4625",
              3,
              null,
              null);
      all.addAll(engine.evaluate(enriched(e, false, "medium")));
    }
    List<Alert> brute = all.stream().filter(a -> a.ruleId().equals("auth-brute-force")).toList();
    assertThat(brute).hasSize(1);
    assertThat(brute.get(0).eventCount()).isEqualTo(10);
    assertThat(brute.get(0).key()).isEqualTo("203.0.113.9|a.khan");
    assertThat(brute.get(0).eventIds()).hasSize(10);
    assertThat(brute.get(0).id())
        .isEqualTo(DetectionEngine.alertId("auth-brute-force", "203.0.113.9|a.khan", base));
    // the spray rule needs 15 distinct users; one user never trips it
    assertThat(all.stream().noneMatch(a -> a.ruleId().equals("auth-password-spray"))).isTrue();
  }

  @Test
  void distinctThresholdCountsDistinctValues() {
    DetectionEngine engine = new DetectionEngine(Duration.ofMinutes(5), 1000, 10);
    engine.setRules(RuleLoader.load(null).rules());
    Instant base = Instant.parse("2026-10-17T12:00:00Z");
    SyntheticEvents s = new SyntheticEvents(9, 0, "t");
    List<Alert> all = new ArrayList<>();
    for (Event e : s.scenario(SyntheticEvents.Scenario.PORT_SCAN, base)) {
      all.addAll(engine.evaluate(enriched(e, false, "medium")));
    }
    assertThat(all.stream().filter(a -> a.ruleId().equals("fw-port-scan"))).hasSize(1);
    assertThat(
            all.stream()
                .filter(a -> a.ruleId().equals("fw-port-scan"))
                .findFirst()
                .orElseThrow()
                .eventCount())
        .isEqualTo(50);
  }

  @Test
  void filterSelectionExcludesServiceAccounts() {
    DetectionEngine engine = new DetectionEngine(Duration.ofMinutes(5), 1000, 10);
    engine.setRules(RuleLoader.load(null).rules());
    Event admin =
        new Event(
            "p1",
            Instant.now(),
            Event.EventType.AUTH,
            "t",
            "srv-dc-01",
            "a.khan",
            "10.0.0.5",
            null,
            null,
            "success",
            "4672",
            2,
            null,
            null);
    Event svc =
        new Event(
            "p2",
            Instant.now(),
            Event.EventType.AUTH,
            "t",
            "srv-dc-01",
            "svc-backup",
            "10.0.0.5",
            null,
            null,
            "success",
            "4672",
            2,
            null,
            null);
    assertThat(engine.evaluate(enriched(admin, true, "critical")))
        .extracting(Alert::ruleId)
        .contains("auth-special-privileges-non-admin");
    assertThat(engine.evaluate(enriched(svc, true, "critical")))
        .extracting(Alert::ruleId)
        .doesNotContain("auth-special-privileges-non-admin");
    assertThat(engine.evaluate(enriched(admin, true, "low")))
        .extracting(Alert::ruleId)
        .doesNotContain("auth-special-privileges-non-admin");
  }
}
