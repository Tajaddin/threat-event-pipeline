package io.github.tajaddin.threat.detect.rules;

import io.github.tajaddin.threat.common.Alert;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/** A rule ready to run: compiled selections, parsed condition, optional threshold. */
public record CompiledRule(
    String id,
    String title,
    String description,
    Alert.Severity severity,
    List<String> tags,
    String product,
    String category,
    Map<String, List<FieldMatcher>> selections,
    Predicate<Map<String, Boolean>> condition,
    ThresholdSpec threshold,
    String yaml) {

  public record ThresholdSpec(int count, Duration window, List<String> groupBy, String distinct) {}

  public static CompiledRule compile(RuleDefinition def, String yaml) {
    if (def.id() == null || def.id().isBlank()) {
      throw new IllegalArgumentException("rule without id");
    }
    if (def.detection() == null
        || !(def.detection().get("condition") instanceof String conditionText)) {
      throw new IllegalArgumentException("rule " + def.id() + " needs detection.condition");
    }
    Map<String, List<FieldMatcher>> selections = new LinkedHashMap<>();
    for (var entry : def.detection().entrySet()) {
      if (entry.getKey().equals("condition")) {
        continue;
      }
      if (!(entry.getValue() instanceof Map<?, ?> fields)) {
        throw new IllegalArgumentException(
            "rule "
                + def.id()
                + ": selection "
                + entry.getKey()
                + " must be a map of field: value");
      }
      List<FieldMatcher> matchers = new ArrayList<>();
      fields.forEach((k, v) -> matchers.add(new FieldMatcher(String.valueOf(k), v)));
      selections.put(entry.getKey(), matchers);
    }
    if (selections.isEmpty()) {
      throw new IllegalArgumentException("rule " + def.id() + " has no selections");
    }
    Predicate<Map<String, Boolean>> condition =
        Condition.parse(conditionText, List.copyOf(selections.keySet()));
    ThresholdSpec threshold = null;
    if (def.threshold() != null) {
      var t = def.threshold();
      if (t.count() < 1 || t.window() == null || t.groupBy() == null || t.groupBy().isEmpty()) {
        throw new IllegalArgumentException(
            "rule " + def.id() + ": threshold needs count >= 1, window and groupBy");
      }
      threshold =
          new ThresholdSpec(
              t.count(), parseDuration(t.window()), List.copyOf(t.groupBy()), t.distinct());
    }
    return new CompiledRule(
        def.id(),
        def.title() == null ? def.id() : def.title(),
        def.description(),
        def.level() == null ? Alert.Severity.MEDIUM : def.level(),
        def.tags() == null ? List.of() : List.copyOf(def.tags()),
        def.logsource() == null ? null : def.logsource().product(),
        def.logsource() == null ? null : def.logsource().category(),
        selections,
        condition,
        threshold,
        yaml);
  }

  /** "60s", "5m", "1h" or an ISO-8601 duration. */
  static Duration parseDuration(String text) {
    String s = text.trim().toLowerCase();
    if (s.startsWith("pt") || s.startsWith("p")) {
      return Duration.parse(text);
    }
    char unit = s.charAt(s.length() - 1);
    long n = Long.parseLong(s.substring(0, s.length() - 1));
    return switch (unit) {
      case 's' -> Duration.ofSeconds(n);
      case 'm' -> Duration.ofMinutes(n);
      case 'h' -> Duration.ofHours(n);
      case 'd' -> Duration.ofDays(n);
      default -> throw new IllegalArgumentException("bad window: " + text);
    };
  }

  /** Does this rule apply to the event at all (logsource product/category)? */
  public boolean appliesTo(Map<String, Object> event) {
    if (category == null) {
      return true;
    }
    Object type = event.get("type");
    return type != null && category.equalsIgnoreCase(String.valueOf(type));
  }

  /** Evaluate selections and the condition against a flattened event. */
  public boolean matches(Map<String, Object> event) {
    Map<String, Boolean> results = new LinkedHashMap<>();
    selections.forEach(
        (name, matchers) -> results.put(name, matchers.stream().allMatch(m -> m.test(event))));
    return condition.test(results);
  }
}
