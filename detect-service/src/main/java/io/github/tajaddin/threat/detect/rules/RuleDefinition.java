package io.github.tajaddin.threat.detect.rules;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.github.tajaddin.threat.common.Alert;
import java.util.List;
import java.util.Map;

/**
 * A rule as written in YAML, following the Sigma rule shape: {@code logsource} narrows the event
 * type, {@code detection} holds named selections (field -> value or list, with Sigma modifiers such
 * as {@code |contains}) and a {@code condition} expression over them. {@code threshold} is this
 * project's extension for stateful rules: fire when {@code count} (or {@code distinct} values of a
 * field) within {@code window} for the same {@code groupBy} key reaches the threshold.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RuleDefinition(
    String id,
    String title,
    String description,
    String status,
    Alert.Severity level,
    List<String> tags,
    Logsource logsource,
    Map<String, Object> detection,
    Threshold threshold) {

  @JsonIgnoreProperties(ignoreUnknown = true)
  public record Logsource(String product, String category, String service) {}

  @JsonIgnoreProperties(ignoreUnknown = true)
  public record Threshold(int count, String window, List<String> groupBy, String distinct) {}
}
