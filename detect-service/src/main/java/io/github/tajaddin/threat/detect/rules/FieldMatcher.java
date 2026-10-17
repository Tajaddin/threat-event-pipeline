package io.github.tajaddin.threat.detect.rules;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * One field test from a selection: {@code field|modifier: value(s)}. Values in a list are OR-ed, as
 * in Sigma. String comparison is case-insensitive (Sigma's default); numeric modifiers parse the
 * event value as a number; {@code cidr} matches IPv4 addresses against a prefix.
 */
public final class FieldMatcher implements Predicate<Map<String, Object>> {
  private final String field;
  private final String modifier;
  private final List<Object> values;
  private final List<Pattern> patterns;

  public FieldMatcher(String spec, Object rawValue) {
    String[] parts = spec.split("\\|", 2);
    this.field = parts[0].trim();
    this.modifier = parts.length > 1 ? parts[1].trim().toLowerCase(Locale.ROOT) : "";
    this.values =
        rawValue instanceof List<?> list
            ? List.copyOf(list)
            : List.of(rawValue == null ? "null" : rawValue);
    this.patterns =
        modifier.equals("re")
            ? values.stream()
                .map(v -> Pattern.compile(String.valueOf(v), Pattern.CASE_INSENSITIVE))
                .toList()
            : List.of();
  }

  public String field() {
    return field;
  }

  @Override
  public boolean test(Map<String, Object> event) {
    Object actual = event.get(field);
    if (actual == null) {
      return values.stream().anyMatch(v -> "null".equals(String.valueOf(v)));
    }
    String s = String.valueOf(actual).toLowerCase(Locale.ROOT);
    switch (modifier) {
      case "":
        return values.stream().anyMatch(v -> equalsLoose(actual, s, v));
      case "contains":
        return values.stream().anyMatch(v -> s.contains(lower(v)));
      case "startswith":
        return values.stream().anyMatch(v -> s.startsWith(lower(v)));
      case "endswith":
        return values.stream().anyMatch(v -> s.endsWith(lower(v)));
      case "re":
        return patterns.stream().anyMatch(p -> p.matcher(String.valueOf(actual)).find());
      case "gt":
        return number(actual).map(n -> values.stream().anyMatch(v -> n > num(v))).orElse(false);
      case "gte":
        return number(actual).map(n -> values.stream().anyMatch(v -> n >= num(v))).orElse(false);
      case "lt":
        return number(actual).map(n -> values.stream().anyMatch(v -> n < num(v))).orElse(false);
      case "lte":
        return number(actual).map(n -> values.stream().anyMatch(v -> n <= num(v))).orElse(false);
      case "cidr":
        return values.stream()
            .anyMatch(v -> Cidr.contains(String.valueOf(v), String.valueOf(actual)));
      default:
        throw new IllegalArgumentException(
            "unsupported modifier '" + modifier + "' on field " + field);
    }
  }

  private static boolean equalsLoose(Object actual, String actualLower, Object expected) {
    if (expected instanceof Number || actual instanceof Number) {
      return number(actual).map(n -> n == num(expected)).orElse(false);
    }
    if (expected instanceof Boolean b) {
      return String.valueOf(actual).equalsIgnoreCase(b.toString());
    }
    return actualLower.equals(lower(expected));
  }

  private static String lower(Object v) {
    return String.valueOf(v).toLowerCase(Locale.ROOT);
  }

  private static java.util.Optional<Double> number(Object v) {
    if (v instanceof Number n) {
      return java.util.Optional.of(n.doubleValue());
    }
    try {
      return java.util.Optional.of(Double.parseDouble(String.valueOf(v)));
    } catch (NumberFormatException e) {
      return java.util.Optional.empty();
    }
  }

  private static double num(Object v) {
    return number(v)
        .orElseThrow(() -> new IllegalArgumentException("rule value is not numeric: " + v));
  }

  /** Minimal IPv4 CIDR test, enough for private-range and documentation-range rules. */
  static final class Cidr {
    static boolean contains(String cidr, String ip) {
      try {
        String[] parts = cidr.split("/");
        long base = toLong(parts[0]);
        int bits = parts.length > 1 ? Integer.parseInt(parts[1]) : 32;
        long mask = bits == 0 ? 0 : (0xFFFFFFFFL << (32 - bits)) & 0xFFFFFFFFL;
        return (toLong(ip) & mask) == (base & mask);
      } catch (RuntimeException e) {
        return false;
      }
    }

    private static long toLong(String ip) {
      String[] o = ip.trim().split("\\.");
      if (o.length != 4) {
        throw new IllegalArgumentException(ip);
      }
      long v = 0;
      for (String part : o) {
        v = (v << 8) | Integer.parseInt(part);
      }
      return v;
    }
  }
}
