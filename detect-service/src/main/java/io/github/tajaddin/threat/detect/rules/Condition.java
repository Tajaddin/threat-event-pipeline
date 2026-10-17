package io.github.tajaddin.threat.detect.rules;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * Parser for Sigma condition expressions over named selections: identifiers, {@code and}, {@code
 * or}, {@code not}, parentheses, {@code 1 of sel*}, {@code all of sel*}, {@code 1 of them}, {@code
 * all of them}. Produces a predicate over the map of selection results.
 */
public final class Condition {
  private final List<String> tokens;
  private final List<String> selectionNames;
  private int pos;

  private Condition(String expression, List<String> selectionNames) {
    this.tokens = tokenize(expression);
    this.selectionNames = selectionNames;
  }

  public static Predicate<Map<String, Boolean>> parse(
      String expression, List<String> selectionNames) {
    Condition c = new Condition(expression, selectionNames);
    Predicate<Map<String, Boolean>> p = c.or();
    if (c.pos != c.tokens.size()) {
      throw new IllegalArgumentException(
          "unexpected token '" + c.tokens.get(c.pos) + "' in condition: " + expression);
    }
    return p;
  }

  private static List<String> tokenize(String expression) {
    List<String> out = new ArrayList<>();
    var m = Pattern.compile("\\(|\\)|[A-Za-z0-9_*]+").matcher(expression);
    while (m.find()) {
      out.add(m.group());
    }
    if (out.isEmpty()) {
      throw new IllegalArgumentException("empty condition");
    }
    return out;
  }

  private String peek() {
    return pos < tokens.size() ? tokens.get(pos) : null;
  }

  private String next() {
    return tokens.get(pos++);
  }

  private Predicate<Map<String, Boolean>> or() {
    Predicate<Map<String, Boolean>> left = and();
    while ("or".equalsIgnoreCase(peek())) {
      next();
      Predicate<Map<String, Boolean>> right = and();
      Predicate<Map<String, Boolean>> l = left;
      left = m -> l.test(m) || right.test(m);
    }
    return left;
  }

  private Predicate<Map<String, Boolean>> and() {
    Predicate<Map<String, Boolean>> left = not();
    while ("and".equalsIgnoreCase(peek())) {
      next();
      Predicate<Map<String, Boolean>> right = not();
      Predicate<Map<String, Boolean>> l = left;
      left = m -> l.test(m) && right.test(m);
    }
    return left;
  }

  private Predicate<Map<String, Boolean>> not() {
    if ("not".equalsIgnoreCase(peek())) {
      next();
      Predicate<Map<String, Boolean>> inner = not();
      return m -> !inner.test(m);
    }
    return atom();
  }

  private Predicate<Map<String, Boolean>> atom() {
    String t = peek();
    if (t == null) {
      throw new IllegalArgumentException("condition ended unexpectedly");
    }
    if (t.equals("(")) {
      next();
      Predicate<Map<String, Boolean>> inner = or();
      if (!")".equals(peek())) {
        throw new IllegalArgumentException("missing ')' in condition");
      }
      next();
      return inner;
    }
    if ((t.equals("1") || t.equalsIgnoreCase("all")) && "of".equalsIgnoreCase(tokenAt(pos + 1))) {
      boolean all = t.equalsIgnoreCase("all");
      next();
      next();
      String pattern = next();
      List<String> names = matching(pattern);
      if (names.isEmpty()) {
        throw new IllegalArgumentException("no selection matches '" + pattern + "'");
      }
      return all
          ? m -> names.stream().allMatch(n -> m.getOrDefault(n, false))
          : m -> names.stream().anyMatch(n -> m.getOrDefault(n, false));
    }
    next();
    if (!selectionNames.contains(t)) {
      throw new IllegalArgumentException("unknown selection '" + t + "' in condition");
    }
    return m -> m.getOrDefault(t, false);
  }

  private String tokenAt(int i) {
    return i < tokens.size() ? tokens.get(i) : null;
  }

  private List<String> matching(String pattern) {
    if (pattern.equalsIgnoreCase("them")) {
      return selectionNames;
    }
    String regex = pattern.replace("*", ".*");
    return selectionNames.stream().filter(n -> n.matches(regex)).toList();
  }
}
