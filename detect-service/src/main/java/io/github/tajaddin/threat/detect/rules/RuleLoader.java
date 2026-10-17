package io.github.tajaddin.threat.detect.rules;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

/**
 * Reads rule YAML from the classpath {@code rules/} folder and an optional directory; compiles each
 * one.
 */
public final class RuleLoader {
  private static final Logger log = LoggerFactory.getLogger(RuleLoader.class);
  private static final ObjectMapper YAML = new ObjectMapper(new YAMLFactory());

  public record Loaded(List<CompiledRule> rules, List<String> errors) {}

  private RuleLoader() {}

  public static Loaded load(Path extraDir) {
    List<CompiledRule> rules = new ArrayList<>();
    List<String> errors = new ArrayList<>();
    try {
      Resource[] resources =
          new PathMatchingResourcePatternResolver().getResources("classpath*:rules/*.yml");
      for (Resource r : resources) {
        try (var in = r.getInputStream()) {
          add(
              new String(in.readAllBytes(), StandardCharsets.UTF_8),
              r.getFilename(),
              rules,
              errors);
        }
      }
      if (extraDir != null && Files.isDirectory(extraDir)) {
        try (Stream<Path> files = Files.list(extraDir)) {
          for (Path p :
              files
                  .filter(p -> p.toString().endsWith(".yml") || p.toString().endsWith(".yaml"))
                  .sorted()
                  .toList()) {
            add(Files.readString(p), p.getFileName().toString(), rules, errors);
          }
        }
      }
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
    log.info("loaded {} rules ({} errors)", rules.size(), errors.size());
    return new Loaded(List.copyOf(rules), List.copyOf(errors));
  }

  public static CompiledRule compile(String yaml) {
    try {
      RuleDefinition def = YAML.readValue(yaml, RuleDefinition.class);
      return CompiledRule.compile(def, yaml);
    } catch (IOException e) {
      throw new IllegalArgumentException("invalid YAML: " + e.getMessage(), e);
    }
  }

  private static void add(String yaml, String name, List<CompiledRule> rules, List<String> errors) {
    try {
      CompiledRule rule = compile(yaml);
      rules.removeIf(
          r ->
              r.id()
                  .equals(rule.id())); // a directory rule overrides a bundled one with the same id
      rules.add(rule);
    } catch (RuntimeException ex) {
      errors.add(name + ": " + ex.getMessage());
      log.warn("rule {} rejected: {}", name, ex.getMessage());
    }
  }
}
