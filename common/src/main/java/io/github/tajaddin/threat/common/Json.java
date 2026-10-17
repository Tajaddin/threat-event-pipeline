package io.github.tajaddin.threat.common;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.io.UncheckedIOException;

/** One ObjectMapper configuration for every service: ISO-8601 instants, unknown fields ignored. */
public final class Json {
  public static final ObjectMapper MAPPER =
      new ObjectMapper()
          .registerModule(new JavaTimeModule())
          .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
          .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

  private Json() {}

  public static String write(Object value) {
    try {
      return MAPPER.writeValueAsString(value);
    } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
      throw new UncheckedIOException(e);
    }
  }

  public static <T> T read(String json, Class<T> type) {
    try {
      return MAPPER.readValue(json, type);
    } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
      throw new IllegalArgumentException(
          "malformed " + type.getSimpleName() + " JSON: " + e.getOriginalMessage(), e);
    }
  }
}
