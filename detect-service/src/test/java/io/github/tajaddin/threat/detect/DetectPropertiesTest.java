package io.github.tajaddin.threat.detect;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.BindException;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

/** Binds the properties the way Spring Boot does at start-up, comma-separated lists included. */
class DetectPropertiesTest {

  private static DetectProperties bind(Map<String, String> source) {
    return new Binder(new MapConfigurationPropertySource(source))
        .bindOrCreate("detect", DetectProperties.class);
  }

  @Test
  void blankEntriesInTheKeyListAreNotKeys() {
    assertThat(bind(Map.of("detect.api-keys", "k1, ,")).apiKeys()).containsExactly("k1");
  }

  @Test
  void requiredKeysStopStartUpWhenNoneIsSet() {
    for (String keys : List.of("", " , ")) {
      assertThatThrownBy(
              () -> bind(Map.of("detect.require-api-keys", "true", "detect.api-keys", keys)))
          .isInstanceOf(BindException.class)
          .hasRootCauseMessage("detect.require-api-keys is set but detect.api-keys holds no key");
    }
    assertThat(bind(Map.of("detect.require-api-keys", "true", "detect.api-keys", "k1")).apiKeys())
        .containsExactly("k1");
  }

  @Test
  void keysAreOptionalUnlessRequired() {
    assertThat(bind(Map.of()).apiKeys()).isEmpty();
  }
}
