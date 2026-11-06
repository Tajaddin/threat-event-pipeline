package io.github.tajaddin.threat.detect.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.tajaddin.threat.detect.AlertRepository;
import io.github.tajaddin.threat.detect.RuleService;
import io.github.tajaddin.threat.detect.rules.RuleLoader;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/**
 * The alert API on a real Tomcat with storage mocked: reads and the rule reload need the key,
 * whatever the path spelling; probes stay open.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = {
      "detect.api-keys=detect-key",
      "spring.flyway.enabled=false",
      "spring.kafka.listener.auto-startup=false"
    })
class DetectHttpTest {
  private static final HttpClient HTTP = HttpClient.newHttpClient();

  @LocalServerPort int port;
  @MockitoBean AlertRepository alerts;
  @MockitoBean RuleService rules;

  private HttpResponse<String> send(String method, String rawPath, String key)
      throws IOException, InterruptedException {
    HttpRequest.Builder b =
        HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + rawPath))
            .method(method, HttpRequest.BodyPublishers.noBody());
    if (key != null) {
      b.header("X-API-Key", key);
    }
    return HTTP.send(b.build(), HttpResponse.BodyHandlers.ofString());
  }

  @ParameterizedTest
  @ValueSource(strings = {"/api/alerts", "/api;x/alerts", "/%61pi/alerts", "//api/alerts"})
  void alertsNeedTheKeyWhateverThePathSpelling(String path) throws Exception {
    assertThat(send("GET", path, null).statusCode()).isIn(400, 401);
    verify(alerts, never()).list(any(), any(), any(), anyInt(), anyInt());
  }

  @ParameterizedTest
  @ValueSource(strings = {"/api/rules/reload", "/api;x/rules/reload", "/%61pi/rules/reload"})
  void ruleReloadNeedsTheKey(String path) throws Exception {
    assertThat(send("POST", path, null).statusCode()).isIn(400, 401);
    verify(rules, never()).reload();
  }

  @Test
  void validKeyReadsAlertsAndReloadsRules() throws Exception {
    when(alerts.list(any(), any(), any(), anyInt(), anyInt())).thenReturn(List.of());
    when(rules.reload()).thenReturn(new RuleLoader.Loaded(List.of(), List.of()));
    assertThat(send("GET", "/api/alerts", "detect-key").statusCode()).isEqualTo(200);
    assertThat(send("POST", "/api/rules/reload", "detect-key").statusCode()).isEqualTo(200);
    assertThat(send("GET", "/api/alerts", "wrong-key").statusCode()).isEqualTo(401);
  }

  @Test
  void probesStayOpenAndAnythingElseIsRefused() throws Exception {
    assertThat(send("GET", "/actuator/health/liveness", null).statusCode()).isEqualTo(200);
    assertThat(send("GET", "/internal", null).statusCode()).isEqualTo(401);
  }
}
