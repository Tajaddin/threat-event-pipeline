package io.github.tajaddin.threat.ingest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.tajaddin.threat.common.Event;
import io.github.tajaddin.threat.common.Json;
import io.github.tajaddin.threat.common.SyntheticEvents;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.errors.TimeoutException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.kafka.KafkaException;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/**
 * The HTTP surface on a real Tomcat with the producer mocked: which paths need the key, and what a
 * caller sees. Requests go out with the raw path as written, so path parameters and
 * percent-encoding reach the server the way an attacker would send them.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = {"ingest.api-keys=test-key,", "spring.kafka.bootstrap-servers=127.0.0.1:1"})
@AutoConfigureObservability
class IngestHttpTest {
  private static final HttpClient HTTP = HttpClient.newHttpClient();

  @LocalServerPort int port;
  @MockitoBean KafkaTemplate<String, String> kafka;

  @AfterEach
  void resetMock() {
    reset(kafka);
  }

  private HttpResponse<String> send(String method, String rawPath, String body, String key)
      throws IOException, InterruptedException {
    HttpRequest.Builder b =
        HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + rawPath))
            .header("Content-Type", "application/json")
            .method(
                method,
                body == null
                    ? HttpRequest.BodyPublishers.noBody()
                    : HttpRequest.BodyPublishers.ofString(body));
    if (key != null) {
      b.header("X-API-Key", key);
    }
    return HTTP.send(b.build(), HttpResponse.BodyHandlers.ofString());
  }

  private static String oneEvent(long seed) {
    List<Event> events = new SyntheticEvents(seed, 0, "http-test").batch(Instant.now(), 1);
    return Json.write(events);
  }

  @SuppressWarnings("unchecked")
  private void kafkaAccepts() {
    when(kafka.send(any(ProducerRecord.class)))
        .thenReturn(CompletableFuture.completedFuture(mock(SendResult.class)));
  }

  @ParameterizedTest
  @ValueSource(strings = {"/api/events", "/api;x/events", "/%61pi/events", "//api/events"})
  @SuppressWarnings("unchecked")
  void eventsNeedTheKeyWhateverThePathSpelling(String path) throws Exception {
    kafkaAccepts();
    HttpResponse<String> resp = send("POST", path, oneEvent(1), null);
    assertThat(resp.statusCode()).isIn(400, 401);
    verify(kafka, never()).send(any(ProducerRecord.class));
  }

  @ParameterizedTest
  @ValueSource(strings = {"/api/generate", "/api;x/generate", "/%61pi/generate"})
  void generatorNeedsTheKeyWhateverThePathSpelling(String path) throws Exception {
    assertThat(send("GET", path, null, null).statusCode()).isIn(400, 401);
  }

  @Test
  void wrongKeyIsRejected() throws Exception {
    assertThat(send("POST", "/api/events", oneEvent(2), "not-the-key").statusCode()).isEqualTo(401);
  }

  @Test
  @SuppressWarnings("unchecked")
  void emptyKeyIsRejectedThoughTheKeyListEndsInAComma() throws Exception {
    kafkaAccepts();
    assertThat(send("POST", "/api/events", oneEvent(5), "").statusCode()).isEqualTo(401);
    verify(kafka, never()).send(any(ProducerRecord.class));
  }

  @Test
  @SuppressWarnings("unchecked")
  void validKeyIsAccepted() throws Exception {
    kafkaAccepts();
    HttpResponse<String> resp = send("POST", "/api/events", oneEvent(3), "test-key");
    assertThat(resp.statusCode()).isEqualTo(202);
    assertThat(resp.body()).contains("\"accepted\":1");
    verify(kafka).send(any(ProducerRecord.class));
  }

  @Test
  void probesMetricsAndDocsStayOpen() throws Exception {
    assertThat(send("GET", "/actuator/health/liveness", null, null).statusCode()).isEqualTo(200);
    assertThat(send("GET", "/actuator/prometheus", null, null).statusCode()).isEqualTo(200);
    assertThat(send("GET", "/v3/api-docs", null, null).statusCode()).isEqualTo(200);
  }

  @Test
  void addressThatIsNotAnIpIsRejectedBeforeKafka() throws Exception {
    kafkaAccepts();
    String body =
        "[{\"id\":\"bad-ip-1\",\"timestamp\":\"2026-11-01T00:00:00Z\",\"type\":\"AUTH\","
            + "\"source\":\"s\",\"srcIp\":\"x\"}]";
    HttpResponse<String> resp = send("POST", "/api/events", body, "test-key");
    assertThat(resp.statusCode()).isEqualTo(400);
    assertThat(resp.body()).contains("srcIp");
    verify(kafka, never()).send(any(ProducerRecord.class));
  }

  @Test
  void anythingElseIsRefused() throws Exception {
    assertThat(send("GET", "/internal", null, null).statusCode()).isEqualTo(401);
  }

  @Test
  @SuppressWarnings("unchecked")
  void brokerTimeoutAnswers503AndTheRetryIsAccepted() throws Exception {
    // what KafkaTemplate throws when the topic's metadata does not arrive within max.block.ms
    when(kafka.send(any(ProducerRecord.class)))
        .thenThrow(
            new KafkaException(
                "Send failed",
                new TimeoutException("Topic events.raw not present in metadata after 5000 ms.")))
        .thenReturn(CompletableFuture.completedFuture(mock(SendResult.class)));
    String body = oneEvent(4);

    HttpResponse<String> first = send("POST", "/api/events", body, "test-key");
    assertThat(first.statusCode()).isEqualTo(503);
    assertThat(first.headers().firstValue("Retry-After")).hasValue("2");

    HttpResponse<String> retry = send("POST", "/api/events", body, "test-key");
    assertThat(retry.statusCode()).isEqualTo(202);
    assertThat(retry.body()).contains("\"accepted\":1").contains("\"duplicates\":0");
    verify(kafka, times(2)).send(any(ProducerRecord.class));
  }
}
