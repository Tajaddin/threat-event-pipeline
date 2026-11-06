package io.github.tajaddin.threat.index;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.tajaddin.threat.common.EnrichedEvent;
import io.github.tajaddin.threat.common.Event;
import io.github.tajaddin.threat.common.Json;
import io.github.tajaddin.threat.common.SyntheticEvents;
import io.github.tajaddin.threat.common.Topics;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.core.BulkRequest;
import org.opensearch.client.opensearch.core.BulkResponse;
import org.opensearch.client.opensearch.core.bulk.BulkResponseItem;
import org.opensearch.client.opensearch.core.bulk.OperationType;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.kafka.support.SendResult;

class IndexListenerTest {
  private final OpenSearchClient client = mock(OpenSearchClient.class);

  @SuppressWarnings("unchecked")
  private final KafkaTemplate<String, String> kafka = mock(KafkaTemplate.class);

  private IndexListener listener;
  private List<ConsumerRecord<String, String>> records;

  @BeforeEach
  @SuppressWarnings("unchecked")
  void setUp() {
    when(kafka.send(any(ProducerRecord.class)))
        .thenReturn(CompletableFuture.completedFuture(mock(SendResult.class)));
    listener =
        new IndexListener(
            client,
            new OpenSearchConfig.IndexProperties(null, null, null, 0),
            kafka,
            new SimpleMeterRegistry());
    records = new ArrayList<>();
    List<Event> events =
        new SyntheticEvents(5, 0, "t").batch(Instant.parse("2026-10-17T12:00:00Z"), 3);
    for (int i = 0; i < events.size(); i++) {
      EnrichedEvent e =
          new EnrichedEvent(events.get(i), "US", "AS0", true, null, false, null, null, null, null);
      records.add(new ConsumerRecord<>(Topics.ENRICHED, 0, i, "k", Json.write(e)));
    }
  }

  private void bulkAnswers(int... statuses) throws IOException {
    List<BulkResponseItem> items = new ArrayList<>();
    for (int status : statuses) {
      items.add(
          BulkResponseItem.of(
              i -> {
                i.operationType(OperationType.Index).index("events-2026.10.17").status(status);
                if (status >= 300) {
                  i.error(e -> e.type("error_" + status).reason("refused with " + status));
                }
                return i;
              }));
    }
    boolean errors = items.stream().anyMatch(i -> i.error() != null);
    when(client.bulk(any(BulkRequest.class)))
        .thenReturn(BulkResponse.of(b -> b.errors(errors).took(1).items(items)));
  }

  @Test
  @SuppressWarnings("unchecked")
  void documentRefusedFor400IsDeadLetteredAndTheBatchIsAcknowledged() throws Exception {
    bulkAnswers(201, 400, 201);
    Acknowledgment ack = mock(Acknowledgment.class);

    listener.onEvents(records, ack);

    ArgumentCaptor<ProducerRecord<String, String>> sent =
        ArgumentCaptor.forClass(ProducerRecord.class);
    verify(kafka).send(sent.capture());
    ProducerRecord<String, String> dead = sent.getValue();
    assertThat(dead.topic()).isEqualTo(Topics.DLQ);
    assertThat(dead.value()).isEqualTo(records.get(1).value());
    assertThat(header(dead, Topics.HEADER_ERROR_STAGE)).isEqualTo("index");
    assertThat(header(dead, Topics.HEADER_ERROR)).contains("400").contains("error_400");
    verify(ack).acknowledge();
  }

  @Test
  @SuppressWarnings("unchecked")
  void throttledDocumentFailsTheBatchAndNothingIsDeadLettered() throws Exception {
    bulkAnswers(201, 429, 400);
    Acknowledgment ack = mock(Acknowledgment.class);

    assertThatThrownBy(() -> listener.onEvents(records, ack)).isInstanceOf(IOException.class);

    verify(kafka, never()).send(any(ProducerRecord.class));
    verify(ack, never()).acknowledge();
  }

  @Test
  void serverErrorAlsoFailsTheBatch() throws Exception {
    bulkAnswers(503, 201, 201);
    Acknowledgment ack = mock(Acknowledgment.class);

    assertThatThrownBy(() -> listener.onEvents(records, ack)).isInstanceOf(IOException.class);
    verify(ack, never()).acknowledge();
  }

  private static String header(ProducerRecord<?, ?> record, String name) {
    return new String(record.headers().lastHeader(name).value(), StandardCharsets.UTF_8);
  }
}
