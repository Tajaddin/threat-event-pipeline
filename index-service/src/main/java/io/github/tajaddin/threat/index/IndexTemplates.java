package io.github.tajaddin.threat.index;

import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch._types.mapping.Property;
import org.opensearch.client.opensearch._types.mapping.TypeMapping;
import org.opensearch.client.opensearch.indices.IndexSettings;
import org.opensearch.client.opensearch.indices.PutIndexTemplateRequest;
import org.opensearch.client.opensearch.indices.put_index_template.IndexTemplateMapping;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Index templates so daily indices get the right field types (keywords for ids and IPs, dates,
 * longs).
 */
@Component
public class IndexTemplates {
  private static final Logger log = LoggerFactory.getLogger(IndexTemplates.class);
  private final OpenSearchClient client;
  private final OpenSearchConfig.IndexProperties props;

  public IndexTemplates(OpenSearchClient client, OpenSearchConfig.IndexProperties props) {
    this.client = client;
    this.props = props;
  }

  @PostConstruct
  public void ensure() {
    try {
      put(props.eventsIndexPrefix(), eventMapping());
      put(props.alertsIndexPrefix(), alertMapping());
    } catch (IOException | RuntimeException e) {
      // OpenSearch may still be starting; the listener retries until the cluster answers, this is
      // best effort
      log.warn("could not install index templates yet: {}", e.getMessage());
    }
  }

  private void put(String prefix, TypeMapping mapping) throws IOException {
    PutIndexTemplateRequest req =
        new PutIndexTemplateRequest.Builder()
            .name(prefix + "-template")
            .indexPatterns(List.of(prefix + "-*"))
            .template(
                new IndexTemplateMapping.Builder()
                    .settings(
                        new IndexSettings.Builder()
                            .numberOfShards(1)
                            .numberOfReplicas(0)
                            .refreshInterval(t -> t.time("5s"))
                            .build())
                    .mappings(mapping)
                    .build())
            .build();
    client.indices().putIndexTemplate(req);
    log.info("index template {} installed", prefix + "-template");
  }

  private static TypeMapping eventMapping() {
    Map<String, Property> event =
        Map.ofEntries(
            Map.entry("id", keyword()),
            Map.entry("timestamp", date()),
            Map.entry("type", keyword()),
            Map.entry("source", keyword()),
            Map.entry("host", keyword()),
            Map.entry("user", keyword()),
            Map.entry("srcIp", ip()),
            Map.entry("dstIp", ip()),
            Map.entry("dstPort", integer()),
            Map.entry("action", keyword()),
            Map.entry("eventCode", keyword()),
            Map.entry("logonType", integer()),
            Map.entry("bytesOut", longType()));
    return new TypeMapping.Builder()
        .properties("event", Property.of(p -> p.object(o -> o.properties(event))))
        .properties("srcCountry", keyword())
        .properties("srcAsn", keyword())
        .properties("srcInternal", bool())
        .properties("dstCountry", keyword())
        .properties("dstInternal", bool())
        .properties("assetOwner", keyword())
        .properties("assetCriticality", keyword())
        .properties("ingestedAt", date())
        .properties("enrichedAt", date())
        .build();
  }

  private static TypeMapping alertMapping() {
    return new TypeMapping.Builder()
        .properties("id", keyword())
        .properties("ruleId", keyword())
        .properties(
            "ruleTitle",
            Property.of(
                p ->
                    p.text(
                        t ->
                            t.fields(
                                "keyword", Property.of(f -> f.keyword(k -> k.ignoreAbove(256)))))))
        .properties("severity", keyword())
        .properties("key", keyword())
        .properties("eventIds", keyword())
        .properties("eventCount", integer())
        .properties("firstSeen", date())
        .properties("lastSeen", date())
        .properties("detectedAt", date())
        .properties("detectionLatencyMs", longType())
        .properties("summary", Property.of(p -> p.text(t -> t)))
        .build();
  }

  private static Property keyword() {
    return Property.of(p -> p.keyword(k -> k));
  }

  private static Property date() {
    return Property.of(p -> p.date(d -> d));
  }

  private static Property ip() {
    return Property.of(p -> p.ip(i -> i.ignoreMalformed(true)));
  }

  private static Property integer() {
    return Property.of(p -> p.integer(i -> i));
  }

  private static Property longType() {
    return Property.of(p -> p.long_(l -> l));
  }

  private static Property bool() {
    return Property.of(p -> p.boolean_(b -> b));
  }
}
