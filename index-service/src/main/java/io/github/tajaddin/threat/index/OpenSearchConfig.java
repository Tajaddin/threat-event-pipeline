package io.github.tajaddin.threat.index;

import io.github.tajaddin.threat.common.Json;
import org.apache.hc.core5.http.HttpHost;
import org.opensearch.client.json.jackson.JacksonJsonpMapper;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.transport.httpclient5.ApacheHttpClient5TransportBuilder;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenSearchConfig {

  /**
   * @param url OpenSearch endpoint (http://opensearch:9200 in compose; security plugin disabled
   *     locally)
   * @param eventsIndexPrefix daily indices events-YYYY.MM.DD
   * @param alertsIndexPrefix daily indices alerts-YYYY.MM.DD
   * @param bulkMaxActions upper bound of documents per bulk request
   */
  @ConfigurationProperties(prefix = "index")
  public record IndexProperties(
      String url, String eventsIndexPrefix, String alertsIndexPrefix, int bulkMaxActions) {
    public IndexProperties {
      if (url == null || url.isBlank()) url = "http://localhost:9200";
      if (eventsIndexPrefix == null) eventsIndexPrefix = "events";
      if (alertsIndexPrefix == null) alertsIndexPrefix = "alerts";
      if (bulkMaxActions <= 0) bulkMaxActions = 1000;
    }
  }

  @Bean
  public OpenSearchClient openSearchClient(IndexProperties props) {
    HttpHost host;
    try {
      host = HttpHost.create(props.url());
    } catch (java.net.URISyntaxException e) {
      throw new IllegalArgumentException("index.url is not a valid URL: " + props.url(), e);
    }
    var transport =
        ApacheHttpClient5TransportBuilder.builder(host)
            .setMapper(new JacksonJsonpMapper(Json.MAPPER))
            .build();
    return new OpenSearchClient(transport);
  }
}
