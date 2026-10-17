package io.github.tajaddin.threat.common;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * An event after enrichment: the raw event plus geo, network and asset context, and pipeline
 * timestamps.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record EnrichedEvent(
    Event event,
    String srcCountry,
    String srcAsn,
    boolean srcInternal,
    String dstCountry,
    boolean dstInternal,
    String assetOwner,
    String assetCriticality,
    Instant ingestedAt,
    Instant enrichedAt) {

  /** Flat view used by rule matching: event fields plus enrichment under stable names. */
  public Map<String, Object> flatten() {
    Map<String, Object> m = new LinkedHashMap<>();
    Event e = event;
    m.put("id", e.id());
    m.put("timestamp", e.timestamp());
    m.put("type", e.type().name());
    m.put("source", e.source());
    m.put("host", e.host());
    m.put("user", e.user());
    m.put("src_ip", e.srcIp());
    m.put("dst_ip", e.dstIp());
    m.put("dst_port", e.dstPort());
    m.put("action", e.action());
    m.put("event_code", e.eventCode());
    m.put("logon_type", e.logonType());
    m.put("bytes_out", e.bytesOut());
    if (e.attributes() != null) {
      e.attributes().forEach((k, v) -> m.put("attr." + k, v));
    }
    m.put("src_country", srcCountry);
    m.put("src_asn", srcAsn);
    m.put("src_internal", srcInternal);
    m.put("dst_country", dstCountry);
    m.put("dst_internal", dstInternal);
    m.put("asset_owner", assetOwner);
    m.put("asset_criticality", assetCriticality);
    return m;
  }
}
