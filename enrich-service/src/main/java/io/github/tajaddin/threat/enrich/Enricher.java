package io.github.tajaddin.threat.enrich;

import io.github.tajaddin.threat.common.EnrichedEvent;
import io.github.tajaddin.threat.common.Event;
import java.time.Instant;
import org.springframework.stereotype.Component;

/** Pure enrichment of one event; the Kafka listener owns transactions and error routing. */
@Component
public class Enricher {
  private final Lookups lookups;

  public Enricher(Lookups lookups) {
    this.lookups = lookups;
  }

  public EnrichedEvent enrich(Event event, Instant ingestedAt) {
    Lookups.IpInfo src = lookups.ip(event.srcIp());
    Lookups.IpInfo dst = lookups.ip(event.dstIp());
    var asset = lookups.asset(event.host());
    return new EnrichedEvent(
        event,
        src.country(),
        src.asn(),
        src.internal(),
        dst.country(),
        dst.internal(),
        asset.map(Lookups.Asset::owner).orElse(null),
        asset.map(Lookups.Asset::criticality).orElse(null),
        ingestedAt,
        Instant.now());
  }
}
