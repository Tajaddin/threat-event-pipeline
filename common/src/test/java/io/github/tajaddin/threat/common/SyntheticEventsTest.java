package io.github.tajaddin.threat.common;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class SyntheticEventsTest {

  @Test
  void sameSeedSameBatch() {
    Instant now = Instant.parse("2026-10-17T12:00:00Z");
    List<Event> a = new SyntheticEvents(7, 0.1, "t").batch(now, 200);
    List<Event> b = new SyntheticEvents(7, 0.1, "t").batch(now, 200);
    assertThat(a).hasSize(200);
    assertThat(a.stream().map(Event::id).toList()).isEqualTo(b.stream().map(Event::id).toList());
    assertThat(a.stream().map(Event::id).distinct().count()).isEqualTo(200);
  }

  @Test
  void scenariosProduceWhatTheRulesLookFor() {
    SyntheticEvents s = new SyntheticEvents(1, 0, "t");
    Instant now = Instant.now();
    List<Event> brute = s.scenario(SyntheticEvents.Scenario.BRUTE_FORCE, now);
    assertThat(brute).hasSize(12).allMatch(e -> "4625".equals(e.eventCode()));
    assertThat(brute.stream().map(Event::srcIp).distinct()).hasSize(1);
    assertThat(brute.stream().map(Event::user).distinct()).hasSize(1);

    List<Event> spray = s.scenario(SyntheticEvents.Scenario.PASSWORD_SPRAY, now);
    assertThat(spray.stream().map(Event::user).distinct().count()).isGreaterThanOrEqualTo(15);

    List<Event> scan = s.scenario(SyntheticEvents.Scenario.PORT_SCAN, now);
    assertThat(scan)
        .hasSize(60)
        .allMatch(e -> e.type() == Event.EventType.FIREWALL && "deny".equals(e.action()));
    assertThat(scan.stream().map(Event::dstPort).distinct()).hasSize(60);

    Event exfil = s.scenario(SyntheticEvents.Scenario.EXFILTRATION, now).get(0);
    assertThat(exfil.bytesOut()).isGreaterThan(100_000_000L);
    assertThat(exfil.srcIp()).startsWith("10.");
  }

  @Test
  void jsonRoundTripKeepsInstantsAndNulls() {
    Event e = new SyntheticEvents(3, 0, "t").batch(Instant.parse("2026-10-17T12:00:00Z"), 1).get(0);
    String json = Json.write(e);
    assertThat(json).contains("\"timestamp\":\"2026-10-17T12:00:00Z\"").doesNotContain("null");
    assertThat(Json.read(json, Event.class)).isEqualTo(e);
  }

  @Test
  void flattenExposesRuleFields() {
    Event e =
        new Event(
            "1",
            Instant.EPOCH,
            Event.EventType.AUTH,
            "s",
            "srv-dc-01",
            "a.khan",
            "10.0.0.5",
            null,
            null,
            "failure",
            "4625",
            3,
            null,
            java.util.Map.of("k", "v"));
    EnrichedEvent enriched =
        new EnrichedEvent(
            e,
            "US",
            "AS0",
            true,
            null,
            false,
            "infrastructure",
            "critical",
            Instant.EPOCH,
            Instant.EPOCH);
    var flat = enriched.flatten();
    assertThat(flat)
        .containsEntry("event_code", "4625")
        .containsEntry("src_internal", true)
        .containsEntry("asset_criticality", "critical")
        .containsEntry("attr.k", "v");
  }
}
