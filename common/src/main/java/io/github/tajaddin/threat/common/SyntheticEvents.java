package io.github.tajaddin.threat.common;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.UUID;

/**
 * Deterministic synthetic traffic: mostly normal authentication and firewall events, with a
 * configurable share of attack scenarios that the shipped rules detect. Used by the ingest
 * generator, the load runner and the tests. Nothing here is real: hosts, users and addresses are
 * invented.
 */
public final class SyntheticEvents {

  public enum Scenario {
    NORMAL,
    BRUTE_FORCE,
    PASSWORD_SPRAY,
    LATERAL_MOVEMENT,
    PORT_SCAN,
    EXFILTRATION,
    PRIVILEGE_USE
  }

  private static final String[] USERS = {
    "a.khan", "b.lopez", "c.nguyen", "d.smith", "e.garcia", "f.okafor", "g.ivanova", "h.tanaka",
        "i.rossi",
    "j.muller", "k.brown", "l.chen", "m.patel", "n.silva", "o.dubois", "p.kowalski", "svc-backup",
        "svc-sql"
  };
  private static final String[] HOSTS = {
    "ws-0101",
    "ws-0102",
    "ws-0103",
    "ws-0104",
    "ws-0105",
    "ws-0201",
    "ws-0202",
    "ws-0203",
    "srv-file-01",
    "srv-sql-01",
    "srv-dc-01",
    "srv-web-01",
    "srv-vpn-01",
    "srv-jump-01",
    "lt-exec-01",
    "lt-exec-02"
  };
  private static final String[] EXTERNAL_PREFIXES = {
    "203.0.113.", "198.51.100.", "192.0.2.", "185.220.101.", "45.155.205."
  };
  private static final int[] COMMON_PORTS = {443, 80, 53, 22, 3389, 445, 25, 587, 993, 8080};

  private final Random random;
  private final double attackShare;
  private final String source;

  public SyntheticEvents(long seed, double attackShare, String source) {
    this.random = new Random(seed);
    this.attackShare = attackShare;
    this.source = source;
  }

  /** Next batch at {@code now}: a scenario burst when the dice say so, otherwise normal events. */
  public List<Event> batch(Instant now, int size) {
    List<Event> out = new ArrayList<>(size);
    while (out.size() < size) {
      if (random.nextDouble() < attackShare) {
        out.addAll(scenario(pick(Scenario.values(), 1), now));
      } else {
        out.add(normal(now));
      }
    }
    return out.size() > size ? new ArrayList<>(out.subList(0, size)) : out;
  }

  public List<Event> scenario(Scenario scenario, Instant now) {
    List<Event> out = new ArrayList<>();
    switch (scenario) {
      case BRUTE_FORCE -> {
        String ip = externalIp();
        String user = pick(USERS, 0);
        String host = pick(HOSTS, 0);
        for (int i = 0; i < 12; i++) {
          out.add(
              auth(
                  now.plusMillis(i * 150L),
                  host,
                  user,
                  ip,
                  "4625",
                  3,
                  Map.of("status", "0xC000006A", "scenario", "brute_force")));
        }
      }
      case PASSWORD_SPRAY -> {
        String ip = externalIp();
        String host = "srv-vpn-01";
        for (int i = 0; i < 18; i++) {
          out.add(
              auth(
                  now.plusMillis(i * 400L),
                  host,
                  USERS[i % USERS.length],
                  ip,
                  "4625",
                  3,
                  Map.of("status", "0xC000006A", "scenario", "password_spray")));
        }
      }
      case LATERAL_MOVEMENT -> {
        String srcHost = pick(HOSTS, 0);
        String user = pick(USERS, 0);
        String ip = internalIp();
        for (int i = 0; i < 7; i++) {
          String target = HOSTS[(i * 3 + 1) % HOSTS.length];
          out.add(
              auth(
                  now.plusMillis(i * 900L),
                  target,
                  user,
                  ip,
                  "4648",
                  3,
                  Map.of(
                      "target_host",
                      target,
                      "from_host",
                      srcHost,
                      "scenario",
                      "lateral_movement")));
        }
      }
      case PORT_SCAN -> {
        String ip = externalIp();
        String dst = internalIp();
        for (int port = 1; port <= 60; port++) {
          out.add(
              firewall(
                  now.plusMillis(port * 20L),
                  ip,
                  dst,
                  port,
                  "deny",
                  0L,
                  Map.of("scenario", "port_scan")));
        }
      }
      case EXFILTRATION -> {
        String src = internalIp();
        String dst = externalIp();
        out.add(
            firewall(
                now,
                src,
                dst,
                443,
                "allow",
                120_000_000L + random.nextInt(50_000_000),
                Map.of("scenario", "exfiltration")));
      }
      case PRIVILEGE_USE -> {
        String user = pick(USERS, 0);
        out.add(
            auth(
                now,
                "srv-dc-01",
                user,
                internalIp(),
                "4672",
                2,
                Map.of("privileges", "SeDebugPrivilege", "scenario", "privilege_use")));
      }
      case NORMAL -> out.add(normal(now));
    }
    return out;
  }

  private Event normal(Instant now) {
    if (random.nextInt(10) < 6) {
      String host = pick(HOSTS, 0);
      String user = pick(USERS, 0);
      boolean failure = random.nextInt(40) == 0;
      return auth(
          now,
          host,
          user,
          internalIp(),
          failure ? "4625" : "4624",
          random.nextBoolean() ? 2 : 10,
          Map.of());
    }
    String dst = random.nextInt(4) == 0 ? externalIp() : internalIp();
    return firewall(
        now,
        internalIp(),
        dst,
        COMMON_PORTS[random.nextInt(COMMON_PORTS.length)],
        random.nextInt(20) == 0 ? "deny" : "allow",
        (long) random.nextInt(2_000_000),
        Map.of());
  }

  private Event auth(
      Instant ts,
      String host,
      String user,
      String srcIp,
      String code,
      int logonType,
      Map<String, String> attrs) {
    return new Event(
        newId(),
        ts,
        Event.EventType.AUTH,
        source,
        host,
        user,
        srcIp,
        null,
        null,
        code.equals("4625") ? "failure" : "success",
        code,
        logonType,
        null,
        attrs.isEmpty() ? null : attrs);
  }

  private Event firewall(
      Instant ts,
      String srcIp,
      String dstIp,
      int port,
      String action,
      long bytes,
      Map<String, String> attrs) {
    return new Event(
        newId(),
        ts,
        Event.EventType.FIREWALL,
        source,
        "fw-edge-01",
        null,
        srcIp,
        dstIp,
        port,
        action,
        null,
        null,
        bytes,
        attrs.isEmpty() ? null : attrs);
  }

  private String newId() {
    return new UUID(random.nextLong(), random.nextLong()).toString();
  }

  private <T> T pick(T[] values, int from) {
    return values[from + random.nextInt(values.length - from)];
  }

  public String internalIp() {
    return "10." + random.nextInt(4) + "." + random.nextInt(32) + "." + (1 + random.nextInt(250));
  }

  public String externalIp() {
    return EXTERNAL_PREFIXES[random.nextInt(EXTERNAL_PREFIXES.length)] + (1 + random.nextInt(250));
  }
}
