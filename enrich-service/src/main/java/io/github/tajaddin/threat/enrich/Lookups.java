package io.github.tajaddin.threat.enrich;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.time.Duration;
import java.util.Optional;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Component;

/**
 * Geo/network and asset context from Postgres, cached. The ip_ranges table uses the inet type and
 * the containment operator, so a lookup is one index-friendly query; the private ranges are flagged
 * internal.
 */
@Component
public class Lookups {
  public record IpInfo(String country, String asn, boolean internal) {
    static final IpInfo UNKNOWN = new IpInfo(null, null, false);
  }

  public record Asset(String owner, String criticality) {}

  private final JdbcClient jdbc;
  private final Cache<String, Optional<IpInfo>> ipCache =
      Caffeine.newBuilder().maximumSize(200_000).expireAfterWrite(Duration.ofMinutes(30)).build();
  private final Cache<String, Optional<Asset>> assetCache =
      Caffeine.newBuilder().maximumSize(50_000).expireAfterWrite(Duration.ofMinutes(30)).build();

  public Lookups(JdbcClient jdbc) {
    this.jdbc = jdbc;
  }

  public IpInfo ip(String ip) {
    if (ip == null || ip.isBlank()) {
      return IpInfo.UNKNOWN;
    }
    return ipCache
        .get(
            ip,
            k ->
                jdbc.sql(
                        "select country, asn, internal from ip_ranges where cidr >>= cast(:ip as inet) "
                            + "order by masklen(cidr) desc limit 1")
                    .param("ip", k)
                    .query(
                        (rs, i) ->
                            new IpInfo(
                                rs.getString("country"),
                                rs.getString("asn"),
                                rs.getBoolean("internal")))
                    .optional())
        .orElse(IpInfo.UNKNOWN);
  }

  public Optional<Asset> asset(String host) {
    if (host == null || host.isBlank()) {
      return Optional.empty();
    }
    return assetCache.get(
        host.toLowerCase(),
        k ->
            jdbc.sql("select owner, criticality from assets where lower(hostname) = :h")
                .param("h", k)
                .query((rs, i) -> new Asset(rs.getString("owner"), rs.getString("criticality")))
                .optional());
  }
}
