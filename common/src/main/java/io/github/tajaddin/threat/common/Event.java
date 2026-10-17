package io.github.tajaddin.threat.common;

import com.fasterxml.jackson.annotation.JsonInclude;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.Map;

/**
 * A raw security event as the ingest API accepts it. Two shapes share one record: authentication
 * events (Windows-style event codes, user, host, logon type) and firewall events (action, ports,
 * bytes). Fields that do not apply are null; {@code attributes} carries anything else the source
 * sent.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record Event(
    @NotBlank @Size(max = 64) @Pattern(regexp = "[A-Za-z0-9_.:-]+") String id,
    @NotNull Instant timestamp,
    @NotNull EventType type,
    @NotBlank @Size(max = 128) String source,
    @Size(max = 128) String host,
    @Size(max = 128) String user,
    @Size(max = 45) String srcIp,
    @Size(max = 45) String dstIp,
    @Min(0) @Max(65535) Integer dstPort,
    @Size(max = 32) String action,
    @Size(max = 16) String eventCode,
    @Min(0) @Max(99) Integer logonType,
    @Min(0) Long bytesOut,
    @Size(max = 32) Map<@Size(max = 64) String, @Size(max = 512) String> attributes) {

  public enum EventType {
    AUTH,
    FIREWALL
  }
}
