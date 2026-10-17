package io.github.tajaddin.threat.common;

/**
 * Topic names. Partitions and retention are set by the kafka-init job in compose and by the Helm
 * chart.
 */
public final class Topics {
  public static final String RAW = "events.raw";
  public static final String ENRICHED = "events.enriched";
  public static final String DLQ = "events.dlq";
  public static final String ALERTS = "alerts";

  public static final String HEADER_INGESTED_AT = "ingested-at";
  public static final String HEADER_ERROR = "error";
  public static final String HEADER_ERROR_STAGE = "error-stage";

  private Topics() {}
}
