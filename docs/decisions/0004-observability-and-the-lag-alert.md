# 0004. Micrometer counters per stage, kafka-exporter for lag, and alerts that are unit tested

Date: 2026-10-17. Status: accepted.

## Context

A pipeline that is "up" can still be silently behind. The signals that matter are per-stage throughput,
consumer lag, detection latency, dead-letter rate and ingest rejections, and each needs an alert that is
known to fire.

## Decision

- Every service exposes `/actuator/prometheus` through Micrometer with a `service` tag; the stages count
  outcomes (`ingest_events_total{outcome}`, `enrich_events_total{outcome}`,
  `detect_events_total{outcome}`, `index_documents_total{kind}`, `index_failures_total`) and time what
  matters (`ingest_produce`, `enrich_latency`, `detect_latency` as ingest-to-alert, `index_bulk`), all as
  histograms so p95 is queryable.
- Consumer lag comes from `kafka-exporter` (`kafka_consumergroup_lag` per group, topic, partition) rather
  than from each client's own metrics, so a stalled or crashed consumer still shows lag.
- Seven Prometheus rules (`observability/alert_rules.yml`): lag above 50,000 for two minutes, a group with
  lag whose offsets stop moving, dead-letter rate, ingest rejection share, detection latency p95, index
  failures, service down. `alerts_test.yml` holds promtool unit tests with synthetic series proving each
  fires at the intended level and stays quiet below it; CI runs them.
- Logs are JSON lines (Logstash encoder) with the service name; the Grafana dashboard
  (`threat-pipeline.json`) is provisioned by compose with throughput by stage, lag by group, detection
  latency percentiles, alerts by rule, DLQ and rejection panels.

## Consequences

- The load runner reads the same Prometheus the alerts read, so the README's numbers and the alert
  thresholds are on one scale.
- The lag threshold (50,000) suits the laptop; in Kubernetes it should be a function of the expected
  rate, which the Helm values do not yet parameterise.
- Traces are not shipped (no OpenTelemetry exporter wired); Micrometer Tracing would be the next step and
  the JSON logs already carry `traceId`/`spanId` fields when it is.
