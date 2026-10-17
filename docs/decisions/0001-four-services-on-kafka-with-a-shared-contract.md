# 0001. Four small services on Kafka topics, one shared contract module, no shared database writes

Date: 2026-10-17. Status: accepted.

## Context

The mission asks for three or more services with idempotent processing and a dead-letter topic. A single
Spring Boot application with internal queues would be simpler and faster on one machine; it would also show
none of what a detection pipeline has to get right: back-pressure between stages, independent scaling,
replay, and a stage failing without taking the others down.

## Decision

Four Spring Boot 3.5 / Java 21 services connected only by Kafka topics:

| Stage | In | Out | Scales by |
|---|---|---|---|
| ingest-service | HTTP | `events.raw` | HTTP replicas; producer batching |
| enrich-service | `events.raw` | `events.enriched`, `events.dlq` | partitions (6) x consumer concurrency |
| detect-service | `events.enriched` | `alerts`, Postgres | partitions; window state is per instance and keyed |
| index-service | `events.enriched`, `alerts` | OpenSearch | batch size per poll |

`common` holds the records (`Event`, `EnrichedEvent`, `Alert`), topic names, the Jackson configuration and
the synthetic generator, so every service serialises the same way and the generator and the tests share
one definition of traffic. Records are keyed by source (ingest) so a source's events stay ordered through
the pipeline, which the threshold rules rely on.

Postgres is written by exactly one service per table: enrich reads lookup tables, detect owns rules and
alerts. OpenSearch is written only by index-service.

## Consequences

- Each stage has its own failure semantics (ADR 0003) and can be replayed from Kafka without touching the
  others; the DLQ is a topic, so poison records are inspectable and re-drivable.
- Detection windows are partition-local: the brute-force key `(src_ip, user)` always lands on one
  partition because records are keyed by source, but a key that spans sources would be split across
  instances. The README states this; a Kafka Streams state store or a re-key step would remove it.
- Four JVMs cost about 1.2 GB of RAM at rest on the laptop, which is the price of the separation.
