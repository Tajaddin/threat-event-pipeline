# 0003. Delivery guarantees per stage: transactional enrich, idempotent detect and index, DLQ for poison

Date: 2026-10-17. Status: accepted.

## Context

"Exactly once" is a property of a stage and its sink, not of a pipeline. Each stage here has a different
sink, so each gets the guarantee its sink can honour.

## Decision

- **ingest**: idempotent producer (`enable.idempotence`, `acks=all`), duplicate event ids suppressed for
  ten minutes in memory, 503 with `Retry-After` when the producer's buffer or the broker cannot keep up,
  429 from the per-key token bucket.
- **enrich**: consume-transform-produce in one Kafka transaction per poll (`transaction-id-prefix`,
  batch listener, up to `max.poll.records` = 500 records, `isolation.level=read_committed` downstream). The
  enriched records, the DLQ records for malformed input and the consumed offsets commit or abort together,
  so a crash never leaves a duplicate output visible to `read_committed` consumers. An unexpected failure
  (database down) rolls back with the index of the failing record (`BatchListenerFailedException`): the
  records before it are committed, it is retried three times a second apart, and after that
  `DefaultAfterRollbackProcessor` publishes it to `events.dlq` with the exception in headers and commits its
  offset, so a poison record cannot stall a partition.
- **detect**: at-least-once with manual acknowledgement after the alert is stored and produced; alert ids
  are deterministic and the store upserts, so redelivery is harmless (tested by producing the same burst
  twice).
- **index**: batch consumer, one bulk request per poll, documents keyed by their ids so a redelivered
  batch overwrites rather than duplicates; a failed bulk throws, the batch is redelivered with exponential
  back-off, nothing is dropped.

## Consequences

- The integration tests assert the properties: `EnrichIT` sends 31 good and 2 bad records and expects
  exactly 31 enriched and 2 dead-lettered; `DetectIT` sends a burst twice and expects one alert; `IndexIT`
  sends everything twice and counts documents.
- The first version committed a transaction per record (`ack-mode: record`). The first load run measured
  about 65 events per second on the enrich stage, with `sendOffsetsToTransaction` and the commit taking
  about 15 ms per record, and all traffic on one partition because ingest keyed records by feed name. The
  transaction now spans the poll and ingest keys by source address (then host, then feed), which is also
  the field most threshold rules group by. The load run in the README is from the second version.
- The ingest de-duplication window is in-memory and per instance; two ingest replicas could each accept
  the same id. The enrich transaction does not de-duplicate either. For strict end-to-end de-duplication a
  shared key store (Redis) in ingest would be the next step.
