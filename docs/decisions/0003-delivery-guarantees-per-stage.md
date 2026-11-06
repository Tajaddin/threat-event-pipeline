# 0003. Delivery guarantees per stage: transactional enrich, idempotent detect and index, DLQ for poison

Date: 2026-10-17. Status: accepted.

## Context

"Exactly once" is a property of a stage and its sink, not of a pipeline. Each stage here has a different
sink, so each gets the guarantee its sink can honour.

## Decision

- **ingest**: idempotent producer (`enable.idempotence`, `acks=all`), duplicate event ids suppressed for
  ten minutes in memory, 503 with `Retry-After` when the producer's buffer or the broker cannot keep up,
  429 from the per-key token bucket. An id is remembered only after Kafka acknowledged its record, so a
  client that retries a batch after a 503 loses nothing; the records that did land count as duplicates.
- **enrich**: consume-transform-produce in one Kafka transaction per poll (`transaction-id-prefix`,
  batch listener, up to `max.poll.records` = 500 records, `isolation.level=read_committed` downstream). The
  enriched records, the DLQ records for malformed input and the consumed offsets commit or abort together,
  so a crash never leaves a duplicate output visible to `read_committed` consumers. A record that fails on
  its own (malformed, an address that is not an IP, a value the database rejects, a bug) is published to
  `events.dlq` with the error in headers inside the same transaction, and the records around it carry on,
  so a poison record cannot stall a partition. A failure of the database or the broker
  (`TransientDataAccessException`, `DataAccessResourceFailureException` and the like, Kafka exceptions)
  rolls the whole poll back, and the after-rollback processor re-reads it with back-off from one second to
  thirty, indefinitely, so an outage dead-letters nothing.
- **detect**: at-least-once with manual acknowledgement after the alert is stored and its send to `alerts`
  is acknowledged; alert ids are deterministic and the store upserts, so redelivery is harmless (tested by
  producing the same burst twice). Each threshold window keeps the ids of the events it counted, so a
  redelivered event is not counted again, and one that counted towards an alert that already fired returns
  that alert again: when storing or producing it failed, the retry finishes the job. A database or broker
  failure is retried with back-off from one second to thirty, indefinitely; any other failure (a rule that
  throws on an event, say) is tried three times and the event goes to `events.dlq` with `error-stage`
  `detect`.
- **index**: batch consumer, one bulk request per poll, documents keyed by their ids so a redelivered
  batch overwrites rather than duplicates; a failed bulk, or any document refused with 429 or a 5xx,
  throws, and the batch is redelivered with exponential back-off, nothing dropped. A document refused for
  any other reason (a 400 mapping conflict, which no retry fixes) goes to `events.dlq` with the status and
  reason in headers once no retryable refusals remain in the batch, and the batch is acknowledged. The
  first version threw on any refused document with unlimited retries, so one such document stopped the
  stage for good.

## Consequences

- The first detect version set the window's "fired" flag before storing the alert and produced it without
  waiting. A failed store was redelivered by Spring's default error handler (ten attempts, no back-off,
  then skip), the engine saw the flag, emitted nothing, and the alert was lost; each retry also counted the
  event again.
- The first enrich version reported the failing record's index and relied on `DefaultAfterRollbackProcessor` to
  dead-letter it. A transactional batch listener never does that: it either re-seeks the whole batch or, with
  `batchRecoverAfterRollback`, dead-letters every record in it. The processor bean was also typed
  `<String, String>`, which Spring Boot does not inject into the container factory, so it was never used.
  One poison record redelivered the same batch forever.
- The tests assert the properties: `EnrichFailurePolicyTest` (in-process broker) puts a record the
  database rejects between good ones and expects it alone in the DLQ, and makes the database fail twice
  and expects nothing dead-lettered; `EnrichIT` sends 32 good and 3 bad records and expects exactly 32
  enriched and 3 dead-lettered; `DetectIT` sends a burst twice and expects one alert;
  `DetectFailurePolicyTest` (in-process broker) dead-letters an event that makes a rule throw and waits
  out a database that refuses three stores without losing the alert; `IndexIT` sends everything twice and
  counts documents.
- The first version committed a transaction per record (`ack-mode: record`). The first load run measured
  about 65 events per second on the enrich stage, with `sendOffsetsToTransaction` and the commit taking
  about 15 ms per record, and all traffic on one partition because ingest keyed records by feed name. The
  transaction now spans the poll and ingest keys by source address (then host, then feed), which is also
  the field most threshold rules group by. The load run in the README is from the second version.
- The ingest de-duplication window is in-memory and per instance; two ingest replicas could each accept
  the same id. The enrich transaction does not de-duplicate either. For strict end-to-end de-duplication a
  shared key store (Redis) in ingest would be the next step.
