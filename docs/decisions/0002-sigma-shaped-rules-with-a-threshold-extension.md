# 0002. Rules follow the Sigma shape, with a small threshold extension and no Sigma backend

Date: 2026-10-17. Status: accepted.

## Context

Detection content should be data, reviewable and reloadable, and look like what detection engineers
already write. Sigma is the common denominator (logsource, named selections, a condition expression).
Most Sigma rules are stateless; the attacks worth detecting here (brute force, spray, scans) need counting
over a window, which Sigma expresses as separate correlation rules.

## Decision

`detect-service` loads YAML files whose top level is the Sigma rule shape: `id`, `title`, `level`,
`tags`, `logsource` (`category` is matched against the event type), `detection` with named selections and a
`condition`. Supported: field modifiers `contains`, `startswith`, `endswith`, `re`, `gt/gte/lt/lte`,
`cidr`; list values OR-ed; conditions with `and`, `or`, `not`, parentheses, `1 of x*`, `all of x*`,
`them`. Matching is case-insensitive, as Sigma specifies.

A `threshold` block is the project's extension: `count`, `window`, `groupBy` and optional `distinct`.
The engine keeps `(rule, key, tumbling window)` state in a bounded, expiring map and fires once per window
when the count or the number of distinct values reaches the threshold. Windows are cut on the event's own
timestamp, so replay and out-of-order delivery land events in the right window, and the alert id is
derived from `(rule, key, window start)`, which makes alert storage idempotent.

Rules live in the service's classpath and in an optional directory (`DETECT_RULES_DIR`, a ConfigMap in
Kubernetes); `POST /api/rules/reload` re-reads them and swaps the engine's rule list atomically. The
catalogue, including each rule's YAML and hit count, is in Postgres and served by the API.

## Consequences

- Seven rules ship (brute force, password spray, lateral movement, port scan, large outbound transfer,
  special privileges on a critical asset, logon from a hostile range); each has a unit test driving it with
  synthetic events, and the parser and matcher have their own tests.
- Sigma rules of the supported subset can be dropped in; rules using unsupported modifiers (`base64`,
  `windash`, aggregation expressions) are rejected at load time with a reason that the API reports.
- Threshold state is per instance (see ADR 0001). Window retention is 30 minutes by default; a window longer
  than that would need the retention raised.
- There is no Sigma-to-backend translation (no conversion to OpenSearch queries): detection runs on the
  stream, and OpenSearch is for search and dashboards after the fact.
