# 0005. Synthetic traffic with injected attack scenarios, and numbers labelled single-machine

Date: 2026-10-17. Status: accepted.

## Context

Real security logs cannot be committed, and public samples are small and static. The pipeline needs a
steady, controllable stream with known attacks in it, both to demonstrate detections and to measure
throughput honestly.

## Decision

`SyntheticEvents` (in `common`) generates deterministic traffic from a seed: Windows-style authentication
events (4624, 4625, 4648, 4672 with logon types) and firewall events (allow/deny, ports, bytes) over
invented users, hosts and addresses in documentation and private ranges. An `attackShare` mixes in
scenario bursts that the bundled rules detect: brute force, password spray, lateral movement, port scan,
large outbound transfer, privilege use. Lookup tables (`ip_ranges`, `assets`) are invented too, with two
ranges labelled hostile.

The ingest service exposes `POST /api/generate` (rate, seconds, attack share, seed), which pushes batches
through the same accept path as the HTTP endpoint. `load/run-load.sh` runs the generator at increasing
rates and reads events per second per stage, maximum consumer lag and detection latency p95/p99 from
Prometheus at the end of each step, draining lag between steps. Results go to `load/results/latest.json`.

## Consequences

- Every throughput and latency number in the README comes from that script on this laptop under Docker
  Desktop, with Kafka, Postgres, OpenSearch and the four services sharing the machine, and is labelled
  "single machine". It is a capacity statement about this deployment, not a benchmark of Kafka.
- The generator bypasses HTTP parsing, so the measured rate is the pipeline's from ingest onwards; the
  HTTP endpoint's own overhead is covered by the ingest integration tests, not by the load number.
- Detection latency is measured from the ingest timestamp (a record header) to alert creation on the same
  clock, so it includes queueing in Kafka and the enrich stage, which is what an analyst would feel.
