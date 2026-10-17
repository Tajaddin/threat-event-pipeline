#!/usr/bin/env bash
# Single-machine load run: drive the ingest generator at increasing rates and read the pipeline's own
# metrics from Prometheus at the end of each step. Writes load/results/latest.json and prints a table.
#
#   bash load/run-load.sh                      # rates 500 1000 2000 4000 8000 16000, 60 s each (the README table)
#   RATES="1000 3000" SECONDS_PER_STEP=90 bash load/run-load.sh
#
# Requires the compose stack with the observability profile (Prometheus on $PROM, ingest on $INGEST).
set -euo pipefail
INGEST="${INGEST:-http://localhost:8081}"
PROM="${PROM:-http://localhost:9093}"
API_KEY="${INGEST_API_KEY:-}"
RATES="${RATES:-500 1000 2000 4000 8000 16000}"
STEP="${SECONDS_PER_STEP:-60}"
ATTACK="${ATTACK_SHARE:-0.02}"
# Seeds must differ between runs: ingest drops event ids it has seen in the last ten minutes, so a repeated
# seed within that window produces nothing. Set SEED_BASE for a reproducible run.
SEED_BASE="${SEED_BASE:-$(date +%s)}"
OUT="${OUT:-load/results/latest.json}"
mkdir -p "$(dirname "$OUT")"

q() { curl -s "$PROM/api/v1/query" --data-urlencode "query=$1" | python -c "import json,sys; r=json.load(sys.stdin)['data']['result']; print(r[0]['value'][1] if r else 'nan')"; }
hdr=(-H "Content-Type: application/json"); [ -n "$API_KEY" ] && hdr+=(-H "X-API-Key: $API_KEY")

echo "step,target_eps,achieved_eps,ingest_eps,enrich_eps,detect_eps,index_eps,max_lag,detect_p95_ms,detect_p99_ms,alerts_per_s"
results="["
i=0
for rate in $RATES; do
  i=$((i+1))
  curl -fsS -X POST "$INGEST/api/generate" "${hdr[@]}" -d "{\"eventsPerSecond\":$rate,\"seconds\":$STEP,\"attackShare\":$ATTACK,\"seed\":$((SEED_BASE + i))}" >/dev/null
  sleep "$STEP"
  # let the tail drain a little, then read 1-minute rates covering the step
  sleep 5
  status=$(curl -fsS "$INGEST/api/generate" "${hdr[@]}")
  achieved=$(echo "$status" | python -c "import json,sys; print(round(json.load(sys.stdin)['achievedPerSecond'],1))")
  ingest=$(q 'sum(rate(ingest_events_total{outcome="accepted"}[1m]))')
  enrich=$(q 'sum(rate(enrich_events_total{outcome="processed"}[1m]))')
  detect=$(q 'sum(rate(detect_events_total{outcome="evaluated"}[1m]))')
  index=$(q 'sum(rate(index_documents_total{kind="event"}[1m]))')
  lag=$(q "max_over_time(sum(kafka_consumergroup_lag)[${STEP}s:5s])")
  p95=$(q 'histogram_quantile(0.95, sum(rate(detect_latency_seconds_bucket[1m])) by (le)) * 1000')
  p99=$(q 'histogram_quantile(0.99, sum(rate(detect_latency_seconds_bucket[1m])) by (le)) * 1000')
  alerts=$(q 'sum(rate(detect_alerts_total[1m]))')
  printf '%s,%s,%s,%.0f,%.0f,%.0f,%.0f,%.0f,%.0f,%.0f,%.2f\n' "$i" "$rate" "$achieved" "$ingest" "$enrich" "$detect" "$index" "$lag" "$p95" "$p99" "$alerts"
  results="$results{\"step\":$i,\"target_eps\":$rate,\"achieved_eps\":$achieved,\"ingest_eps\":$ingest,\"enrich_eps\":$enrich,\"detect_eps\":$detect,\"index_eps\":$index,\"max_lag\":$lag,\"detect_p95_ms\":$p95,\"detect_p99_ms\":$p99,\"alerts_per_s\":$alerts},"
  # wait until lag drains before the next step so steps do not bleed into each other
  for _ in $(seq 1 60); do l=$(q 'sum(kafka_consumergroup_lag)'); [ "${l%.*}" -lt 1000 ] 2>/dev/null && break; sleep 2; done
done
results="${results%,}]"
python - "$OUT" "$STEP" "$ATTACK" "$SEED_BASE" "$results" <<'EOF'
import json, sys, datetime
out, step, attack, seed_base, results = sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), int(sys.argv[4]), json.loads(sys.argv[5])
json.dump({"run_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M"), "machine": "single machine, Docker Desktop (WSL2) on Windows 11, Intel i7 / 20 threads, 16 GB VM memory", "seconds_per_step": step, "attack_share": attack, "seed_base": seed_base,
           "method": "ingest generator at a target rate per step; rates and lag read from Prometheus 1-minute windows at the end of each step; single machine, Docker Desktop",
           "steps": results}, open(out, "w"), indent=2)
print("wrote", out)
EOF
