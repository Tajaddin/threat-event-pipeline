# Running and deploying

## Compose (one machine)

```bash
cp .env.example .env
docker compose up -d --build                        # Kafka, Postgres, OpenSearch + Dashboards, 4 services, console
docker compose --profile observability up -d        # + kafka-exporter, Prometheus, Alertmanager, Grafana
```

| What | Where |
|---|---|
| Console | http://localhost:4200 |
| Ingest API, Swagger | http://localhost:8081/swagger-ui.html |
| Detect API, Swagger | http://localhost:8083/swagger-ui.html |
| OpenSearch Dashboards | http://localhost:5601 (indices `events-*`, `alerts-*`) |
| Prometheus / Alertmanager / Grafana | http://localhost:9093, :9096, :3004 (admin / `GRAFANA_ADMIN_PASSWORD`) |

Generate traffic from the console's Pipeline tab or directly:

```bash
curl -X POST http://localhost:8081/api/generate -H 'Content-Type: application/json' \
  -d '{"eventsPerSecond":500,"seconds":60,"attackShare":0.05}'
```

Set `INGEST_API_KEYS=key1,key2` in `.env` to require `X-API-Key` on the ingest API (the console asks for it).
The first start takes two to three minutes: Kafka and OpenSearch warm up, the services wait for them.

Resource notes: Kafka 768 MB heap, OpenSearch 1 GB heap (`OPENSEARCH_HEAP`), each service about 300 MB.
Plan on 6 GB for the full stack with the observability profile.

## Load run

```bash
bash load/run-load.sh                                # 500 to 16,000 events/s in six steps of 60 s (the README table)
RATES="1000 3000" SECONDS_PER_STEP=90 bash load/run-load.sh
```

Prints a table per step and writes `load/results/latest.json` with the method recorded; `python load/render-results.py --write README.md`
puts the table into the README. Seeds derive from the clock because ingest drops event ids seen in the last ten
minutes; set `SEED_BASE` to reproduce a run.

## Tests

```bash
mvn -B verify                       # unit tests, then integration tests with Kafka, Postgres and OpenSearch in Testcontainers
mvn -B spotless:check               # Google Java Format
cd console && npx ng lint && npx ng test --watch=false --browsers=ChromeHeadless && npx ng build
cd console && CONSOLE_BASE=http://localhost:4200 npx playwright test     # against the compose stack
make alerts-test                    # promtool unit tests for the 7 alert rules
make helm-lint                      # helm lint + template
```

On this machine the local JDK is 25 and the project targets 21: builds and tests run fine on 25
(`maven.compiler.release=21`); the images build on `maven:3.9.16-eclipse-temurin-21`.

## Kubernetes (Helm)

The chart in `deploy/helm/threat-event-pipeline` deploys the four services and the console with readiness
and liveness probes, a rolling update with zero unavailable, non-root pods with read-only root filesystems,
a NetworkPolicy, a PodDisruptionBudget for detect, an optional Ingress and an optional ServiceMonitor.
Kafka, Postgres and OpenSearch are external and configured in `values.yaml`:

```bash
kubectl create namespace threat
kubectl -n threat create secret generic threat-postgres --from-literal=password='...'
kubectl -n threat create secret generic threat-ingest-keys --from-literal=apiKeys='key1,key2'
helm upgrade --install tep deploy/helm/threat-event-pipeline -n threat \
  --set kafka.bootstrapServers=my-kafka:9092 \
  --set postgres.url=jdbc:postgresql://my-pg:5432/threat \
  --set opensearch.url=http://my-opensearch:9200 \
  --set image.registry=ghcr.io/tajaddin --set image.tag=0.1.0
```

Images are built by the `Dockerfile` (`--build-arg MODULE=<service>`) and `console/Dockerfile`; pushing
them to a registry is a manual step until the k8s-platform-gitops project wires Argo CD and a registry.
Extra rules go in `detect.rules` (file name to YAML) and are mounted at `/rules`.

## Teardown

```bash
make down                 # compose down -v (all data)
helm uninstall tep -n threat
```
