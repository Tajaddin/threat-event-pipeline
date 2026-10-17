.PHONY: build test verify format up up-obs down logs load e2e console-build alerts-test helm-lint images teardown

MVN ?= mvn
COMPOSE ?= docker compose

build:
	$(MVN) -B -q -DskipTests -DskipITs package

test:
	$(MVN) -B -DskipITs test

verify:  ## unit + integration tests (Testcontainers), coverage, format check
	$(MVN) -B verify

format:
	$(MVN) -B -q spotless:apply
	cd console && npx prettier --write "src/**/*.ts" "e2e/**/*.ts"

up:
	$(COMPOSE) up -d --build

up-obs:
	$(COMPOSE) --profile observability up -d --build

down:
	$(COMPOSE) --profile observability down -v --remove-orphans

logs:
	$(COMPOSE) logs -f ingest-service enrich-service detect-service index-service

load:  ## single-machine load run; writes load/results/latest.json
	bash load/run-load.sh

e2e:
	cd console && CONSOLE_BASE=http://localhost:$${CONSOLE_PORT:-4200} npx playwright test

console-build:
	cd console && npx ng lint && npx ng test --watch=false --browsers=ChromeHeadless && npx ng build --configuration production

alerts-test:
	docker run --rm -v "$(CURDIR)/observability:/w" -w /w --entrypoint promtool prom/prometheus:v3.5.0 check rules alert_rules.yml
	docker run --rm -v "$(CURDIR)/observability:/w" -w /w --entrypoint promtool prom/prometheus:v3.5.0 test rules alerts_test.yml

helm-lint:
	docker run --rm -v "$(CURDIR)/deploy/helm:/w" -w /w alpine/helm:3.22.1 lint threat-event-pipeline
	docker run --rm -v "$(CURDIR)/deploy/helm:/w" -w /w alpine/helm:3.22.1 template tep threat-event-pipeline --set ingress.enabled=true --set serviceMonitor.enabled=true > /dev/null && echo "template ok"

images:
	for m in ingest-service enrich-service detect-service index-service; do docker build --build-arg MODULE=$$m -t threat/$$m:local .; done
	docker build -t threat/console:local console

teardown: down
