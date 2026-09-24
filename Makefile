# open-shield
#
# Go is not required on the host: every Go command runs inside a container, so
# the only dependency is Docker.
#
# CI overrides GO_RUN with an empty value, so the same targets run natively
# against actions/setup-go. One definition of what "the tests pass" means,
# shared by this machine and the runner.

# The demo stack is the base stack plus an override, layered with -f. See the
# header of docker-compose.quickstart.yml for why it is not an `include:`.
COMPOSE       ?= docker compose -f deploy/docker-compose.yml
COMPOSE_DEMO  ?= $(COMPOSE) -f deploy/docker-compose.quickstart.yml
COMPOSE_E2E   ?= $(COMPOSE_DEMO) -f deploy/docker-compose.e2e.yml
COMPOSE_LOAD  ?= $(COMPOSE_DEMO) -f deploy/docker-compose.load.yml
COMPOSE_DEPS  ?= docker compose -f deploy/docker-compose.test.yml
GO_IMAGE      ?= golang:1.25
GO_RUN         = docker run --rm -v "$(CURDIR):/src" -w /src -v open-shield-gomod:/go/pkg/mod $(GO_IMAGE)

# The compose project name of the stack, which is also the network k6 joins.
STACK_NETWORK ?= open-shield_openshield

# Dependencies for the integration suite. The ports are high on purpose so a
# test run cannot collide with a demo stack somebody left running.
TEST_POSTGRES_DSN ?= postgres://openshield:openshield@localhost:$(or $(OS_TEST_POSTGRES_PORT),55432)/openshield_test?sslmode=disable
TEST_REDIS_ADDR   ?= localhost:$(or $(OS_TEST_REDIS_PORT),56379)

# Where the running stack answers.
#
# The published ports come from deploy/.env, so they are read from there rather
# than assumed: a stack on OS_HTTP_PORT=8090 is perfectly normal, and a target
# that hardcoded 80 would fail with "connection refused" and no hint as to why.
# An environment variable still wins, and 80/8081 are the last resort.
ENV_FILE      ?= deploy/.env
env_port       = $(shell sed -n 's/^$(1)=//p' $(ENV_FILE) 2>/dev/null | tail -1)

HTTP_PORT     ?= $(or $(OS_HTTP_PORT),$(call env_port,OS_HTTP_PORT),80)
DASH_PORT     ?= $(or $(OS_DASHBOARD_PORT),$(call env_port,OS_DASHBOARD_PORT),8081)

# 127.0.0.1 rather than localhost: inside a container "localhost" resolves to
# ::1 first, and nothing is listening there.
PROXY_URL     ?= http://127.0.0.1:$(HTTP_PORT)
DASHBOARD_URL ?= http://127.0.0.1:$(DASH_PORT)

# Host networking, so a containerised test run reaches the ports the stack
# publishes. CI overrides GO_RUN_HOST with an empty value, exactly as it does
# GO_RUN, and the same target then runs natively.
GO_RUN_HOST    = docker run --rm --network host -v "$(CURDIR):/src" -w /src \
	-v open-shield-gomod:/go/pkg/mod $(GO_IMAGE)

.DEFAULT_GOAL := help

.PHONY: help
help: ## Muestra esta ayuda
	@# Los dígitos importan: sin ellos, up-e2e y test-e2e no salen en la ayuda.
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# --- Ejecución ---------------------------------------------------------------

.PHONY: up
up: ## Levanta el stack completo con la aplicación de demostración
	$(COMPOSE_DEMO) up -d --build

.PHONY: up-prod
up-prod: ## Levanta el stack apuntando a OS_BACKEND_URL
	$(COMPOSE) up -d --build

.PHONY: down
down: ## Detiene el stack (conserva el log de auditoría)
	$(COMPOSE_DEMO) down

.PHONY: clean
clean: ## Detiene el stack y BORRA el log de auditoría
	$(COMPOSE_DEMO) down -v

.PHONY: logs
logs: ## Sigue los logs de todos los servicios
	$(COMPOSE_DEMO) logs -f

.PHONY: ps
ps: ## Estado de los servicios
	$(COMPOSE_DEMO) ps

# --- Desarrollo --------------------------------------------------------------

.PHONY: tidy
tidy: ## Actualiza go.mod y go.sum
	$(GO_RUN) go mod tidy

.PHONY: web
web: ## Compila el dashboard React localmente
	cd dashboard/web && npm ci && npm run build

.PHONY: hash-password
hash-password: ## Genera el hash bcrypt del administrador. Uso: make hash-password PASSWORD='...'
	@test -n "$(PASSWORD)" || (echo "Uso: make hash-password PASSWORD='tu contraseña'" && exit 1)
	@$(GO_RUN) go run ./dashboard/api/cmd/api -hash-password '$(PASSWORD)'

# --- Pruebas -----------------------------------------------------------------
#
# La pirámide completa está documentada en docs/testing-strategy.md.
# Todos estos pasos son obligatorios para aprobar un PR.

.PHONY: test
test: ## Ejecuta go vet y los tests unitarios (sin dependencias externas)
	$(GO_RUN) sh -c "go vet ./... && go test ./..."

.PHONY: test-unit
test-unit: test ## Alias de 'test'

.PHONY: test-race
test-race: ## Ejecuta los tests unitarios con el detector de carreras
	$(GO_RUN) sh -c "go test -race ./..."

.PHONY: test-integration
test-integration: ## Tests de integración contra PostgreSQL y Redis reales
	$(COMPOSE_DEPS) up -d --wait
	@$(MAKE) --no-print-directory test-integration-only; \
		status=$$?; \
		$(COMPOSE_DEPS) down; \
		exit $$status

# The suite spans three directories because of Go's internal rule, and all of
# them share one database — so the package binaries must not run in parallel.
# That is what -p 1 is for; without it they truncate each other's tables
# mid-test and the failures make no sense.
.PHONY: test-integration-only
test-integration-only: ## Igual que test-integration, con las dependencias ya levantadas
	$(GO_RUN) sh -c '\
		OS_TEST_POSTGRES_DSN="$(TEST_POSTGRES_DSN)" \
		OS_TEST_REDIS_ADDR="$(TEST_REDIS_ADDR)" \
		go test -tags=integration -p 1 -count=1 ./...'

.PHONY: test-e2e
test-e2e: ## Tests end-to-end contra el stack en marcha. Necesita OS_ADMIN_PASSWORD
	@test -n "$(OS_ADMIN_PASSWORD)" || \
		(echo "Uso: OS_ADMIN_PASSWORD='...' make test-e2e" && exit 1)
	$(GO_RUN_HOST) sh -c '\
		OS_PROXY_URL="$(PROXY_URL)" \
		OS_DASHBOARD_URL="$(DASHBOARD_URL)" \
		OS_ADMIN_USER="$(or $(OS_ADMIN_USER),admin)" \
		OS_ADMIN_PASSWORD="$(OS_ADMIN_PASSWORD)" \
		OS_RATELIMIT_REQUESTS="$(or $(OS_E2E_RATELIMIT_REQUESTS),200)" \
		OS_RATELIMIT_WINDOW_S="$(or $(OS_E2E_RATELIMIT_WINDOW_S),5)" \
		go test -tags=e2e -count=1 -v ./test/e2e/...'

.PHONY: test-web
test-web: ## Tests y comprobación de tipos del dashboard React
	cd dashboard/web && npm ci && npm run typecheck && npm run test:run

.PHONY: up-e2e
up-e2e: ## Levanta el stack con los ajustes de la batería end-to-end
	$(COMPOSE_E2E) up -d --build --wait

.PHONY: up-load
up-load: ## Levanta el stack con los ajustes de la batería de carga
	$(COMPOSE_LOAD) up -d --build --wait

.PHONY: test-load
test-load: ## Prueba de carga corta (k6) contra el stack en marcha
	./scripts/load.sh smoke

.PHONY: test-load-full
test-load-full: ## Prueba de carga completa (k6), ~10 minutos
	./scripts/load.sh full

.PHONY: test-soak
test-soak: ## Prueba de resistencia (k6), ~30 minutos
	./scripts/load.sh soak

.PHONY: test-all
test-all: lint test-race test-integration test-web ## Todo lo que no necesita el stack levantado

.PHONY: cover
cover: ## Cobertura por paquete, contrastada con test/coverage-floors.txt
	$(COMPOSE_DEPS) up -d --wait
	@$(GO_RUN) sh -c '\
		OS_TEST_POSTGRES_DSN="$(TEST_POSTGRES_DSN)" \
		OS_TEST_REDIS_ADDR="$(TEST_REDIS_ADDR)" \
		go test -tags=integration -p 1 -count=1 \
			-covermode=atomic -coverprofile=coverage.out -coverpkg=./... ./... > /dev/null && \
		sh scripts/coverage.sh coverage.out'; \
		status=$$?; \
		$(COMPOSE_DEPS) down; \
		exit $$status

.PHONY: lint
lint: ## gofmt, go vet y golangci-lint
	$(GO_RUN) sh -c 'test -z "$$(gofmt -l .)" || (echo "Sin formatear:"; gofmt -l .; exit 1)'
	$(GO_RUN) go vet ./...
	docker run --rm -v "$(CURDIR):/src" -w /src \
		-v open-shield-golangci:/root/.cache golangci/golangci-lint:v2.6.2 \
		golangci-lint run --timeout 5m

.PHONY: vuln
vuln: ## Busca CVEs conocidos en las dependencias
	$(GO_RUN) sh -c "go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./..."

# --- Verificación ------------------------------------------------------------

.PHONY: smoke
smoke: ## Prueba de humo end-to-end contra el stack en marcha
	./scripts/smoke.sh

.PHONY: tamper-demo
tamper-demo: ## Demuestra la detección de manipulación (CORROMPE el log)
	./scripts/tamper-demo.sh
