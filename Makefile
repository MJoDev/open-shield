# open-shield
#
# Go is not required on the host: every Go command runs inside a container, so
# the only dependency is Docker.

COMPOSE       ?= docker compose -f deploy/docker-compose.yml
COMPOSE_DEMO  ?= docker compose -f deploy/docker-compose.quickstart.yml
GO_IMAGE      ?= golang:1.25
GO_RUN         = docker run --rm -v "$(CURDIR):/src" -w /src -v open-shield-gomod:/go/pkg/mod $(GO_IMAGE)

.DEFAULT_GOAL := help

.PHONY: help
help: ## Muestra esta ayuda
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

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

.PHONY: test
test: ## Ejecuta go vet y la batería de tests
	$(GO_RUN) sh -c "go vet ./... && go test ./..."

.PHONY: test-race
test-race: ## Ejecuta los tests con el detector de carreras
	$(GO_RUN) sh -c "go test -race ./..."

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

# --- Verificación ------------------------------------------------------------

.PHONY: smoke
smoke: ## Prueba de humo end-to-end contra el stack en marcha
	./scripts/smoke.sh

.PHONY: tamper-demo
tamper-demo: ## Demuestra la detección de manipulación (CORROMPE el log)
	./scripts/tamper-demo.sh
