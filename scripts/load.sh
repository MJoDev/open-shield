#!/usr/bin/env bash
# Runs the k6 load suite against a running stack.
#
#   ./scripts/load.sh [smoke|full|soak]
#
# k6 runs as a container joined to the stack's own network, so it reaches both
# the proxy and the demo backend by service name — the same vantage point the
# manual's §5.1 measurement uses, and the only one from which the two are
# comparable. Measuring from the host would add the Docker port mapping to one
# side of the comparison and not the other.
#
# The stack must be up with the load overrides applied, or the rate limiter will
# throttle the run and the numbers will describe the limiter:
#
#   make up-load
#
# k6 exits non-zero when a threshold in test/load/k6/thresholds.js is broken, so
# this works as a CI gate as it stands.
#
# --quiet suppresses the per-second progress redraw. Without a TTY k6 reprints
# the whole block every second, which buries the summary in a CI log.
set -uo pipefail

# Git Bash rewrites arguments that look like Unix paths into Windows ones, which
# turns docker's -w /work/out into something the daemon rejects. Harmless
# everywhere else: on Linux this is just an unused variable.
export MSYS_NO_PATHCONV=1

PROFILE="${1:-smoke}"
NETWORK="${STACK_NETWORK:-open-shield_openshield}"
K6_IMAGE="${K6_IMAGE:-grafana/k6:latest}"
OUTPUT_DIR="${OUTPUT_DIR:-.}"

DASHBOARD="${OS_DASHBOARD_URL:-http://localhost:${OS_DASHBOARD_PORT:-8081}}"
ADMIN_USER="${OS_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${OS_ADMIN_PASSWORD:-}"

case "$PROFILE" in
    smoke|full|soak) ;;
    *)
        echo "Perfil desconocido: $PROFILE (usa smoke, full o soak)" >&2
        exit 1
        ;;
esac

if ! docker network inspect "$NETWORK" >/dev/null 2>&1; then
    cat >&2 <<EOF
No existe la red $NETWORK.

Levanta el stack con los ajustes de carga:

  docker compose -f deploy/docker-compose.yml \\
                 -f deploy/docker-compose.quickstart.yml \\
                 -f deploy/docker-compose.load.yml up -d --build

Si tu proyecto de compose tiene otro nombre, define STACK_NETWORK.
EOF
    exit 1
fi

# The audit queue depth before the run, so the two can be compared afterwards.
# It is the number that degrades quietly: entries are dropped and counted rather
# than blocking a request, which is correct, and invisible unless somebody looks.
COOKIES="$(mktemp)"
trap 'rm -f "$COOKIES"' EXIT

audit_stats() {
    [ -n "$ADMIN_PASSWORD" ] || return 0

    curl -s -o /dev/null -c "$COOKIES" -X POST "$DASHBOARD/api/v1/login" \
        -H 'Content-Type: application/json' \
        -d "{\"user\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASSWORD\"}" || return 0

    curl -s -b "$COOKIES" "$DASHBOARD/api/v1/status" \
        | sed -n 's/.*"audit":{\([^}]*\)}.*/\1/p'
}

before="$(audit_stats)"

echo
echo "open-shield · carga (perfil: $PROFILE, red: $NETWORK)"
[ -n "$before" ] && echo "  cola de auditoría antes: $before"
echo

docker run --rm \
    --network "$NETWORK" \
    -v "$(pwd)/test:/work/test:ro" \
    -v "$(pwd)/${OUTPUT_DIR}:/work/out" \
    -w /work/out \
    -e OS_LOAD_PROFILE="$PROFILE" \
    -e OS_PROXY_URL="${OS_LOAD_PROXY_URL:-http://proxy}" \
    -e OS_BACKEND_URL="${OS_LOAD_BACKEND_URL:-http://demo-backend:3000}" \
    -e OS_LOAD_LATENCY_BUDGET_MS="${OS_LOAD_LATENCY_BUDGET_MS:-}" \
    "$K6_IMAGE" run --quiet /work/test/load/k6/main.js

status=$?

after="$(audit_stats)"
if [ -n "$after" ]; then
    echo "  cola de auditoría después: $after"
    echo
    echo "  Si 'dropped' creció, la base de datos no siguió el ritmo del tráfico."
    echo "  Revisa la E/S de disco antes de subir OS_AUDIT_BUFFER: un buffer mayor"
    echo "  solo alarga el momento en que empieza a descartar."
    echo
fi

exit $status
