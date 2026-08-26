#!/usr/bin/env bash
# End-to-end check of a running open-shield stack.
#
#   ./scripts/smoke.sh [http://localhost] [http://localhost:8081]
#
# Exercises the whole request path — proxy, rule chain, audit log, dashboard —
# and exits non-zero on the first failure, so it works as a CI gate.
set -uo pipefail

PROXY="${1:-http://localhost:${OS_HTTP_PORT:-80}}"
DASHBOARD="${2:-http://localhost:${OS_DASHBOARD_PORT:-8081}}"
ADMIN_USER="${OS_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${OS_ADMIN_PASSWORD:-}"

COOKIES="$(mktemp)"
trap 'rm -f "$COOKIES"' EXIT

passed=0
failed=0

pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; passed=$((passed + 1)); }
fail() { printf '  \033[31m✗\033[0m %s\n' "$1"; failed=$((failed + 1)); }

# check <description> <expected-status> <curl args...>
check() {
    local description="$1" expected="$2"; shift 2
    local actual
    actual="$(curl -s -o /dev/null -w '%{http_code}' "$@")"
    if [ "$actual" = "$expected" ]; then
        pass "$description (${actual})"
    else
        fail "$description — se esperaba ${expected}, llegó ${actual}"
    fi
}

echo
echo "open-shield · prueba de humo"
echo "  proxy:     $PROXY"
echo "  dashboard: $DASHBOARD"
echo

echo "1. El proxy responde"
check "health del proxy" 200 "$PROXY/__openshield/health"

echo
echo "2. El tráfico legítimo llega al backend (RF-01, RF-02)"
check "petición normal" 200 "$PROXY/"
check "ruta con parámetros normales" 200 "$PROXY/catalogo?page=2&orden=nombre"

echo
echo "3. Se filtran los payloads maliciosos (RF-03)"
check "SQLi en la query" 403 "$PROXY/productos?id=1'%20OR%20'1'='1"
check "UNION SELECT" 403 "$PROXY/buscar?q=x'%20UNION%20SELECT%20clave%20FROM%20usuarios--"
check "XSS en la query" 403 "$PROXY/buscar?q=<script>alert(1)</script>"
# The case auth_request could never have caught: the payload is in the body.
check "XSS en el cuerpo del POST" 403 -X POST "$PROXY/comentarios" \
    -d 'texto=<script>fetch("//evil")</script>'
check "SQLi en el cuerpo del POST" 403 -X POST "$PROXY/login" \
    -d "usuario=admin'--&clave=x"

echo
echo "4. Rate limiting por IP (RF-05)"
limit="${OS_RATELIMIT_REQUESTS:-100}"
burst=$((limit + 30))
throttled=0
for _ in $(seq 1 "$burst"); do
    code="$(curl -s -o /dev/null -w '%{http_code}' "$PROXY/rate-limit-probe")"
    [ "$code" = "429" ] && throttled=$((throttled + 1))
done
if [ "$throttled" -gt 0 ]; then
    pass "$throttled de $burst peticiones recibieron 429"
else
    fail "ninguna petición fue limitada tras $burst intentos (límite: $limit)"
fi

echo
echo "5. El dashboard exige autenticación"
check "eventos sin sesión" 401 "$DASHBOARD/api/v1/events"
check "verificación sin sesión" 401 "$DASHBOARD/api/v1/audit/verify"

if [ -z "$ADMIN_PASSWORD" ]; then
    echo
    echo "  (Define OS_ADMIN_PASSWORD para probar también las rutas autenticadas.)"
else
    echo
    echo "6. Integridad del log de auditoría (RF-06, §6)"
    login_status="$(curl -s -o /dev/null -w '%{http_code}' -c "$COOKIES" \
        -X POST "$DASHBOARD/api/v1/login" \
        -H 'Content-Type: application/json' \
        -d "{\"user\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASSWORD\"}")"

    if [ "$login_status" != "200" ]; then
        fail "inicio de sesión (${login_status})"
    else
        pass "inicio de sesión"

        verify="$(curl -s -b "$COOKIES" "$DASHBOARD/api/v1/audit/verify")"
        if printf '%s' "$verify" | grep -q '"ok":true'; then
            checked="$(printf '%s' "$verify" | sed -n 's/.*"checked":\([0-9]*\).*/\1/p')"
            pass "cadena de hashes íntegra (${checked} entradas verificadas)"
        else
            fail "la cadena no verifica: $verify"
        fi

        # The blocks made above must be on the record. A filter that stops an
        # attack without leaving evidence fails RF-06.
        blocked="$(curl -s -b "$COOKIES" "$DASHBOARD/api/v1/events?verdict=block&limit=1")"
        if printf '%s' "$blocked" | grep -q '"total":[1-9]'; then
            pass "los bloqueos quedaron registrados"
        else
            fail "el log no contiene los bloqueos que acaban de producirse"
        fi
    fi
fi

echo
echo "──────────────────────────────────────────"
printf '  %d correctas, %d fallidas\n' "$passed" "$failed"
echo

[ "$failed" -eq 0 ]
