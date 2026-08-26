#!/usr/bin/env bash
# Demonstrates the forensic guarantee of §6: an altered audit entry is detected,
# and the exact record is named.
#
#   OS_ADMIN_PASSWORD='...' ./scripts/tamper-demo.sh
#
# WARNING: this deliberately corrupts the audit log of the running stack. Once
# the chain is broken it stays broken — that is the whole point. Run it against
# a demo stack, then recreate the database volume:
#
#   docker compose -f deploy/docker-compose.quickstart.yml down -v
set -uo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-deploy/docker-compose.quickstart.yml}"
DASHBOARD="${DASHBOARD:-http://localhost:${OS_DASHBOARD_PORT:-8081}}"
ADMIN_USER="${OS_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${OS_ADMIN_PASSWORD:-}"
PG_USER="${POSTGRES_USER:-openshield}"
PG_DB="${POSTGRES_DB:-openshield}"

if [ -z "$ADMIN_PASSWORD" ]; then
    echo "Define OS_ADMIN_PASSWORD con la contraseña del dashboard." >&2
    exit 1
fi

COOKIES="$(mktemp)"
trap 'rm -f "$COOKIES"' EXIT

psql() { docker compose -f "$COMPOSE_FILE" exec -T db psql -U "$PG_USER" -d "$PG_DB" "$@"; }

rule() { printf '\n\033[1m%s\033[0m\n' "$1"; }

curl -s -o /dev/null -c "$COOKIES" -X POST "$DASHBOARD/api/v1/login" \
    -H 'Content-Type: application/json' \
    -d "{\"user\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASSWORD\"}"

rule "1 · La cadena está íntegra"
curl -s -b "$COOKIES" "$DASHBOARD/api/v1/audit/verify"
echo

rule "2 · La base de datos rechaza modificar el log"
# The hash chain makes tampering detectable; the trigger makes it inconvenient.
psql -c "UPDATE audit_log SET payload = jsonb_set(payload, '{verdict}', '\"allow\"')
         WHERE payload->>'verdict' = 'block';" 2>&1 | head -3

rule "3 · Un atacante con privilegios suficientes desactiva el trigger y edita"
# This is the realistic threat: someone who already owns the database. The
# chain does not try to stop them — it makes sure they cannot do it quietly.
psql -q \
    -c "ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_modify;" \
    -c "UPDATE audit_log
        SET payload = jsonb_set(payload, '{verdict}', '\"allow\"')
        WHERE seq = (SELECT min(seq) FROM audit_log WHERE payload->>'verdict' = 'block');" \
    -c "ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_modify;"
echo "   Un bloqueo fue reescrito como si hubiera sido permitido."

rule "4 · La verificación lo detecta y señala el registro exacto"
curl -s -b "$COOKIES" "$DASHBOARD/api/v1/audit/verify"
echo
echo

echo "El log ya no verifica. Para volver a un estado limpio:"
echo "  docker compose -f $COMPOSE_FILE down -v"
echo
