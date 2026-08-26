# open-shield

**English** · [Español](README.es.md)

[![CI](https://github.com/MJoDev/open-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/MJoDev/open-shield/actions/workflows/ci.yml)

Reverse proxy with a rules engine and verifiable forensic traceability.

It sits in front of any web application and installs with a single command.
Every request passes through a rules engine before it reaches the origin
server, and every decision is written to an audit log chained by hashes: if
someone alters or deletes a record, verification detects it and points at the
exact entry.

Implementation of the [technical decisions document](docs/technical-document.md).
No proprietary dependencies and no coupling to any particular infrastructure:
the same stack installs the same way on any VPS.

---

## Getting started

Docker is the only requirement.

```bash
git clone https://github.com/MJoDev/open-shield.git && cd open-shield
cp deploy/.env.example deploy/.env
```

Generate the three secrets that `deploy/.env` marks as mandatory:

```bash
openssl rand -base64 24     # POSTGRES_PASSWORD
openssl rand -hex 32        # OS_SESSION_SECRET

make hash-password PASSWORD='your password'   # OS_ADMIN_PASSWORD_HASH
```

> The command prints the line already escaped. The `$$` in the hash are
> intentional: Docker Compose reads a lone `$` as a variable, and pasting the
> hash unescaped makes the container receive an empty value with no visible
> error.

Bring up the full stack, demo application included:

```bash
make up
```

| | |
|---|---|
| `http://localhost` | the protected application, behind the proxy |
| `http://localhost:8081` | the dashboard |

To protect your own application instead of the demo, point `OS_BACKEND_URL` at
it in `deploy/.env` and use `make up-prod`.

### Check it

```bash
curl -i localhost/                                # 200 — passes to the backend
curl -i "localhost/?id=1'%20OR%20'1'='1"          # 403 — sqli rule
curl -i -X POST localhost/ -d "q=<script>x</script>"   # 403 — xss rule, in the body
```

Or all at once, including rate limiting and log integrity:

```bash
OS_ADMIN_PASSWORD='your password' make smoke
```

---

## What it does

| | |
|---|---|
| **RF-01** | Intercepts every connection before the origin server |
| **RF-02** | Routes to the configured backend |
| **RF-03** | Filters SQLi and XSS in path, query, headers, cookies **and body** |
| **RF-05** | Limits requests per IP over a sliding window |
| **RF-06** | Logs every connection with verifiable integrity |
| **RF-09** | Real-time dashboard over WebSocket |
| **RF-10** | Full installation with a single command |

Deferred to v1.1, with their anchor points already in place: TLS and automatic
certificate renewal (RF-04), notification on anomalous traffic (RF-07), and
load balancing across instances (RF-08).

---

## Architecture

```
internet ──► proxy (OpenResty)
               │  access_by_lua → POST /v1/decide   [keepalive]
               ▼
            engine (Go)
               │  ipblock → ratelimit → sqli → xss     ← first block wins
               ├──► Redis        rate limit sliding window
               │
               └──► single writer ──► PostgreSQL   hash chain
                                  └──► Redis Pub/Sub
                                            │
            dashboard-api (Go) ◄─────────────┘
               └── REST + WebSocket + embedded React
```

Every request carries an `X-Request-ID` that travels with it from the proxy to
the audit entry and on to the backend, so a single request can be followed
across all three.

**Built here:** the rules engine, the forensic traceability scheme, and the
dashboard. **Third-party infrastructure:** Nginx/OpenResty, Redis and
PostgreSQL, used as they come and with no business logic inside them.

### Layout

```
internal/          model, audit chain, events, configuration
engine/            rules and decision engine
dashboard/api/     REST, WebSocket and embedded SPA
dashboard/web/     React interface
proxy/             OpenResty configuration and the Lua hook
migrations/        PostgreSQL schema, applied at startup
examples/          demo application
deploy/            docker-compose and .env.example
scripts/           smoke test, forensic demo, load runner
test/              shared attack corpus, integration, end-to-end and load suites
```

---

## Forensic traceability

Every log entry stores the hash of the previous one. Verifying means walking
the chain and recomputing:

```bash
curl -s -b cookies.txt localhost:8081/api/v1/audit/verify
# {"ok":true,"checked":1432}
```

The database also rejects any `UPDATE` or `DELETE` against the log. That makes
tampering inconvenient; the chain makes it **detectable**, which is what
matters against an attacker who already controls the database:

```bash
OS_ADMIN_PASSWORD='your password' make tamper-demo
```

The script disables the trigger, rewrites a block as if it had been allowed,
and verifies again:

```json
{
  "ok": false,
  "checked": 7,
  "broken_at": "fe5ec189-e4e2-4cdc-9738-6b0397c82d1d",
  "position": 7,
  "detail": "stored hash 8622dfd3ccff… does not match the recomputed hash 1cb8ecd17781… (this entry's content was modified after it was written)"
}
```

Deleting an entry does not go unnoticed either: the remaining hashes stay valid
on their own, but the link to the next one breaks.

**What is not stored:** request bodies and the `Cookie` and `Authorization`
headers. They are inspected, not kept. An append-only log with long retention
is the worst possible place for passwords and session tokens. What does remain
is the bounded fragment that triggered the block, which is the evidence of
*why* it was blocked.

---

## Development

Go does not need to be installed: everything runs in a container.

```bash
make test        # go vet + unit tests, no dependencies
make test-race   # with the race detector
make lint        # gofmt, go vet, golangci-lint
make logs        # follow the logs
make clean       # stop and DELETE the audit log
```

To work on the interface with hot reload:

```bash
cd dashboard/web && npm install && npm run dev   # proxied to localhost:8081
```

---

## Testing

Six levels, all of them required to merge a pull request. The full strategy is
in [the testing document](docs/estrategia-de-pruebas.md) *(in Spanish)*.

```bash
make test              # unit tests and fuzzing seeds — no dependencies
make test-integration  # real PostgreSQL and Redis, brought up and torn down
make cover             # per-package coverage against test/coverage-floors.txt

make up-e2e                                # the stack, configured for the suite
OS_ADMIN_PASSWORD='...' make test-e2e      # proxy → engine → log → dashboard

make up-load           # the stack, configured for measurement
make test-load         # k6: latency, availability and detection under load

make test-web          # the React dashboard
```

The attack corpus in `test/corpus/` is shared by three levels — the rule chain
in isolation, the live stack through the proxy, and the k6 attack scenario — so
a vector added once is covered by all three and cannot quietly stop being.

The load run states the number §8.2 budgets at under 50 ms:

```
                                p50          p95
Backend directly              0.48 ms     1.04 ms
Through the proxy             2.01 ms     7.60 ms
----------------------------------------------------
Added overhead                1.52 ms     6.56 ms
```

k6 exits non-zero when a threshold is broken, so the requirement is a gate
rather than a paragraph.

---

## Documentation

- [Technical document](docs/technical-document.md)
  ([Español](docs/documento-tecnico.md))
- [Implementation decisions](docs/decisiones-implementacion.md) — where and why
  the code departs from the technical document *(in Spanish)*
- [Operations manual](docs/manual-operacion.md) — deployment, tuning and
  diagnostics *(in Spanish)*
- [Testing strategy](docs/estrategia-de-pruebas.md) — what each level defends,
  how to run it, and how CI gates a pull request *(in Spanish)*

## License

[Apache License 2.0](LICENSE).
