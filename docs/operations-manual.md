# Operations manual

*[Español](operations-manual.es.md)*

Deployment, tuning and diagnostics for open-shield.

---

## 1. Requirements

| | |
|---|---|
| System | Linux with Docker Engine 24+ and Compose v2 |
| Network | Public IP, DNS pointing at the server, ports 80/443 open |
| Resources | 1 vCPU and 1 GB of RAM are enough for the full stack under moderate traffic |
| Storage | The audit log grows continuously — see §6 |

The protected backend can be written in any technology: all it has to do is
expose an HTTP port reachable from the stack's network.

---

## 2. Installation

```bash
git clone <repository> && cd open-shield
cp deploy/.env.example deploy/.env
```

### 2.1 Secrets

All three are mandatory; the stack does not start without them.

```bash
openssl rand -base64 24     # → POSTGRES_PASSWORD
openssl rand -hex 32        # → OS_SESSION_SECRET
make hash-password PASSWORD='the administrator password'
```

The last command prints the complete line to paste into `deploy/.env`.

> **The `$$` in the hash are mandatory.** Docker Compose reads a lone `$` in a
> `.env` as the start of a variable. A bcrypt hash starts with `$2a$10$`, so
> pasting it unescaped makes the container receive an empty string — and the
> only symptom is that no password ever works.

### 2.2 The backend to protect

In `deploy/.env`:

```ini
OS_BACKEND_URL=http://my-application:8000
OS_SERVER_NAME=example.com
```

If the application already runs in another Compose stack, attach it to the
`openshield` network or publish its port on the host's internal network.

`OS_SERVER_NAME=_` accepts any `Host` header, which is what you want while
testing against `localhost` or an IP. In production, set the real domain.

### 2.3 Start

```bash
make up-prod                 # your backend
make up                      # with the bundled demo application
```

The engine applies migrations on startup; there is no manual schema step.

### 2.4 Verification

```bash
OS_ADMIN_PASSWORD='...' make smoke
```

Fourteen checks: legitimate traffic, SQLi and XSS filtering in the query and in
the body, rate limiting, dashboard authentication and chain integrity.

---

## 3. Tuning

Everything is configured through environment variables in `deploy/.env`. After
changing them: `docker compose -f deploy/docker-compose.yml up -d`.

### 3.1 Rate limiting

```ini
OS_RATELIMIT_REQUESTS=100
OS_RATELIMIT_WINDOW_S=60
```

It is a sliding window per source address, not a fixed window: a client cannot
send twice the limit by straddling the window boundary.

**How to choose the value.** Look at `Requests` in the dashboard over a normal
day and divide by the number of distinct visitors. Start at three or four times
that number. A page with many static assets burns through the budget quickly —
if the proxy also serves images and CSS, raise the limit.

**If it blocks legitimate users:** it is almost always NAT. A whole office, or
a mobile carrier, shares one public IP. Add their range to the allow list from
the **Rules** tab instead of raising the global limit.

### 3.2 Body inspection

```ini
OS_MAX_BODY_INSPECT_BYTES=8192
```

How many bytes of the body the `sqli` and `xss` rules examine. More coverage
costs more work on the request path. `0` disables body inspection (not
recommended: it is where a `POST` payload travels).

Bodies larger than `client_body_buffer_size` (64 KiB) are spilled to disk by
Nginx and reach the engine marked as truncated, instead of being re-read from
the filesystem.

### 3.3 Detection signatures

The SQLi and XSS signatures live in a versioned JSON file separate from the
code, so they can be updated without recompiling (§8.2). To replace them:

```yaml
# deploy/docker-compose.yml, engine service
volumes:
  - ./my-signatures.json:/etc/openshield/patterns.json:ro
environment:
  OS_PATTERNS_FILE: /etc/openshield/patterns.json
```

Start from `engine/internal/rules/patterns.json`. They are RE2 expressions: no
backreferences, linear time, no catastrophic backtracking — important, because
they run on attacker-controlled input.

A malformed signature **prevents the engine from starting**, deliberately: it is
better than failing silently on real traffic.

### 3.4 Failure behavior

```ini
OS_FAIL_MODE=open
OS_DECIDE_TIMEOUT_MS=150
```

`open` (the default) lets the request through if the engine does not answer in
time, and logs it. `closed` responds 503.

Choose `closed` only where an unfiltered request is worse than an unserved one.
For a public site with a 99% availability target, `open` is the right choice.

---

## 4. Day-to-day operation

### 4.1 The dashboard

`http://<server>:8081`

| Tab | What for |
|---|---|
| **Live** | Volume, block rate, top IPs and top-firing rules, and the real-time decision feed |
| **Audit** | The full history, filterable by kind, outcome and IP. Each row expands to show its payload and hashes |
| **Rules** | Enable and disable rules, and manage the IP access list |
| **Forensics** | Integrity chain verification |

The connection indicator next to the window selector tells an idle system from
one without a feed. If it says *Reconnecting…* for more than a minute, check
Redis.

### 4.2 Blocking an attacker

**Rules** tab → *IP access list*. A single address or a CIDR is accepted; an
`allow` entry wins over a `block` entry, so you can block a whole range and let
a specific address inside it through.

The change reaches the engine in under a second over the Redis control channel,
and as a fallback the engine re-reads the configuration every 30 seconds.

### 4.3 Investigating a complaint

When a user reports being blocked, the block page shows them an identifier.
With it:

**Audit** → filter by IP, or directly:

```bash
curl -s -b cookies.txt \
  "http://localhost:8081/api/v1/events?request_id=<the-identifier>"
```

The same identifier travels in the `X-Request-ID` header to the backend and
appears in the proxy's operational log, so the request can be followed across
all three layers.

### 4.4 Verifying integrity

**Forensics** tab → *Verify chain*. With no dates, the whole history is
verified.

Do it routinely, and always before using the log as evidence of an incident. If
the result is `Chain broken`, the report names the exact entry, its position
and what failed: a hash mismatch means modified content; a broken link means a
record was deleted, reordered or inserted.

---

## 5. Performance

### 5.1 Measured latency

Measured on the demo stack (Docker Desktop, WSL2), 100 requests per target,
from inside the stack's network:

| | p50 | p95 |
|---|---|---|
| Backend directly | 1.29 ms | 1.76 ms |
| Through the proxy, full chain | 2.63 ms | 3.41 ms |
| **Added overhead** | **+1.3 ms** | **+1.7 ms** |

Against the **< 50 ms** budget of §8.2, that leaves a margin of more than an
order of magnitude.

The numbers in the table come from a manual `curl` measurement, kept as a
historical reference. To repeat it reproducibly:

```bash
make up-load     # the stack with rate limiting disabled for measurement
make test-load   # k6, four scenarios, ~1 minute
```

The run prints the same comparison and exits non-zero if the overhead falls
outside the §8.2 budget. `make test-load-full` runs the nine-minute version.

Rate limiting is disabled during measurement on purpose: the engine identifies
the client by source address, every virtual user comes from a single one, and
with the default limit the run would throttle itself and measure the limiter.
See `docs/testing-strategy.md` §4.5.

### 5.2 Where the overhead comes from

One HTTP call to the engine over a reused connection, one evaluation of the
rule chain and, for rate limiting, one Redis round trip. Writing the log is
**not** on the path: the verdict returns before it starts.

If latency goes up:

- **Large bodies** — scanning is proportional to `OS_MAX_BODY_INSPECT_BYTES`.
  Lower it.
- **Slow Redis** — only affects the `ratelimit` rule. `docker stats redis`.
- **Expensive custom signatures** — a pattern with nested alternations can be
  costly even in RE2. Measure before and after.

### 5.3 Audit queue

`OS_AUDIT_BUFFER=4096` is the depth of the queue between the request path and
the database. If it fills, entries are dropped and counted; a request is never
blocked on writing the log.

The `dropped` counter is on `/api/v1/status`. If it grows, the database is not
keeping up with the traffic: check disk I/O before raising the buffer, because
a larger buffer only delays the moment it starts dropping.

---

## 6. Maintenance

### 6.1 Log growth

Every request produces an entry. Under continuous traffic the log grows
steadily and **cannot be pruned**: deleting rows breaks the chain, exactly as
an attacker would.

```sql
SELECT pg_size_pretty(pg_total_relation_size('audit_log')),
       count(*), min(ts), max(ts)
FROM audit_log;
```

When archiving is needed, the correct procedure is to **export the complete
span with its hashes** (so it stays independently verifiable) and only then
recreate the volume. The new chain starts from the genesis hash, and that
discontinuity is documented by the exported archive.

### 6.2 Backups

```bash
docker compose -f deploy/docker-compose.yml exec -T db \
  pg_dump -U openshield openshield | gzip > audit-$(date +%F).sql.gz
```

Verify the chain **before** every backup: a backup of an already corrupted log
preserves the corruption.

Redis needs no backup. It only holds rate limiting counters and the event
channel, both rebuildable; that is why its persistence is disabled.

### 6.3 Upgrades

```bash
git pull
docker compose -f deploy/docker-compose.yml up -d --build
```

Migrations apply themselves when the engine starts, under a PostgreSQL lock, so
several instances starting at once do not race.

The audit log survives the upgrade: it lives in the `db-data` volume.
`make clean` **does** delete it.

### 6.4 Rotating the session secret

Changing `OS_SESSION_SECRET` invalidates every open session. It is the way to
sign everyone out after a suspected compromise.

---

## 7. Diagnostics

### The proxy responds 502

The backend is not reachable from the stack's network.

```bash
docker compose -f deploy/docker-compose.yml exec proxy \
  curl -sv "$OS_BACKEND_URL" 2>&1 | head -20
```

Check that `OS_BACKEND_URL` uses the service name, not `localhost`: inside a
container, `localhost` is the container itself.

### Everything passes unfiltered

The engine is down and `OS_FAIL_MODE=open` is doing its job. Look for
`engine unreachable` in the proxy logs:

```bash
docker compose -f deploy/docker-compose.yml logs proxy | grep openshield
docker compose -f deploy/docker-compose.yml logs engine | tail -40
```

### The dashboard rejects the correct password

It is almost always the `$` escaping (§2.1). Check what reaches the container:

```bash
docker compose -f deploy/docker-compose.yml exec dashboard-api \
  sh -c 'echo "$OS_ADMIN_PASSWORD_HASH"'
```

It must start with `$2a$`. If it is empty or truncated, the `$$` are missing.

The other cause is `OS_SECURE_COOKIES=true` served over plain HTTP: sign-in
appears to work and the session does not persist, because the browser never
sends the cookie back. Leave it `false` until TLS exists.

### The live feed shows nothing

The engine publishes to Redis and the dashboard subscribes. With the stack up:

```bash
docker compose -f deploy/docker-compose.yml exec redis \
  redis-cli SUBSCRIBE openshield:events
```

If events appear there and not in the browser, the problem is the WebSocket
(check the browser console). If they do not appear there either, the engine is
not publishing.

### The engine does not start

It is almost always configuration: a mandatory variable is missing, or a
signature in the patterns file does not compile. The error says so explicitly:

```bash
docker compose -f deploy/docker-compose.yml logs engine | tail -20
```

---

## 8. Securing the system itself

- **Only the proxy and the dashboard publish ports.** The engine, Redis and
  PostgreSQL live on the internal network. Do not expose them.
- **Restrict access to the dashboard.** It can change what the proxy blocks, so
  reaching it is equivalent to getting through the proxy. Put it behind a VPN
  or limit `OS_DASHBOARD_PORT` to the management network with the host
  firewall.
- **The perimeter firewall is still necessary.** The proxy protects web
  traffic; it does not stop someone from reaching the backend directly by
  another route. Close everything other than 80 and 443 to the outside.
- **Every administrative action is logged** in the same chain, with its actor.
  If the entry cannot be written, the change is not applied.

---

## 9. Rollback

The proxy is a layer in front of the backend, so rolling back means taking it
out of the way:

```bash
docker compose -f deploy/docker-compose.yml stop proxy
```

and pointing DNS or the firewall back at the backend directly. The backend was
never modified, so there is nothing to undo on it.

The audit log stays in the volume and remains verifiable.
