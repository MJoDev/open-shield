---
title: "Deploying open-shield on Railway"
project: "open-shield"
date: "2026-09-25"
language: "en"
---

# Deploying open-shield on Railway

The `docker compose` install in the operations manual assumes one host you own:
the proxy binds port 80, Docker's embedded DNS resolves the backend, and the
address that opens the connection is the client's. A managed platform breaks all
three assumptions at once, and the failures are quiet rather than loud — the
stack starts, serves traffic, and protects nothing.

This document is the worked example for that topology, using Railway. The
settings it introduces are not Railway-specific: the same four apply behind Fly,
Cloud Run, an ALB or Cloudflare. They are documented one by one in
`deploy/.env.example`.

---

## 1. The topology

```
internet ──► Railway edge (TLS)
                 │
                 ├──► proxy      ──► rack-backend.railway.internal   [no public domain]
                 │      │
                 │      └──► engine.railway.internal:8080 ──► Postgres + Redis
                 │
                 ├──► dashboard  (own public domain, session auth)
                 └──► rack-frontend  (static SPA, public)
```

Only the API sits behind the filter. The SPA is static assets: no parser, no
database, nothing to inject into — and putting it behind the proxy would spend
the rate-limit budget of every visitor on a burst of asset requests, forcing the
limit so high it stops being a limit. That trade-off is the reason the budget in
§4 can stay tight enough to matter.

**The step that makes this real is removing the public domain from
`rack-backend`.** An origin that stays directly addressable turns the proxy into
decoration; every rule in the chain is bypassed by typing the old URL.

All services must live in **one Railway project**: private networking
(`*.railway.internal`) does not cross project boundaries.

---

## 2. Before you start

- Run `make up && make smoke` locally once. The proxy image is shared by both
  topologies, so a configuration error is far cheaper to find on your machine
  than in a container that will not boot on a platform.
- Two secrets, generated locally and pasted into Railway, never committed:

  ```bash
  make hash-password PASSWORD='the password you will sign in with'
  openssl rand -hex 32     # OS_SESSION_SECRET
  ```

  `make hash-password` prints two forms. The escaped one, with every `$` doubled,
  exists only because Docker Compose reads `$` in a `.env` file as a variable
  reference. **Railway does not. Paste the line labelled "el hash real es",
  unescaped** — doubling it there produces a hash that matches no password and a
  sign-in screen that simply never accepts you.

---

## 3. Private networking is IPv6-only

A process listening on `0.0.0.0` receives nothing from another Railway service.
Both applications need one line changed before they are reachable by the proxy.

`rack-backend`, in `Procfile`:

```
web: python manage.py migrate --noinput && gunicorn core.wsgi --bind [::]:$PORT --log-file -
```

`rack-frontend`, in `package.json`:

```json
"start": "serve -s dist -l tcp://[::]:$PORT"
```

Set `PORT` explicitly as a service variable on each (`8000` and `3000` below).
Without a public domain the platform does not always inject it, and the proxy
needs a port it can count on.

---

## 4. The services

Create them in this order; each one's private address is needed by the next.

### 4.1 Datastores

Add a **PostgreSQL** and a **Redis** from Railway's catalogue. Name them
`postgres` and `redis`. Nothing else: the engine applies its own migrations at
startup.

### 4.2 `engine`

From the `open-shield` repository. Settings: root directory `/`, Dockerfile path
`engine/Dockerfile`, health check path `/readyz`, watch paths `engine/**`,
`internal/**`, `migrations/**`, `go.*`. **No public domain, ever** — the engine
answers verdicts without authentication, because its only reachable caller is
supposed to be the proxy.

```
OS_POSTGRES_DSN=${{Postgres.DATABASE_URL}}
OS_REDIS_ADDR=${{Redis.REDISHOST}}:${{Redis.REDISPORT}}
OS_REDIS_PASSWORD=${{Redis.REDISPASSWORD}}
OS_ENGINE_ADDR=:8080
OS_RATELIMIT_REQUESTS=120
OS_RATELIMIT_WINDOW_S=60
OS_MAX_BODY_INSPECT_BYTES=8192
OS_AUDIT_BUFFER=4096
OS_EVENTS_CHANNEL=openshield:events
OS_LOG_LEVEL=info
```

Check the datastore's own Variables tab for the exact reference names; they vary
between template versions.

On `OS_RATELIMIT_REQUESTS`: 120/min is a starting point for an API behind a SPA,
not a measurement. Watch the dashboard for a week and set it from the busiest
legitimate session you observe, with room to spare. A limit that blocks real
users gets switched off, and a limit that is switched off stops nothing.

### 4.3 `dashboard`

Same repository. Root directory `/`, Dockerfile path `dashboard/api/Dockerfile`,
health check path `/healthz`, watch paths `dashboard/**`, `internal/**`, `go.*`.
Generate a public domain with target port `8081`.

```
OS_POSTGRES_DSN=${{Postgres.DATABASE_URL}}
OS_REDIS_ADDR=${{Redis.REDISHOST}}:${{Redis.REDISPORT}}
OS_REDIS_PASSWORD=${{Redis.REDISPASSWORD}}
OS_ENGINE_URL=http://engine.railway.internal:8080
OS_DASHBOARD_ADDR=:8081
OS_ADMIN_USER=admin
OS_ADMIN_PASSWORD_HASH=<the raw bcrypt hash>
OS_SESSION_SECRET=<openssl rand -hex 32>
OS_SESSION_TTL_S=28800
OS_SECURE_COOKIES=true
```

`OS_SECURE_COOKIES=true` is correct here and only here: the platform serves this
domain over HTTPS. The warning in the operations manual applies to plain HTTP,
where the same setting makes sign-in appear to succeed and then silently fail.

The dashboard reads the entire audit log, which makes it the most sensitive
surface in the deployment — a single password with no second factor. If you run
anything in front that can authenticate before the request arrives, put it there.

### 4.4 `rack-backend`

From its own repository, with `PORT=8000`. Then **Settings → Networking → remove
the public domain.** Skipping this leaves every rule in the chain bypassable.

### 4.5 `rack-frontend`

From its own repository, with `PORT=3000`. Keeps its public domain; `VITE_API_URL`
is filled in §5.

### 4.6 `proxy`

From the `open-shield` repository, third service. Root directory `/proxy`, watch
paths `proxy/**`, health check path `/__openshield/health`, public domain with
target port `80`.

```
OS_BACKEND_URL=http://rack-backend.railway.internal:8000
OS_ENGINE_URL=http://engine.railway.internal:8080
OS_SERVER_NAME=_
OS_RESOLVER_IPV6=on
OS_TRUSTED_PROXY=0.0.0.0/0 ::/0
OS_REAL_IP_HEADER=X-Envoy-External-Address
OS_FAIL_MODE=open
OS_DECIDE_TIMEOUT_MS=150
OS_MAX_BODY_INSPECT_BYTES=8192
```

Four of these carry the whole difference between topologies, and three of them
fail silently if they are wrong:

- **`OS_RESOLVER_IPV6=on`** — `*.railway.internal` publishes AAAA records only.
  Left `off`, every request returns 502 with "host not found in upstream".
  This one at least fails loudly.
- **`OS_TRUSTED_PROXY`** — without it `remote_addr` is the platform edge, so
  `ipblock` and `ratelimit` key the entire internet to a single address. The
  rules keep running and keep reporting; they simply protect nothing.
- **`OS_REAL_IP_HEADER=X-Envoy-External-Address`** — the header Railway's edge
  writes with the real client address. `X-Forwarded-For` is a list a client can
  prepend to, so trusting *that* from `0.0.0.0/0` would let an attacker forge the
  address an `ipblock` rule is keyed on, or get a third party blocked.
- The listening port needs nothing: the platform injects `PORT` and the
  entrypoint follows it.

`OS_FAIL_MODE=open` stays open. Flipping it to `closed` means a restart of the
engine takes the API down with it.

---

## 5. Rewire

1. Copy the proxy's domain. In `rack-frontend`, set
   `VITE_API_URL=https://<proxy-domain>` and **redeploy** — Vite bakes this in at
   build time, so without a rebuild the SPA keeps calling the old address and the
   whole deployment looks like it works while bypassing the filter entirely.
2. In `rack-backend`, add the proxy and frontend domains to `CORS_ALLOWED_ORIGINS`
   and `CSRF_TRUSTED_ORIGINS`.
3. Decide on `SECURE_PROXY_SSL_HEADER`. The proxy forwards `X-Forwarded-Proto`,
   relaying only `http` or `https` and falling back to its own scheme otherwise.
   That keeps a malformed header out of the backend but does **not** make the
   value trustworthy on its own: it is trustworthy exactly when an edge in front
   overwrites it, which is the condition `OS_TRUSTED_PROXY` declares. Behind the
   platform edge, set it; on a bare VPS with the proxy exposed directly, do not.

---

## 6. Verify

The smoke script takes both base URLs, so it works against the deployment
unchanged:

```bash
OS_ADMIN_PASSWORD='...' ./scripts/smoke.sh https://<proxy-domain> https://<dashboard-domain>
```

Then confirm by hand that the filter is actually filtering, and — more
importantly — that it sees real client addresses:

```bash
curl -i "https://<proxy-domain>/?q=%27%20OR%201=1--"          # 403, carries X-Request-ID
curl -i "https://<proxy-domain>/?q=%3Cscript%3Ealert(1)%3C/script%3E"   # 403

for i in $(seq 1 200); do
  curl -s -o /dev/null -w "%{http_code}\n" "https://<proxy-domain>/"
done | sort | uniq -c                                          # 429s appear
```

In the dashboard: events arriving live, `GET /api/v1/audit/verify` reporting an
intact chain, and `dropped` at 0 on `/api/v1/status`.

**Then look at the source addresses in the event list.** If every entry shows the
same address, `real_ip` is not working — recheck `OS_TRUSTED_PROXY` and
`OS_REAL_IP_HEADER`. Everything else will look perfectly healthy while the rate
limit and the IP list are inert, which is why this check is worth more than the
403s above.

---

## 7. Custom domains

Point `api.example.com` at the proxy and `app.example.com` at the frontend;
Railway issues the certificates. Then set `OS_SERVER_NAME=api.example.com` on the
proxy so it stops accepting any `Host` header, and update `VITE_API_URL`,
`CORS_ALLOWED_ORIGINS` and `CSRF_TRUSTED_ORIGINS` to match.

This is also where RF-04 is satisfied: TLS is terminated and renewed at the
platform edge rather than by certbot inside the container. The commented `443`
block in the proxy template stays commented — it exists for the single-VPS
topology, which this document is not.

---

## 8. What this deployment does not give you

- **Volumetric denial of service** is absorbed, or not, by the platform edge.
  A flood still consumes the project's bandwidth and compute; the engine records
  that it blocked the requests.
- **The audit log cannot be pruned.** It now lives in a managed Postgres and
  grows without bound. Deleting rows breaks the chain exactly as an attacker
  would. Budget for it.
- **Traffic inside the project is unencrypted** — edge to proxy, and proxy to
  origin, both travel in clear over private networking. The same is true of the
  `docker compose` install, but it is worth writing down.
- **The filter's coverage is measured, and partial.** See
  `filtering-coverage-findings.md`: obfuscated variants of the corpus vectors
  pass, and three attack classes have no signature yet. Deploying this is
  strictly better than an unfiltered origin, and it is not the same as being
  covered.
