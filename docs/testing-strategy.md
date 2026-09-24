# Testing strategy

*[Español](testing-strategy.es.md)*

This document describes open-shield's test suite: which levels exist, what each
one guarantees, how to run them and how they block a pull request from merging.

§2 of the technical document sets as its third objective *"validate the system
through load testing and controlled attack simulations"*, and §8.2 puts numbers
on it: less than **50 ms** of added latency and **≥ 99 %** availability. This
module turns those two sentences into something that can fail a build.

---

## 1. The levels

| Level | Where it lives | What it guarantees | Dependencies | Duration |
|---|---|---|---|---|
| **Unit** | next to the code, `*_test.go` | hash chain invariants, detection rules, parsing, HTTP layers with doubles | none | < 5 s |
| **Fuzzing** | `internal/model/fuzz_test.go` | that the hash survives any input, not just the ones someone thought of | none | seeds in the gate; 5 min per target nightly |
| **Integration** | `test/integration/` and next to the `internal` packages | real SQL, migrations, the sliding window on real Redis, Pub/Sub | PostgreSQL + Redis | ~10 s |
| **End-to-end** | `test/e2e/` | the full path: proxy → engine → log → dashboard | the stack in Docker | ~10 s |
| **Load and stress** | `test/load/k6/` | the §8.2 budget, translated into k6 thresholds | the stack in Docker | 1 min / 9 min / 30 min |
| **Frontend** | `dashboard/web/src/**/*.test.tsx` | the live feed, the API client, the forensic table | Node | ~6 s |

### The pyramid, in one line

What is cheap and dependency-free always runs; what is expensive runs once per
PR; what is slow runs nightly. Nothing is run by hand by convention.

---

## 2. The shared corpus

`test/corpus/` holds two JSON files:

- **`attacks.json`** — 17 SQLi and XSS vectors, each with the rule and the
  signature that *must* fire.
- **`benign.json`** — 15 legitimate requests that look like an attack and must
  **not** be blocked.

Three different levels consume them:

```
test/corpus/*.json
   ├──► engine/internal/rules/corpus_test.go   the rule chain, in isolation
   ├──► test/e2e/                              the live stack, through the proxy
   └──► test/load/k6/main.js                   the "attack" scenario under load
```

Adding a vector means editing a JSON file, and it is covered in all three
places at once. There is no way for one of the three to fall behind.

### Why the benign corpus matters as much as the attack one

The false-positive budget is **zero**. A filter that blocks `O'Brien` at sign-in,
or an article about the European Union, ends up disabled by the operator — and
then it detects nothing at all. Several cases in `benign.json` are adversarial
on purpose: they contain the same words the signatures look for, in contexts
where they are harmless.

### How to add a vector

1. Add the case to `test/corpus/attacks.json`:

   ```json
   {
     "id": "sqli_descriptive_name",
     "description": "What it is, in readable text",
     "rule": "sqli",
     "signature": "union_select",
     "method": "GET",
     "path": "/search",
     "query": "q=x%27%20UNION%20SELECT..."
   }
   ```

2. `query` is written **as it travels on the wire**, percent-encoded. It is
   what Nginx hands the engine and what an HTTP client will transmit untouched.
   Several vectors are only detectable after the engine decodes the field, and
   that is deliberate: it exercises the decoding pass of `scanTargets`.

3. `signature` pins **which specific signature** must fire. Signatures are
   evaluated in file order for each field, so a case has to be written to reach
   its own and not an earlier one. If it starts matching another, the test
   fails — and that is correct: it is a real change in what the log will say
   about that attack.

4. Run `make test`. If it fails with *"blocked by X, want Y"*, the payload is
   triggering an earlier signature; adjust it until it only triggers its own.

5. If the vector resembles real traffic, also add the equivalent legitimate
   case to `benign.json`.

> **Observed trap.** A case with `url=javascript%3Aalert(document.cookie)`
> does not fire `javascript_uri` but `cookie_theft`: `document.cookie` appears
> unencoded in the **raw** field, and the raw field is scanned before the
> decoded one. Keep each vector free of any other payload.

---

## 3. Running each level

Go is not needed on the machine: everything runs in containers.

```bash
make test              # unit + go vet. No dependencies. Seconds.
make test-race         # the same with the race detector.
make lint              # gofmt, go vet and golangci-lint.
make vuln              # known CVEs in the dependencies.

make test-integration  # brings up ephemeral PostgreSQL and Redis, runs, tears them down.
make cover             # per-package coverage against test/coverage-floors.txt.

make up-e2e                                  # the stack with the E2E settings
OS_ADMIN_PASSWORD='...' make test-e2e        # the full path

make up-load           # the stack with the load settings
make test-load         # k6, short profile (~1 min)
make test-load-full    # k6, full profile (~9 min)
make test-soak         # k6, soak (30 min)

make test-web          # types and tests for the React dashboard

make test-all          # everything that does not need the stack running
```

### Integration tests skip themselves

Without `OS_TEST_POSTGRES_DSN` and `OS_TEST_REDIS_ADDR` set, the whole
integration suite is skipped with a message explaining how to bring up the
dependencies. It never fails on a machine that simply does not have them
running.

`make test-integration` brings them up with `deploy/docker-compose.test.yml`,
on high ports (55432 and 56379) so a test run does not collide with a demo
stack someone left running.

### Why `-p 1` for integration

The suite is split across three directories because Go's `internal` rule
forces it: only code under `engine/` can import `engine/internal/…`, and only
code under `dashboard/api/` can import `dashboard/api/internal/…`. All three
share a single database. Without `-p 1`, the test binaries run in parallel and
empty each other's tables mid-run; the resulting failures make no sense at all.
The shared helpers live in `test/harness/`.

---

## 4. What each level checks, concretely

### 4.1 Unit — the forensic core

`internal/model` and `internal/audit` are the project's core contribution, and
their tests are the protection of that claim:

- The hash is **deterministic** over 1,000 recomputes, independent of map
  iteration order, time zone and a JSON round trip.
- Fields are **length-prefixed**: no different partition of the same bytes
  produces the same digest. A fuzzing target checks it against every possible
  split of each generated entry.
- There is **only one** writer: 1,000 goroutines calling `Record` produce a
  strictly linear chain under `-race`. Two writers sealing against the same
  head would fork it, and verification would report tampering where there was
  none.
- With the queue full, entries are **dropped and counted**, never blocked.
  §8.2 budgets less than 50 ms of added latency; blocking a request to write
  the log would turn an audit backlog into a site outage.
- A rejected write **does not advance the head**: the next entry links to the
  last one that actually went in.

### 4.2 Unit — the contract with the Lua hook

`engine/internal/httpapi` is the boundary between `proxy/lua/openshield.lua`
and the engine, and there is nothing else on the request path. Its tests pin
the shape of the verdict, the echo of `X-Request-ID`, the size limits and —
above all — the **negative invariant**: the audited payload never contains the
request body, the `Cookie` header, or `Authorization`.

### 4.3 Integration — what only exists with a database behind it

- **Store parity**: the same writes must produce entries that re-hash correctly
  both in memory and in PostgreSQL. This is what proves that the microsecond
  truncation and `NormalizePayload` survive the trip through `timestamptz` and
  `jsonb`.
- **Row-level tamper detection**: an `UPDATE`, a `DELETE` in the middle and a
  resealed entry. All three are detected and verification names the exact
  entry. It is `scripts/tamper-demo.sh` turned into a test.
- **The append-only trigger**: the database rejects `UPDATE`, `DELETE` and
  `TRUNCATE` on `audit_log`. The chain makes tampering *detectable*; the
  trigger makes it inconvenient.
- **Migrations**: idempotent, in name order, transactional, and serialized by
  the advisory lock when two containers start at once.
- **Chain order is `seq`, not `ts`**: 25 entries sharing the same instant
  verify correctly.

### 4.4 End-to-end — the evidence loop

The test that justifies the whole project:

```
attack → 403 with X-Request-ID
       → GET /api/v1/events?request_id=…
       → the entry names the rule, the IP and the fragment that fired
       → GET /api/v1/audit/verify is still ok:true
```

RF-03 and RF-06 together. Alongside it:

- **What is not persisted**: a `POST` with `Cookie`, `Authorization` and a
  password in the body; none of the three appears in the logged event.
- **The Lua contract**: the event arriving with `ip`, `method`, `path` and
  `host` populated proves that `openshield.lua` fills them in. The Lua script
  has no tests of its own; it is covered here (see §7).
- **RF-05**: a burst from one IP produces 429.

### 4.5 Load — §8.2, executable

`test/load/k6/main.js` runs four scenarios **in sequence**, not in parallel:

| Scenario | Against | What for |
|---|---|---|
| `baseline` | `demo-backend` directly | the reference |
| `proxied` | the proxy, legitimate traffic | subtracting `baseline` gives the real overhead |
| `attack` | the proxy, attack corpus | that filtering still works under load |
| `mixed` | the proxy, 95 % legitimate / 5 % attack | the shape of real traffic |

They run in sequence because in parallel they would compete for the same CPU
and the difference would measure contention, not the system.

The thresholds (`test/load/k6/thresholds.js`) make k6 exit non-zero:

```js
'http_req_duration{scenario:proxied}': ['p(95)<50'],   // §8.2: < 50 ms
'http_req_failed{scenario:proxied}':   ['rate<0.01'],  // §8.2: ≥ 99 %
'checks{scenario:attack}':             ['rate>0.99'],  // RF-03
```

The last one matters most and is the easiest to forget: a proxy that got fast
by skipping the rule chain under pressure would pass every latency threshold.

At the end, the summary prints the comparison:

```
                                p50          p95
Backend directly              0.48 ms     1.04 ms
Through the proxy             2.01 ms     7.60 ms
----------------------------------------------------
Added overhead                1.52 ms     6.56 ms
```

Compare it with the table in §5.1 of the operations manual.

> **Why load needs its own override.** The engine identifies the client by
> `ngx.var.remote_addr` (`proxy/lua/openshield.lua:141`), not by
> `X-Forwarded-For` — a header the client controls is no use for counting.
> Every k6 virtual user comes from a single address and shares one bucket:
> with the default limit the run would throttle itself within the first
> second, and the result would measure the rate limiter.
> `deploy/docker-compose.load.yml` effectively disables it. **RF-05 is not
> covered there**: it is covered in E2E and in `smoke.sh`, against a real
> limit.

### 4.6 Frontend

- `useLiveEvents`: reconnection with exponential backoff, a 200-event cap,
  surviving a malformed frame, and cleanup on unmount. A feed that does not
  reconnect goes silent, and silence is indistinguishable from "no traffic" —
  the worst possible failure in a monitoring tool.
- `api.ts`: the session cookie travels on every request, a 4xx reaches the
  caller as an error carrying the API's message, and the delete's 204 is not
  parsed as JSON.
- `EventTable`: attacker-controlled payloads are rendered **as text, never as
  markup**. It is the test that will notice the day someone reaches for
  `dangerouslySetInnerHTML`.

---

## 5. Coverage

`scripts/coverage.sh` measures statement coverage **per package** and checks it
against the floors in `test/coverage-floors.txt`.

Per package rather than one global number: a single total lets a large,
well-covered package hide a small untested one. The floors are not uniform
either — the forensic core and the request path are held high because a gap
there is a gap in what the project claims to do; glue code is held low because
chasing its last statements buys nothing.

The floors are **measured**, not aspirational: each sits a few points below
what the suite actually reaches. A threshold that is born red gets disabled
within a week, and then it protects nothing.

Coverage is measured **with the dependencies up**, in the integration job.
Measuring without them would leave `internal/audit` at roughly half its real
figure: its SQL store is most of the file.

To raise a floor: `make cover`, take the measured value, subtract a few points.
To lower one: explain why in the commit message.

---

## 6. The CI gate

`.github/workflows/ci.yml` runs on every pull request. **All six checks are
required.**

| Check | What it does | Approx. duration |
|---|---|---|
| `lint` | `gofmt`, `go vet`, `golangci-lint` | ~1 min |
| `unit` | the whole suite, and again with `-race` | ~2 min |
| `vuln` | `govulncheck` over dependencies and toolchain | ~1 min |
| `integration` | real PostgreSQL and Redis + the coverage floors | ~3 min |
| `web` | types, tests and build of the dashboard | ~2 min |
| `stack` | real containers: E2E, smoke, short load and tamper demo | ~8 min |

`.github/workflows/nightly.yml` runs in the early hours and on demand: 5-minute
fuzzing per target, full load, 30-minute soak, integration with the race
detector, and chain verification over 200,000 entries.

### The Go jobs call the same Makefile targets

With `GO_RUN=` empty, `$(GO_RUN) sh -c "…"` degrades to native execution
against `actions/setup-go`. A single place defines what "the tests pass" means,
and it cannot drift between a developer's machine and the runner.

### The `.env` in CI

There is no `deploy/.env` in the repository and there never should be. The
`stack` job generates it with throwaway secrets.

The bcrypt hash is produced with `-hash-password`, which **already prints the
line with the `$` escaped as `$$`**. Compose reads a lone `$` as a variable
reference, so pasting the raw hash delivers an **empty** value to the
container, with no error, and every sign-in fails. The workflow checks the
escaping before spending eight minutes discovering it on the login screen.

### Making the checks actually block

A workflow does not prevent merging on its own. The checks have to be marked as
required in the branch protection:

```bash
gh api -X PUT repos/MJoDev/open-shield/branches/main/protection \
  --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["lint", "unit", "vuln", "integration", "web", "stack"]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": null,
  "restrictions": null
}
JSON
```

`strict: true` also requires the branch to be up to date with `main` before
merging, which is what stops two PRs that are green separately from breaking
`main` together.

### Checking that the gate bites

A gate that has never been seen failing is untested. To check it:

```bash
# The latency budget is overridable precisely for this.
OS_LOAD_LATENCY_BUDGET_MS=3 make test-load   # exits with code 99
```

For the rest, flip a byte in `internal/model/audit.go` (`Seal`) on a throwaway
branch and open a test PR: `unit` and `stack` must go red.

---

## 7. What is not tested, and why

- **The Lua script has no unit tests.** Setting up a Lua harness (busted,
  `resty`) for 194 lines that contain no filtering logic — they collect data,
  ask, and act on the answer — would cost more than it protects. It is covered
  by E2E, which checks that the fields it fills in arrive populated in the log
  and that `OS_FAIL_MODE=open` is honored.
- **`engine/cmd/engine` and `dashboard/api/cmd/api` have no coverage floor.**
  They are process wiring; a unit test there would only assert that `main()`
  calls what `main()` calls. The end-to-end level covers them, since it starts
  the real binaries.
- **Extreme numeric magnitudes.** `encoding/json` writes a float in exponential
  notation as soon as its exponent reaches 21 or drops below −6: `1e21`
  serializes as `"1e+21"`, and `jsonb` returns `"1000000000000000000000"`. The
  two texts canonicalize differently, so the hash recomputed on read does not
  match the sealed one and `VerifyChain` reports tampering on a log nobody has
  touched. No current payload comes close to either threshold (`decision_ms`
  is single-digit milliseconds, `status` three digits), and fixing it would
  change what is hashed, invalidating every existing chain. It is pinned as a
  known limit in `TestExtremeMagnitudesAreOutsideTheChainsRange` and noted in
  `implementation-decisions.md`.

---

## 8. References

- `docs/technical-document.md` §2 (objectives), §8.2 (non-functional requirements)
- `docs/implementation-decisions.md` — where and why the code departs
- `docs/operations-manual.md` §5 — performance measured in production
- `test/coverage-floors.txt` — the floors, with the reasoning for each
