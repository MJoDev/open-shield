# Implementation decisions

*[Español](implementation-decisions.es.md)*

A record of where the code departs from the
[technical document](technical-document.md), and why. The technical document
remains the design; this is what was found while building it.

Section references (§) point to the technical document.

---

## 1. `access_by_lua` instead of `auth_request` (§3.2, §4.4, §7.2)

**The document:** Nginx calls the engine through an internal `auth_request`
subrequest.

**The code:** `access_by_lua` with a bounded read of the body.

**Why:** Nginx's `auth_request` module **discards the request body** — the
authorization subrequest only receives headers. RF-03 requires filtering SQLi
and XSS payloads, and in a `POST` those payloads travel in the body. With
`auth_request`, the `sqli` and `xss` rules would have been blind to the most
common vector.

The technology decision in §4.4 does not change: it is still Lua on
Nginx/OpenResty, with the proxy as a thin layer that delegates. Only the
invocation mechanism changes, and it saves the internal subrequest as well.

The test that verifies it lives in `scripts/smoke.sh`:
`XSS in the POST body → 403`.

**Operational consequence:** the body is read up to
`OS_MAX_BODY_INSPECT_BYTES` (8 KiB by default). Beyond
`client_body_buffer_size`, Nginx spills the body to disk and the engine
receives it marked as truncated, rather than reading it back from the
filesystem on the request path.

---

## 2. The hash function in §6.2 is not deterministic

**The document:**

```go
raw := e.PrevHash + e.Timestamp.String() + fmt.Sprint(e.Payload)
```

**The problem:** `Payload` is a `map[string]any`, and Go randomizes map
iteration order on every run. The same record produces a different hash every
time it is computed. In other words: `VerifyChain` would report tampering on a
perfectly intact chain, and the whole forensic mechanism of §6 — the core
contribution of the proposal — would not work.

`Timestamp.String()` adds a second, smaller problem: its output depends on the
time zone and on whether the `time.Time` carries a monotonic clock reading.

**The code:** canonical encoding in `internal/model/canonical.go`.

```
hash = sha256( prevHash | id | requestID | ts | kind | canonicalJSON(payload) )
```

- Canonical JSON: keys sorted recursively, no whitespace, no HTML escaping.
- Timestamp in `RFC3339Nano`, normalized to UTC.
- Each field is preceded by its length in 8 bytes, so no combination of values
  can be reinterpreted as a different set of fields (`{"ab","c"}` and
  `{"a","bc"}` must hash differently).
- `ID`, `RequestID` and `Kind` are part of the hash. In the sketch they were
  left out and could be rewritten without breaking the chain.

The tests in `internal/model/audit_test.go` cover each of these properties,
including determinism over 1,000 recomputes.

### 2.1 Normalization before sealing

The payload is normalized (`NormalizePayload`) before the hash is computed:
every number becomes a `json.Number`, keeping its literal. Without this, a
`float64` sealed as `1.50` could be read back from PostgreSQL as `1.5` and
break verification without anyone having touched anything.

### 2.2 Truncation to microseconds

PostgreSQL's `timestamptz` stores microseconds. The writer truncates the
timestamp to microseconds **before** sealing, so that the hashed value is
exactly the one that comes back on a read.

---

## 3. `audit` moves from `engine/internal/` up to the root `internal/` (§7)

**The document:** `engine/internal/audit/`.

**The problem:** in Go, a package under `engine/internal/` can only be imported
from `engine/…`. The dashboard needs `AuditEntry` and chain verification for
the forensic view, so the proposed tree does not compile.

**The code:** the shared packages (`model`, `audit`, `events`, `config`,
`migrate`, `rulestore`) live in the module's root `internal/`. The ones private
to the engine (`rules`, `ratelimit`) stay in `engine/internal/`. The
document's conceptual separation is preserved.

The interface is named `audit.Repository` rather than `AuditRepository`, to
avoid repeating the package name. Its two methods from §5.3 are intact;
`VerifyChain` returns a `VerifyResult` instead of a `bool` because, faced with
a broken chain, the operator's first question is *where*, and only the store
can answer it while it walks the history.

---

## 4. A single log writer, and it is asynchronous

The document does not specify this. It is a decision with two motives and one
consequence.

**Correctness.** Each entry's hash covers the previous one, so appends must
happen in strict order. Two goroutines sealing against the same head would
fork the chain into two branches that no longer verify. The writer is a single
goroutine behind a channel (`internal/audit/writer.go`).

**Latency.** §8.2 sets a budget of 50 ms of added latency. Blocking the request
on an `INSERT` would spend that budget on bookkeeping. The verdict returns to
the proxy as soon as the rules decide, and the entry is written afterwards.

**Consequence:** there is a brief window in which a decision has been served
but is not yet durable. `Close` drains the queue on shutdown, so the window is
bounded by shutdown and not by loss. If the queue fills, entries are dropped
and counted — never at the cost of blocking a request — and the counter is
visible.

### 4.1 The dashboard does not write to the chain

Same reason: two processes writing would fork it. The dashboard records its
administrative actions by calling the engine's `POST /v1/audit`, which is
synchronous.

And it does so **before** applying the change. If the entry cannot be
confirmed, the change is not applied and the API responds 503. A change to
what the proxy blocks that nobody can account for afterwards is worse than a
change that never happened.

The exception is sign-in, which is logged best-effort: denying access to the
panel because the engine is not responding would leave the operator without
the very tool they need to find out why it is not responding.

---

## 5. Policy when the engine is down: `OS_FAIL_MODE`

The document does not specify this. The default is **`open`**: if the engine
does not answer within `OS_DECIDE_TIMEOUT_MS`, the request passes and the
failure is logged.

A protection layer that takes the protected site down every time its own
control plane blinks has inverted its purpose, and §8.2 sets an availability
target of ≥99% that no filtering requirement overrides. `closed` inverts the
criterion where an unfiltered request is worse than an unserved one.

The same criterion applies inside the engine: if Redis does not answer, the
rate limiting rule allows the request and counts the failure, instead of
rejecting all traffic because the counter is down.

---

## 6. What is not logged

§6.1 asks to log "relevant headers". The implementation decides what is
relevant by excluding what must not be persisted:

- **The request body is not stored.** It is inspected and discarded. An
  append-only log with long retention is the worst possible place for the
  passwords and personal data that travel in a `POST`.
- **`Cookie` and `Authorization` are not stored.** An audit log that keeps
  session tokens becomes a credential store.

What is kept is the bounded fragment (60 characters around the match, control
characters stripped) that triggered the block. It is the evidence of *why* the
request was blocked, which is what §6 asks for.

---

## 7. Minor details

**Rule chain order.** `ipblock → ratelimit → sqli → xss`. Cheapest first: a
prefix comparison, then a Redis round trip, and only then content scanning. An
already-known client never reaches the expensive checks.

**`Decide` takes the context as a parameter.** §5.2 stores it on the engine
(`e.ctx`). The context belongs to the request being decided and carries its
deadline; storing it on the struct is an anti-pattern in Go. The `Rule`
interface stays exactly as in the document.

**HTTP status per rule.** Rate limiting responds 429 and the rest 403, through
an optional `BlockStatus()` interface. The distinction is not cosmetic: a
well-behaved client reads 429 as "wait and retry", while 403 tells it to give
up.

**No backreferences in signatures.** Go uses RE2, which does not support them.
The `bare_tautology` signature matches any numeric comparison (`or 1=2` as well
as `or 1=1`), which is still an injection attempt.

**Ordering by `seq`, not by timestamp.** Two requests can land in the same
microsecond and `timestamptz` would not tell them apart. Chain order is
insertion order.

**Anchoring when verifying a range.** Verifying from a date uses the hash of
the entry immediately before the range as the anchor. Without that anchor, a
first entry rewritten in an internally consistent way would pass verification.

**A `$` in the bcrypt hash breaks the install.** Docker Compose reads `$` in a
`.env` as a variable reference, so `$2a$10$…` reaches the container empty with
no visible error. `-hash-password` prints the line already escaped with `$$`,
and `.env.example` warns about it.

**Go module path.** `github.com/open-shield/open-shield`. If the repository
ends up published under another owner, it is a `sed` over the imports and one
line in `go.mod`.

---

## 8. The `test/` tree does not appear in §7

§7 of the technical document draws the repository structure and has no test
directory: Go unit tests live next to the code, and that was enough while
there were only unit tests.

The full suite needs things that are not `_test.go` files next to a package:

```
test/
├── corpus/        attack vectors and legitimate traffic, in JSON
├── harness/       shared fixtures for the integration suite
├── integration/   //go:build integration
├── e2e/           //go:build e2e
└── load/k6/       the load scripts, which are not Go
```

`test/corpus` is a real Go package, not a data folder, because the corpus is
consumed by three different levels and the files are embedded with
`//go:embed`. The k6 scripts read the same JSON directly.

See `docs/testing-strategy.md` for what each level defends.

### 8.1 Build tags, not `testing.Short()`

Integration and end-to-end tests sit behind `//go:build integration` and
`//go:build e2e`.

`testing.Short()` would have been less machinery, but it leaves the files in
the build: their imports — the PostgreSQL pool, the Redis client, the HTTP
server — enter the dependency graph of `go test ./...` even when the test is
skipped. With tags, `make test` is genuinely dependency-free, and whoever runs
the default target does not need to know why it passed.

### 8.2 The `internal` rule splits the suite across three places

This is the practical consequence of the departure in §3, and it surprises
people the first time.

Go only allows `engine/internal/…` to be imported from `engine/…`, and
`dashboard/api/internal/…` from `dashboard/api/…`. An integration test for the
rate limiter or for the dashboard router **cannot live in
`test/integration/`**: it has to sit next to the package it exercises, behind
the same tag.

The result:

| Where | What it covers |
|---|---|
| `test/integration/` | everything reachable from the root `internal/`: `audit`, `rulestore`, `migrate`, `events` |
| `engine/internal/ratelimit/integration_test.go` | the sliding window against real Redis |
| `dashboard/api/internal/httpapi/integration_test.go` | `/rules` and `/ipblock` against real PostgreSQL |

`test/harness/` is the part all three share. It is not under `internal/`
precisely so that all three can import it.

All three also share **a single database**, so the suite runs with `-p 1`:
without it the test binaries run in parallel and empty each other's tables
mid-run.

---

## 9. The Lua is tested end to end, not in isolation

`proxy/lua/openshield.lua` is the only component without its own tests.

Setting up a Lua harness — busted, or `resty -e` — inside the OpenResty image
is possible, but the file is 194 lines that contain no filtering logic: they
collect what the engine needs, ask, and act on the answer. The whole decision
lives in Go, where it is already tested exhaustively.

What can fail in the Lua is that it stops filling in a field, and that is
detectable from the outside: `TestTheProxyPopulatesTheFieldsTheEngineDependsOn`
requires `ip`, `method`, `path` and `host` to arrive populated in the audit
entry. A hook that stopped sending them would blind the rule that reads them,
and the test says so.

---

## 10. Numeric magnitudes outside the chain's range

A known limit, documented rather than fixed.

`encoding/json` writes a `float64` in exponential notation as soon as its
exponent reaches 21 or drops below −6. `1e21` serializes as `"1e+21"`;
PostgreSQL stores the number as `numeric` and returns it as
`"1000000000000000000000"`. The two texts canonicalize differently, so the hash
recomputed on read does not match the one that was sealed, and `VerifyChain`
reports tampering on a log nobody has touched.

It is not reachable today: `decision_ms` is single-digit milliseconds and
`status` has three digits. The trap is for whoever adds the next numeric field.

**Why it is not fixed.** Any fix changes what goes into the hash — normalizing
the numeric literal to the form `jsonb` emits, for example — and that
invalidates **every existing chain**. The log cannot be pruned or recomputed:
deleting rows breaks it exactly as an attacker would. Changing the hash
function is a migration with a full export and a volume reset, not a patch.

It is pinned by `TestExtremeMagnitudesAreOutsideTheChainsRange`
(`test/integration/audit_test.go`), which fails if the behavior changes in
either direction. If it is ever fixed, that test will flag that this section
needs updating.

---

## 11. The client's address is only believed from a declared edge

**What the document says.** §8.1 keys RF-05 on the source address, and RF-06
records "each connection with its address, result and reason". Neither says
where that address comes from, because on a single VPS the question does not
arise: the address that opens the connection is the client's.

**What the code does.** Both the proxy and the dashboard now read the address
from `X-Forwarded-For` only when the connection arrives from a network listed
in `OS_TRUSTED_PROXY`, and they walk the list from the right, stopping at the
first address outside that set. Unset — the default — the header is ignored
entirely and the peer address stands.

**Why.** Behind an edge that terminates the connection, every request carries
the edge's address. Keyed on that, `ipblock` and `ratelimit` count the whole
internet as one client and the dashboard's sign-in throttle locks out every
operator at once. Both failures are silent: the rules still evaluate, the
dashboard still reports, and nothing in either says the control is inert.

The obvious repair — believe the header — is worse than the disease, and the
dashboard shipped with it. `clientIP` took the *first* entry of
`X-Forwarded-For` from any caller, which is the end of the list a client
controls. That turned ten sign-in attempts per fifteen minutes into an
unlimited password oracle against the single administrator account, because a
different forged address gave every attempt a fresh counter. It also let an
attacker choose the address recorded as the author of an administrative change
— and that address is sealed into the hash chain, so the forgery comes back out
of verification looking like authenticated evidence.

Picking the header is not a detail either. On a first deployment we chose
`X-Envoy-External-Address`, reasoning that an edge-written header cannot be
extended by a client. Measurement said otherwise: a request carrying a
hand-written value was logged verbatim, which proves the edge does not set it,
and that a header only an edge *should* write is worthless unless that edge
actually does. `X-Forwarded-For` with a narrow trusted range is the weaker-
looking option that is actually sound, because the right-to-left walk makes the
attacker's entries unreachable rather than trusting the header's provenance.

**The rule this leaves.** An address is usable as a control input only when a
trusted edge writes it and a client cannot extend it past that point. The
technical document states this for RF-11; it applies wherever an address decides
anything, which is every rule in the chain and the dashboard's front door.

---

## Out of scope in this version

With its anchor point already in place:

| Requirement | Status | Anchor |
|---|---|---|
| RF-04 · TLS and certbot | Deferred | Commented `443` block and ACME webroot in `proxy/conf.d/openshield.conf.template` |
| RF-07 · Anomaly notification | Deferred | Events are already published to Redis; the subscriber is missing |
| RF-08 · Load balancing | Deferred | `proxy_pass` over a variable; the `upstream` block with several members is missing |
| Geo-IP | Deferred | The audit payload is an open map |
| SQLite | Deferred | `audit.Repository` already has two implementations (Postgres and in-memory) |
| Multi-VPS control plane | Excluded in §2 | — |
