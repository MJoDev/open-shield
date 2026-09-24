---
title: "Reverse Proxy System — Technical Decisions Document"
project: "open-shield"
date: "2026-08-25"
version: "1.2 (draft)"
revision: "2026-09-24"
license: "Open source"
language: "en"
translation_es: "technical-document.es.md"
---

> **Status of this revision.** v1.2 incorporates the results of the evasion
> resistance evaluation recorded in `filtering-coverage-findings.md`. Items
> marked **(proposed)** are pending approval and are the only ones that change
> what was agreed in v1.1.

# Reverse Proxy System

## Full Technical Document

**open-shield**
Reverse proxy system for the protection of web infrastructure
TECHNICAL DECISIONS DOCUMENT

---

### General Data
- **Scope:** Open source, portable to any VPS, integrable into CI/CD
- **Area:** Computing and internet services
- **Year:** 2026

---

### Table of Contents
1. Executive summary
2. Scope and objectives
3. System architecture
4. Technology decisions
5. Design patterns applied
6. Forensic traceability
7. Repository structure
8. Requirements
9. Feasibility
10. Tentative timeline
11. Conclusions

---

### 1. Executive Summary

This document formalizes the development decisions for a reverse proxy system conceived as a general-purpose open source project: "installable on any VPS with a single command, with no licensing cost, and integrable into a CI/CD pipeline with no manual steps."

The scope is not limited to the proxy itself — it also includes the rules/decision engine, the administration dashboard, and the forensic traceability scheme as original developments.

---

### 2. Scope and Objectives

**General Objective:**
"Design and implement a reverse proxy system that acts as a perimeter protection layer for web infrastructure, mitigating unauthorized access and malicious traffic without altering existing applications, and distributable as open source software ready for immediate installation."

**Specific Objectives:**

1. Diagnose the level of exposure of a web infrastructure to direct connections from the internet

2. Design the architecture of the reverse proxy, the rules engine, the monitoring dashboard, and the forensic traceability scheme, "packaged as a container stack installable on any VPS"

3. Validate the system through load testing and controlled attack simulations, including the obfuscated variants of every vector, and report effectiveness as a detection rate alongside a false-positive rate

**Out of Scope (v1):**
A centralized control-plane-style panel that manages multiple VPS instances. The initial version assumes one installation per server.

**Adversary model.**
Stating *who* the system protects against is what makes the claim that it protects evaluable. The adversary considered:

* operates from the internet, with no access to the server or the database;
* knows the common attack classes (SQL injection, XSS, path traversal, command injection) and knows a filter sits in front, and therefore applies known obfuscation techniques — repeated percent-encoding, JSON `\uXXXX` escapes, HTML entities, interleaved comments — to get past it;
* holds neither the signatures in use nor an unpublished vulnerability in the underlying technologies.

**Outside** the model: an attacker with access to the host or to PostgreSQL; a volumetric network-level denial of service, which is absorbed upstream rather than at the origin; abuse by an already authenticated legitimate user; and compromise of the protected application by a route that does not pass through the proxy.

**Inspection envelope.**
What the system looks at, and what it explicitly does not:

| Inspected | Not inspected |
|---|---|
| Path, query string and headers, except those excluded by explicit decision | Backend responses |
| The request body up to `OS_MAX_BODY_INSPECT_BYTES` | A body above `client_body_buffer_size`, which Nginx spills to disk: it arrives marked truncated and is **not re-read on the request path** |
| Every field both raw and normalized (see RF-03) | Traffic that does not pass through the proxy |

TLS termination may be resolved at the deployment provider's edge; in that topology the proxy receives the connection already decrypted and RF-04 is satisfied outside the container.

---

### 3. System Architecture

#### 3.1 Overview

"The reverse proxy is the single entry point for web traffic. Each request passes through two separate planes: the data plane (the HTTP request itself, which must reach the backend with the lowest possible latency) and the control plane (the decision on whether that request is allowed, and the record of that decision)."

**Main Components:**

| Component | Responsibility | Nature |
|---|---|---|
| Nginx / OpenResty | Receives traffic, terminates TLS, delegates the decision to the engine via Lua | Configuration + thin script |
| Rules engine (Go) | Evaluates requests, applies rate limiting, writes the audit log | Custom code — core of the system |
| Dashboard API (Go) | Exposes REST + WebSocket for the admin panel | Custom code |
| Dashboard Web (React) | Real-time monitoring interface | Custom code |
| Redis | Real-time state and event pub/sub | Third-party infrastructure |
| PostgreSQL / SQLite | Persistence of the audit log with verifiable integrity | Third-party infrastructure + custom schema |

#### 3.2 Request Flow

Every incoming HTTP request follows this sequence, identified by a unique correlation ID:

1. The client connects to Nginx/OpenResty, which terminates TLS and generates a request_id (UUID)

2. Nginx invokes the rules engine via an internal auth_request, sending IP, headers, method, path, and request_id

3. The rules engine evaluates the request against the active rules using state held in Redis

4. The engine responds allow or block, writing the event to the audit log and publishing it to Redis Pub/Sub

5. If the verdict is "allow," Nginx forwards the request to the backend. If "block," Nginx terminates the connection

6. The dashboard receives the event in real time via Redis and updates the view

#### 3.3 Deployment Model

"Each installation is self-contained: a VPS runs a single stack (proxy, engine, dashboard, Redis, database) brought up with Docker Compose. There is no central instance managing multiple VPS instances — each deployment is independent."

The protected backend can be written in any technology, as long as it exposes an HTTP/HTTPS port reachable from the stack's network.

---

### 4. Technology Decisions

#### 4.1 Proxy Engine

| Option | Pros | Cons |
|---|---|---|
| **Nginx / OpenResty ✓** | Lightweight, mature, very high adoption, native Lua support | Less flexible configuration than a fully programmable proxy |
| HAProxy | Excellent for high-performance load balancing | Smaller ecosystem for embedded logic |
| Traefik | Convenient dynamic routing in containers | Higher overhead for a small VPS |

**Justification:** "Nginx/OpenResty is chosen because it lets the proxy stay a thin layer (config + a Lua script that calls the rules engine) without turning it into the place where business logic lives — that logic belongs to the rules engine written in Go."

#### 4.2 Rules Engine Language

| Option | Pros | Cons |
|---|---|---|
| **Go ✓** | Native high concurrency (goroutines), single dependency-free binary, low memory footprint | Smaller library ecosystem for general-purpose tasks |
| Node.js | Huge ecosystem, same language as many backends | Less predictable concurrency model under load |
| Python | Fast development, good analysis libraries | Insufficient performance for the critical path |

#### 4.3 Dashboard Frontend

| Option | Pros | Cons |
|---|---|---|
| **React ✓** | Mature ecosystem, data components, well-known learning curve | Requires a build step packaged into the container |
| Svelte | Lighter bundle | Smaller ecosystem of dashboard components |
| HTMX + Go templates | Zero frontend build | Worse fit for a highly interactive UI |

#### 4.4 Proxy ↔ Rules Engine Communication

| Option | Pros | Cons |
|---|---|---|
| **Lua + auth_request ✓** | Native to Nginx/OpenResty, low-overhead internal sub-request | Glue logic split across two languages |
| Pure HTTP sidecar | Simpler to reason about | Network overhead on every request |

#### 4.5 Real-Time Event Bus

| Option | Pros | Cons |
|---|---|---|
| **Redis Pub/Sub ✓** | Redis is already needed for rate limiting; minimal latency | No event persistence |
| Kafka | High retention and replay capacity | Overengineering for a single VPS |
| NATS | Very lightweight | Additional infrastructure with no clear benefit |

#### 4.6 Audit Log Storage

| Option | Pros | Cons |
|---|---|---|
| **PostgreSQL / SQLite ✓** | Structured queries, transactions for the hash chain | Requires schema management and migrations |
| Flat files | Extreme simplicity | No transactional guarantees |

#### 4.7 Packaging Model

| Option | Pros | Cons |
|---|---|---|
| **Multi-container Docker Compose ✓** | Single-command install, each service updates independently | Slightly more pieces to manage |
| Single monolithic container | Apparently simpler install | One failure takes everything down |

---

### 5. Design Patterns Applied

#### 5.1 Sidecar / Chain of Responsibility

"The proxy doesn't decide, it delegates. Each request passes through a chain of responsibility: Nginx → rules engine → (allow/block). Each link has a single responsibility and can evolve or be deployed independently — this is the same idea behind the Sidecar pattern in microservice architectures."

#### 5.2 Strategy — Interchangeable Filtering Rules

"Each rule (SQLi detection, rate limiting, IP blocklist) is modeled as an implementation of the same interface. The rules engine doesn't know the details of each rule — it only executes them in sequence — so rules can be added or removed without touching the engine's core."

```go
type Rule interface {
    Name() string
    Evaluate(ctx context.Context, req *RequestContext) (Verdict, string)
}

// The engine only knows the interface, not the concrete rules
func (e *Engine) Decide(req *RequestContext) Decision {
    for _, rule := range e.rules {
        if v, reason := rule.Evaluate(e.ctx, req); v == Block {
            return Decision{Verdict: Block, Rule: rule.Name(), Reason: reason}
        }
    }
    return Decision{Verdict: Allow}
}
```

#### 5.3 Repository — Audit Log Access

"The rules engine never writes SQL directly against Postgres/SQLite. It talks to an AuditRepository interface, which allows swapping the database engine (SQLite for a small installation, Postgres for one with higher volume) without touching business logic."

```go
type AuditRepository interface {
    Append(ctx context.Context, entry AuditEntry) error
    VerifyChain(ctx context.Context, from, to time.Time) (bool, error)
}
```

#### 5.4 Observer / Pub-Sub — Events to the Dashboard

"The rules engine publishes every decision to a Redis channel; it doesn't know or care who is listening. The dashboard backend subscribes to that channel and forwards events via WebSocket to connected clients. This fully decouples the engine from the dashboard: either one can go down without affecting the other."

#### 5.5 12-Factor Configuration

"All configuration (ports, Redis/DB credentials, initial rules, the protected backend's domain) is injected via environment variables, never hardcoded or hand-edited in files inside the container."

---

### 6. Forensic Traceability

"The audit log is not a debugging tool: it is designed to serve as evidence. Each entry includes the hash of the previous entry, so that any alteration or deletion of an intermediate record breaks the chain and is exposed when verified."

#### 6.1 What Is Logged

* External traffic: source IP, relevant headers, method, path, geo-IP, the rule that triggered the verdict, latency per stage
* Internal system events: configuration changes, service restarts, rules added or removed
* Administrative access: who logs into the dashboard, what configuration they change, and when

#### 6.2 Integrity Chain

```go
type AuditEntry struct {
    ID        string    // UUID of the entry
    RequestID string    // correlates with the original HTTP request
    Timestamp time.Time
    Kind      string    // "traffic" | "system" | "admin"
    Payload   map[string]any
    PrevHash  string    // hash of the previous entry in the chain
    Hash      string    // sha256(PrevHash + Payload + Timestamp)
}

func (e AuditEntry) ComputeHash() string {
    raw := e.PrevHash + e.Timestamp.String() + fmt.Sprint(e.Payload)
    sum := sha256.Sum256([]byte(raw))
    return hex.EncodeToString(sum[:])
}
```

"Verifying the integrity of the history consists of walking the chain and recomputing each hash: if any of them doesn't match the recorded value, the exact point of tampering is identified."

#### 6.3 Log Separation

| Log | Purpose | Retention |
|---|---|---|
| Operational | Quick debugging, structured JSON format | Short rotation (e.g., 30 days) |
| Audit / forensic | Evidence with a verifiable integrity chain | Long retention, append-only |
| Administrative access | Who changed what in the system itself, and when | Long retention, alongside the audit log |

---

### 7. Repository Structure

**Monorepo:** "the proxy, the engine, and the dashboard evolve and are versioned together."

```
open-shield/
├── proxy/                      # Nginx/OpenResty config + Lua scripts
├── engine/                     # rules and decision engine (Go)
│   ├── cmd/
│   ├── internal/rules/         # Rule implementations (Strategy)
│   ├── internal/ratelimit/
│   └── internal/audit/         # AuditRepository, hash chaining
├── dashboard/
│   ├── api/                    # dashboard backend (Go)
│   └── web/                    # React frontend
├── deploy/
│   ├── docker-compose.yml
│   ├── docker-compose.quickstart.yml
│   └── .env.example
├── migrations/                 # Postgres/SQLite schema
└── docs/
```

#### 7.1 docker-compose.yml (skeleton)

```yaml
services:
  proxy:
    build: ./proxy
    ports: ["80:80", "443:443"]
    depends_on: [engine]
  engine:
    build: ./engine
    env_file: .env
    depends_on: [redis, db]
  dashboard-api:
    build: ./dashboard/api
    env_file: .env
    depends_on: [redis, db]
  redis:
    image: redis:7-alpine
  db:
    image: postgres:16-alpine
    env_file: .env
    volumes: ["db-data:/var/lib/postgresql/data"]
volumes:
  db-data:
```

#### 7.2 Nginx/OpenResty → Rules Engine Hook

```nginx
location / {
    auth_request /__decide;
    proxy_pass   http://backend;
}

location = /__decide {
    internal;
    proxy_pass http://engine:8080/decide;
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Real-IP      $remote_addr;
    proxy_set_header X-Request-ID   $request_id;
}
```

#### 7.3 Live Events Hook — React

```javascript
function useLiveEvents() {
  const [events, setEvents] = useState([]);
  useEffect(() => {
    const ws = new WebSocket(WS_URL + "/live");
    ws.onmessage = (msg) => {
      const ev = JSON.parse(msg.data);
      setEvents((prev) => [ev, ...prev].slice(0, 200));
    };
    return () => ws.close();
  }, []);
  return events;
}
```

---

### 8. Requirements

#### 8.1 Functional

| ID | Description |
|---|---|
| RF-01 | Intercept every incoming connection before it reaches the origin server |
| RF-02 | Route to different internal backends based on configuration |
| RF-03 | Filter requests against defined patterns, over the **normalized** input. Classes covered, a closed list for this version: SQL injection, XSS, path traversal/LFI and command injection |
| RF-03.1 | Normalize every field before matching: percent-decoding to a fixed point (bounded), JSON `\uXXXX` escapes, HTML entities, and removal of null bytes and control characters. Matching against the raw form is retained as well, because normalizing can also destroy a match |
| RF-04 | Support TLS/SSL certificate termination and automatic renewal, or delegate it to the provider's edge where the deployment resolves it there |
| RF-05 | Limit requests per IP within a time window (rate limiting), with an additional per-resource budget for endpoints exposed to brute force. The per-IP budget still applies **above** the specific one: spreading load across routes must not multiply the total budget |
| RF-06 | Log every connection with IP, outcome, and reason, with verifiable integrity |
| RF-07 | Notify technical staff of anomalous traffic patterns |
| RF-08 | Support load balancing across instances of the same service |
| RF-09 | Expose a real-time dashboard with the state of filtered traffic |
| RF-10 | Allow full installation via a single command (Docker Compose) |
| RF-11 | **(proposed)** Automatically and temporarily block an address that accumulates a configurable number of block decisions within a window |

**On RF-11.** It is the only addition in v1.2 that widens the scope rather than sharpening what was already agreed, which is why it is stated separately instead of being derived from RF-05. Up to here the system decides request by request and the response on addresses is manual; an automatic detection-to-response loop introduces state that changes policy **without human intervention**, and with it two risks that did not exist before:

* **Self-inflicted denial of service.** A false positive stops costing one rejected request and starts evicting a legitimate address for the whole lifetime of the block. The trigger threshold has to be set from the measured false-positive rate, not from intuition, and the block has to expire on its own.
* **Induced blocking of third parties.** If the header the real address is taken from were forgeable by the client, an attacker could get other people's addresses blocked. The feature requires, as a precondition, that the address come from a header a trusted edge overwrites and a client cannot extend.

RF-11 delimitation: it acts on IP addresses, not on sessions or accounts; the block is always temporary; and it covers neither shared reputation nor external intelligence feeds.

#### 8.2 Non-Functional

| Category | Criterion |
|---|---|
| Security | Encryption in transit, least privilege, periodic rule updates |
| Evasion resistance | Effectiveness is measured over a corpus that includes, for every vector, its obfuscated variants per the adversary model in §2. Both a detection rate and a false-positive rate are reported; a detection figure without the false-positive figure is not a measurement |
| Availability | 24/7 operation, fault tolerance, target ≥99% |
| Performance | Additional proxy latency < 50 ms under normal load |
| Scalability | New backends can be added without interrupting service |
| Maintainability | Environment-variable configuration, CI/CD-ready |
| Forensic traceability | Audit log with a verifiable integrity chain |
| Portability | Equivalent installation on any VPS, independent of the protected stack |

#### 8.3 Technical Requirements

| Area | Detail |
|---|---|
| Hardware | Physical or virtual server; CPU/RAM sized to expected traffic; storage for logs and certificates |
| Software | Linux, Nginx/OpenResty, Go (engine + dashboard API), React, Redis, PostgreSQL/SQLite, Certbot |
| Network | Public IP, DNS pointing to the proxy, ports 80/443, complementary perimeter firewall |
| Deployment | Docker Compose; installation agnostic to the protected backend's stack |

#### 8.4 Non-Technical Requirements

* Staff trained in Linux systems and network administration
* Information security and incident management policies
* Technical staff training on system operation
* Technical documentation and operations manual
* IT management approval and coordination of the migration window
* Rollback plan in case of availability impact

---

### 9. Feasibility

| Dimension | Assessment |
|---|---|
| Technical | Mature, well-documented open source technologies; does not require modifying existing applications |
| Operational | Low impact on current staff; moderate learning curve with training |
| Economic | No licensing cost; main investment is implementation hours |

---

### 10. Tentative Timeline

| Phase | Weeks | Deliverable |
|---|---|---|
| Assessment and diagnosis | 1–2 | Diagnosis of the exposure of the infrastructure to be protected |
| Technology selection and design | 3 | Documented architecture and decisions |
| Test implementation | 4–6 | Functional proxy, rules engine, and dashboard |
| Security and load testing | 7–8 | Attack simulation and performance report |
| Production migration | 9 | Stack operating as the single point of entry |
| Documentation and training | 10 | Operations manual and trained staff |

---

### 11. Conclusions

"The project rests on a clear separation between what is third-party configuration (Nginx, Redis, Postgres) and what is original, defensible development: the rules engine in Go, the dashboard in React, and the forensic traceability scheme with verifiable integrity. That separation is also what keeps the system decoupled from any particular infrastructure — the same stack, packaged in Docker Compose, installs the same way on any VPS and can be incorporated into a CI/CD pipeline with no cost and no manual steps."
