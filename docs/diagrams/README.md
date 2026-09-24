# Diagrams

PlantUML sources for the technical document's figures, versioned next to the
code they describe.

A diagram saved only as an image drifts out of sync with the system at the
first refactor and nobody notices. As plain text it shows up in the diff of
every code review, where the divergence is visible.

## Regenerating

```bash
docker run --rm -v "$PWD/docs/diagrams:/data" plantuml/plantuml \
  -tpng -charset UTF-8 /data/*.puml
```

or, with a local Java install:

```bash
java -jar plantuml.jar -tpng -charset UTF-8 docs/diagrams/*.puml
```

`style.iuml` holds the shared palette and typography; every `.puml` includes it
on its second line. Restyling every figure at once means editing that file and
rendering again.

Colored activity steps are written `:text; <<#RRGGBB>>`, not the older
`#RRGGBB:text;`. PlantUML 1.2026 rejects the older form when the step is
followed by `stop`, `else` or `endif`.

The `.puml` files carry **no `title` with a figure number**: a document that
embeds them numbers figures in its own insertion order, and a number baked into
the diagram would sooner or later contradict the caption.

## Index

| File | What it shows |
|---|---|
| `01-context` | The system as the single point of entry; boundary and actors |
| `02-components` | Internal packages and their dependencies |
| `03-deployment` | Containers, internal network and published ports |
| `04-request-sequence` | Data path: from the request to the verdict |
| `05-rule-chain-activity` | Evaluation of `ipblock → ratelimit → sqli → xss` |
| `06-use-cases` | Use case model, grouped by plane |
| `07-user-model` | Conceptual roles versus the implemented identity |
| `08-domain-model` | `internal/model` types; entities and value objects |
| `09-entity-relationship` | PostgreSQL schema, indexes and triggers |
| `10-strategy-pattern` | The `Rule` interface and its implementations |
| `11-repository-pattern` | `audit.Repository` and the shared chain walker |
| `12-observer-pattern` | Event publishing and the control channel |
| `13-single-writer-pattern` | Why the chain does not fork |
| `14-admin-change-sequence` | Record before applying, and the 503 when that fails |
| `15-hash-chain` | Chaining structure and the sealing function |
| `16-verification-activity` | Verification walk and range anchoring |
| `17-engine-failure-sequence` | `OS_FAIL_MODE` and `ratelimit` degradation |
