---
title: "Filtering coverage findings and proposal for technical document v1.2"
project: "open-shield"
date: "2026-09-19"
status: "Findings record. No code has been changed."
language: "en"
translation_es: "filtering-coverage-findings.es.md"
---

# Filtering coverage findings

This document records the result of an **evasion resistance** evaluation of
the rule chain, carried out on 2026-09-19 against the engine as it stands on
`main`. Not a single line of code has been changed: the goal is to pin down the
evidence and decide afterwards what goes into version 1.2 of the technical
document.

It is written here and not in `implementation-decisions.md` because there is
not yet any divergence between document and code to record. When any of the
proposed changes is implemented, its corresponding entry goes there.

---

## 1. Motivation

The attack corpus (`test/corpus/attacks.json`) contains 17 vectors for 16
signatures: roughly one per signature. That checks that **each signature fires
on its canonical input**, which is a necessary property but a different one from
what the system claims to provide.

The external actor the system aims to contain knows there is a filter in front.
It does not send the payload in the clear. The unanswered question was: what
happens when the same attack arrives obfuscated?

---

## 2. Method

A probe was built that instantiates the `sqli` and `xss` rules with the
embedded signatures (`engine/internal/rules/patterns.json`) and evaluates them
against four families:

- **A and B** — a base SQL injection attack and its obfuscated variants.
- **C** — a base XSS attack and its obfuscated variants.
- **D** — attack classes for which no signature exists.

The variants are documented, commonly used evasion techniques: double
percent-encoding, JSON `\uXXXX` escapes and HTML entities. The probe's code is
in the annex and is reproducible with `go test`.

---

## 3. Results

**7 of 14 cases get through the filter.**

| Family | Case | Result | Signature that fires |
|---|---|---|---|
| A | `admin'--` in `x-www-form-urlencoded` | Blocked | `comment_terminator` |
| A | the same attack with a JSON `'` escape | **Evades** | — |
| A | the same attack with a literal quote in JSON | Blocked | `comment_terminator` |
| B | tautology `' OR 1=1--` in the query | Blocked | `quoted_tautology` |
| B | the same, double-encoded | **Evades** | — |
| B | the same with a JSON escape | Blocked | `bare_tautology` |
| C | `<script>` in the query | Blocked | `script_tag` |
| C | the same, double-encoded | **Evades** | — |
| C | the same with HTML entities | **Evades** | — |
| C | the same with a JSON escape | **Evades** | — |
| D | path traversal `../../etc/passwd` | **Evades** | no signature |
| D | encoded path traversal | **Evades** | no signature |
| D | command injection `;cat /etc/passwd` | **Evades** | no signature |
| D | LFI through the `php://filter` wrapper | **Evades** | no signature |

### 3.1 Root causes

**(a) Normalization is single-pass.** `scanTargets`
(`engine/internal/rules/patterns.go:132`) scans each field raw and once decoded
with `url.QueryUnescape`. The decision is well reasoned and its comment
justifies it correctly, but it only covers one layer: `%2527` decodes to `%27`,
not to `'`, and neither form matches a signature. JSON `\uXXXX` escapes and
HTML entities are not handled either.

**(b) The XSS signatures are anchored to literal characters.** All eight depend
on a `<` or a `:` being present in the text. Any alternative representation of
those characters neutralizes them completely. It is the more fragile of the two
families: 3 of 4 variants evade, against 1 of 3 for SQLi.

**(c) Three attack classes have no signature.** RF-03 states "SQLi, XSS,
**known payloads**". The third category is declared and not implemented.

### 3.2 A result not to overlook

The JSON-escaped case B **is** blocked, but not by the signature it
corresponded to: `quoted_tautology` fails because the quote is obfuscated, and
it is caught by `bare_tautology`, which does not depend on it.

In other words: **the resistance observed in that case did not come from the
design, it came from accidental redundancy between two signatures.** Relying on
that is not a strategy. The finding supports, with its own evidence, the design
principle v1.2 must adopt: *normalize the input before matching, instead of
piling up signatures that cover every representation*. Piling up signatures
multiplies the per-request cost and the false-positive surface; normalizing is
a bounded function in a single place in the code.

---

## 4. Impact on objective, scope and boundaries

The question is whether any of the changes expands what the technical document
agreed to. The short answer: **the objective does not change; the scope changes
at a single point; the boundaries become more precise, which is an
improvement.**

| Proposed change | Classification | Does it alter the scope? |
|---|---|---|
| Multi-layer normalization | Defect fix | **No.** RF-03 already requires filtering by pattern; if the pattern does not see the payload, the requirement is not met. Normalizing enforces what is already written |
| Missing attack classes | Completing an under-implemented requirement | **No**, but it forces closing the list of "known payloads" (see §5) |
| Evasion corpus | Validation methodology | **No.** It changes the testing strategy, not the system |
| RF-07 notification | Declared and unimplemented requirement | **No.** It narrows the gap between document and code |
| Per-endpoint rate limit | Refinement of RF-05 | **No**, but it requires settling a design decision (see §5) |
| **Progressive automatic blocking** | **New capability** | **Yes.** It requires a new RF |

### 4.1 The only change that does expand the scope

Today the system decides **request by request** and the response on IPs
(`ip_rules`) is entirely manual. An automatic detection → response loop
introduces three things the technical document does not contemplate:

1. State that persists across requests and **modifies policy without human
   intervention**.
2. A new risk: **self-inflicted denial of service**. A false positive stops
   being one rejected request and becomes a legitimate IP locked out for the
   whole TTL of the block.
3. A derived risk: if the header the real IP is taken from were forgeable, an
   attacker could get third parties blocked. Behind a managed edge, the IP must
   come from a header the edge itself writes and the client cannot chain (for
   example `X-Envoy-External-Address`), but **it is a new security
   requirement** that has to be stated before the feature is built.

Recommendation: present it as an explicit **RF-11** in v1.2, with its own
boundaries, and not as a natural consequence of RF-05. Slipping it in without
declaring it is what would read as an unagreed scope change.

### 4.2 What the boundaries gain

Two things that are not written down today and that the finding makes it
possible to write precisely:

- **The inspection envelope.** What is examined and what is not: bodies above
  `client_body_buffer_size` arrive marked as truncated and **are not re-read
  from disk**; some headers are excluded from scanning by explicit decision
  (`skipHeader`, `patterns.go:169`); responses are not inspected; TLS is
  terminated upstream in the current deployment.
- **The adversary model.** How far containment is meant to go. With this data
  it can be stated without vagueness: *an attacker who knows the attack classes
  and applies known obfuscation techniques, but does not have the specific
  signatures or access to the machine.* An explicit adversary model is what
  separates an evaluation from a demonstration.

### 4.3 What happens to the project's value

It does not change direction: it changes status. Today the central claim — *the
system contains malicious external traffic* — rests on a suite that tests
signature coverage with canonical input. Afterwards it rests on a **detection
rate measured against evasion**, with a before and after figure.

And the finding is itself a result. Discovering by a systematic method that 7
of 14 variants of the project's own attacks get through its own filter,
documenting it and closing it with a comparative measurement is validation in
the strict sense. A test suite that only reports successes has measured
nothing.

---

## 5. What technical document v1.2 must resolve

> **Status as of 2026-09-24.** Items 1 to 5 and 7 are drafted in the v1.2 draft
> of `technical-document.md` and its translation `technical-document.es.md`,
> pending approval. Item 6 is incorporated as a non-functional criterion
> ("Evasion resistance"), but the variant corpus itself **has not been built**:
> it is still implementation work.

1. **RF-03** — close the list of "known payloads". Stated open-ended, the scope
   is infinite. Proposal: SQLi, XSS, path traversal/LFI and command injection,
   and nothing else in v1.2.
2. **RF-03** — add normalization as an explicit requirement, not as an
   implementation detail. It is the piece on which the rest of the requirement
   depends to mean anything.
3. **RF-05** — decide and write down the granularity. If the limit is per
   `(IP, path)`, an attacker gets one budget per path: the global per-IP budget
   must still exist **above** the specific one, not replace it.
4. **RF-11 (new)** — progressive automatic blocking, with its boundaries and the
   risks of §4.1.
5. **§ Boundaries** — incorporate the inspection envelope and the adversary
   model of §4.2.
6. **§ Validation** — incorporate the evasion corpus as a test level, with the
   before/after comparison table.
7. **RF-04** — record that TLS termination is handled by the provider's edge in
   the current deployment, instead of appearing as simply deferred.

Pending a separate decision, outside this finding: RF-06 does not provide for
**external anchoring** of the head hash, so truncation of the tail of the chain
is not detectable. It does not affect filtering and is not proposed for v1.2,
but it must appear as a known limitation.

---

## Annex — evasion probe

Reproducible by placing this file in `engine/internal/rules/` and running
`go test ./engine/internal/rules/ -run Evasion -v`. It is not part of the tree:
it is a measuring instrument, and its final version should be folded into
`test/corpus/attacks.json` as permanent cases.

```go
package rules

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/open-shield/open-shield/internal/model"
)

// '@' stands in for the backslash so the source carries no escapes.
func unesc(s string) string { return strings.ReplaceAll(s, "@", string([]byte{92})) }

func TestEvasionProbe(t *testing.T) {
	set, _ := LoadSignatures("")
	sqli := NewPatternRule("sqli", set.SQLi, 8192)
	xss := NewPatternRule("xss", set.XSS, 8192)

	type c struct{ group, name, query, body string }
	cases := []c{
		{"A", "base: SQLi ' -- in form-urlencoded", "", "user=admin%27--&pass=x"},
		{"A", "  var: same attack, escaped JSON", "", unesc(`{"user":"admin@u0027--"}`)},
		{"A", "  var: same attack, literal JSON", "", `{"user":"admin'--"}`},

		{"B", "base: SQLi tautology in query", "id=1%27%20OR%201%3D1--", ""},
		{"B", "  var: double encoding", "id=1%2527%2520OR%25201%253D1--", ""},
		{"B", "  var: escaped JSON", "", unesc(`{"id":"1@u0027 OR 1=1--"}`)},

		{"C", "base: XSS <script> in query", "q=%3Cscript%3Ealert(1)%3C/script%3E", ""},
		{"C", "  var: double encoding", "q=%253Cscript%253Ealert(1)%253C/script%253E", ""},
		{"C", "  var: HTML entities", "q=&lt;script&gt;alert(1)&lt;/script&gt;", ""},
		{"C", "  var: escaped JSON", "", unesc(`{"c":"@u003cscript@u003ealert(1)@u003c/script@u003e"}`)},

		{"D", "missing class: path traversal", "file=../../../../etc/passwd", ""},
		{"D", "missing class: encoded traversal", "file=..%2f..%2f..%2fetc%2fpasswd", ""},
		{"D", "missing class: command injection", "host=127.0.0.1;cat%20/etc/passwd", ""},
		{"D", "missing class: LFI via php wrapper", "p=php://filter/convert.base64-encode/resource=index", ""},
	}

	prev := ""
	for _, tc := range cases {
		if tc.group != prev {
			fmt.Println()
			prev = tc.group
		}
		req := &model.RequestContext{Path: "/search", Query: tc.query, Body: tc.body, Headers: map[string]string{}}
		verdict, reason := "PASS  <-- EVADES", ""
		if v, r := sqli.Evaluate(context.Background(), req); v == model.Block {
			verdict, reason = "BLOCK", r
		} else if v, r := xss.Evaluate(context.Background(), req); v == model.Block {
			verdict, reason = "BLOCK", r
		}
		if i := strings.Index(reason, " matched"); i > 0 {
			reason = reason[:i]
		}
		fmt.Printf("  %-40s %-18s %s\n", tc.name, verdict, reason)
	}
	fmt.Println()
}
```
