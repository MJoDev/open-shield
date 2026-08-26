// Package corpus is the shared body of test traffic: the attack vectors RF-03
// must catch, and the legitimate requests it must not.
//
// It exists as a package rather than as a fixture inside one test because three
// different levels consume the same cases — the rule chain in isolation, the
// live stack through the proxy, and the k6 load scenario. A vector that is only
// in the unit test proves the signature compiles; a vector that travels the
// whole path proves the system blocks it. Keeping one corpus means adding a
// case gives both, and the three levels cannot drift apart.
//
// The JSON files are embedded so that a test can load the corpus whatever
// directory it runs from, and read directly by the k6 scripts, which are not Go.
package corpus

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/open-shield/open-shield/internal/model"
)

//go:embed attacks.json
var attacksJSON []byte

//go:embed benign.json
var benignJSON []byte

// Case is one request, described the way it travels on the wire.
//
// Query is percent-encoded exactly as a client would send it, which is also
// what Nginx hands the engine. Several attack cases are consequently invisible
// until the engine decodes the field — that is the point of them.
type Case struct {
	ID          string `json:"id"`
	Description string `json:"description"`

	// Rule and Signature are set on attack cases only, and name what must fire.
	Rule      string `json:"rule"`
	Signature string `json:"signature"`

	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Query   string            `json:"query"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type file struct {
	Cases []Case `json:"cases"`
}

// Attacks returns the vectors that must be blocked.
func Attacks() []Case { return load(attacksJSON, "attacks.json", true) }

// Benign returns the legitimate traffic that must be allowed.
func Benign() []Case { return load(benignJSON, "benign.json", false) }

// load parses one corpus file. A malformed corpus is a defect in the test
// suite itself, not a test failure, so it panics rather than returning an
// error every caller would have to handle identically.
func load(raw []byte, name string, attacks bool) []Case {
	var parsed file
	if err := json.Unmarshal(raw, &parsed); err != nil {
		panic(fmt.Sprintf("corpus: parse %s: %v", name, err))
	}
	if len(parsed.Cases) == 0 {
		panic(fmt.Sprintf("corpus: %s contains no cases", name))
	}

	seen := make(map[string]bool, len(parsed.Cases))
	for i, c := range parsed.Cases {
		switch {
		case c.ID == "":
			panic(fmt.Sprintf("corpus: case %d in %s has no id", i, name))
		case seen[c.ID]:
			panic(fmt.Sprintf("corpus: duplicate id %q in %s", c.ID, name))
		case attacks && (c.Rule == "" || c.Signature == ""):
			panic(fmt.Sprintf("corpus: attack %q in %s must name a rule and a signature", c.ID, name))
		case !attacks && (c.Rule != "" || c.Signature != ""):
			panic(fmt.Sprintf("corpus: benign case %q in %s must not name a rule", c.ID, name))
		}
		seen[c.ID] = true
	}
	return parsed.Cases
}

// HTTPMethod is the method to send, defaulting to GET.
func (c Case) HTTPMethod() string {
	if c.Method == "" {
		return "GET"
	}
	return c.Method
}

// Target joins the case onto a base URL, leaving Query byte-for-byte as
// written: the encoding in the corpus is part of the case.
func (c Case) Target(base string) string {
	target := strings.TrimSuffix(base, "/") + c.Path
	if c.Query != "" {
		target += "?" + c.Query
	}
	return target
}

// RequestContext builds what the engine would receive for this case, matching
// what engine/internal/httpapi does with a decision request: header names
// lowercased, and a UTC arrival time.
func (c Case) RequestContext(ip string) model.RequestContext {
	headers := make(map[string]string, len(c.Headers))
	for name, value := range c.Headers {
		headers[strings.ToLower(name)] = value
	}

	return model.RequestContext{
		RequestID:  "corpus-" + c.ID,
		IP:         ip,
		Method:     c.HTTPMethod(),
		Path:       c.Path,
		Query:      c.Query,
		Headers:    headers,
		Body:       c.Body,
		ReceivedAt: time.Now().UTC(),
	}
}

// Decoded renders the case the way a person reads it, for failure messages.
// Percent-encoding is what the wire carries, but it is not what anyone wants to
// see when a test fails.
func (c Case) Decoded() string {
	target := c.Path
	if c.Query != "" {
		if q, err := url.QueryUnescape(c.Query); err == nil {
			target += "?" + q
		} else {
			target += "?" + c.Query
		}
	}

	out := c.HTTPMethod() + " " + target
	if c.Body != "" {
		out += " body=" + c.Body
	}
	return out
}
