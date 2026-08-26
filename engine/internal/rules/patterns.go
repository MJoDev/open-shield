package rules

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/open-shield/open-shield/internal/model"
)

//go:embed patterns.json
var defaultPatterns []byte

// Signature is one named detection pattern.
type Signature struct {
	ID          string `json:"id"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`

	re *regexp.Regexp
}

// SignatureSet is the whole signature file, grouped by rule name.
type SignatureSet struct {
	SQLi []Signature `json:"sqli"`
	XSS  []Signature `json:"xss"`
}

// LoadSignatures reads the signature file from path, or the embedded copy when
// path is empty. Every pattern is compiled here, at startup: a malformed
// signature must stop the engine from booting rather than surface as a failed
// evaluation on live traffic.
func LoadSignatures(path string) (SignatureSet, error) {
	raw := defaultPatterns
	source := "embedded"

	if path != "" {
		content, err := os.ReadFile(path)
		if err != nil {
			return SignatureSet{}, fmt.Errorf("rules: read signature file %s: %w", path, err)
		}
		raw, source = content, path
	}

	var set SignatureSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return SignatureSet{}, fmt.Errorf("rules: parse signatures from %s: %w", source, err)
	}

	if err := compileAll(set.SQLi, source); err != nil {
		return SignatureSet{}, err
	}
	if err := compileAll(set.XSS, source); err != nil {
		return SignatureSet{}, err
	}
	if len(set.SQLi) == 0 && len(set.XSS) == 0 {
		return SignatureSet{}, fmt.Errorf("rules: signature file %s contains no patterns", source)
	}
	return set, nil
}

func compileAll(signatures []Signature, source string) error {
	for i := range signatures {
		if signatures[i].ID == "" {
			return fmt.Errorf("rules: signature %d in %s has no id", i, source)
		}
		re, err := regexp.Compile(signatures[i].Pattern)
		if err != nil {
			return fmt.Errorf("rules: signature %q in %s: %w", signatures[i].ID, source, err)
		}
		signatures[i].re = re
	}
	return nil
}

// PatternRule matches a set of signatures against every part of a request an
// attacker controls. Both the sqli and the xss rules are instances of it — the
// difference between them is data, not code.
type PatternRule struct {
	name       string
	signatures []Signature
	maxScan    int
}

// NewPatternRule returns a rule named name backed by the given signatures.
// maxScan caps how many bytes of any single field are examined.
func NewPatternRule(name string, signatures []Signature, maxScan int) *PatternRule {
	if maxScan <= 0 {
		maxScan = 8192
	}
	return &PatternRule{name: name, signatures: signatures, maxScan: maxScan}
}

func (r *PatternRule) Name() string { return r.name }

// Evaluate scans the request. It returns the first signature that matches,
// naming both the signature and the field it was found in — an operator
// reading the audit log needs to know *where* the payload was, not only that
// something matched.
func (r *PatternRule) Evaluate(_ context.Context, req *model.RequestContext) (model.Verdict, string) {
	for _, field := range scanTargets(req, r.maxScan) {
		for i := range r.signatures {
			sig := &r.signatures[i]
			if sig.re == nil {
				continue
			}
			if loc := sig.re.FindStringIndex(field.value); loc != nil {
				return model.Block, fmt.Sprintf("%s signature %q matched in %s: %s",
					r.name, sig.ID, field.name, excerpt(field.value, loc))
			}
		}
	}
	return model.Allow, ""
}

// scanField is one named piece of a request to run signatures against.
type scanField struct {
	name  string
	value string
}

// scanTargets lists everything worth scanning, each one both raw and
// percent-decoded.
//
// Decoding matters: %27%20OR%20%271%27%3D%271 is the same injection as
// ' OR '1'='1, and a rule that only saw the raw form would miss every attack
// that took the trouble to encode itself. Both forms are scanned because
// decoding can also *destroy* a match — a literal '%' in the raw text makes
// decoding fail, and the raw pass still covers it.
func scanTargets(req *model.RequestContext, maxScan int) []scanField {
	fields := make([]scanField, 0, 12)

	add := func(name, value string) {
		if value == "" {
			return
		}
		value = truncate(value, maxScan)
		fields = append(fields, scanField{name: name, value: value})
		if decoded, err := url.QueryUnescape(value); err == nil && decoded != value {
			fields = append(fields, scanField{name: name + " (decoded)", value: decoded})
		}
	}

	add("path", req.Path)
	add("query", req.Query)
	add("body", req.Body)

	for name, value := range req.Headers {
		// The host and the standard negotiation headers are set by the client
		// but never carry a payload aimed at the backend's parser; scanning
		// them is cost without detection.
		if skipHeader(name) {
			continue
		}
		add("header "+name, value)
	}

	return fields
}

// skipHeader lists headers excluded from signature scanning.
func skipHeader(name string) bool {
	switch strings.ToLower(name) {
	case "host", "accept", "accept-encoding", "accept-language", "connection",
		"content-length", "content-type", "upgrade-insecure-requests",
		"x-request-id", "x-forwarded-for", "x-real-ip":
		return true
	}
	return false
}

func truncate(s string, max int) string {
	if max > 0 && len(s) > max {
		return s[:max]
	}
	return s
}

// excerpt returns a short, safe-to-log window around a match. The matched text
// itself is hostile input, so it is bounded and the surrounding context is
// dropped — an audit entry should describe the payload, not reproduce a
// megabyte of it.
func excerpt(value string, loc []int) string {
	const window = 60

	start := loc[0] - 10
	if start < 0 {
		start = 0
	}
	end := loc[1] + 10
	if end > len(value) {
		end = len(value)
	}
	if end-start > window {
		end = start + window
	}

	out := strings.TrimSpace(value[start:end])
	out = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, out)

	if end < len(value) || start > 0 {
		out = "…" + out + "…"
	}
	return out
}
