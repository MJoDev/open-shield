package rules

import (
	"context"
	"strings"
	"testing"

	"github.com/open-shield/open-shield/internal/model"
)

func loadRule(t *testing.T, name string) *PatternRule {
	t.Helper()

	set, err := LoadSignatures("")
	if err != nil {
		t.Fatalf("LoadSignatures: %v", err)
	}

	switch name {
	case "sqli":
		return NewPatternRule("sqli", set.SQLi, 8192)
	case "xss":
		return NewPatternRule("xss", set.XSS, 8192)
	default:
		t.Fatalf("unknown rule %q", name)
		return nil
	}
}

func TestSignaturesCompile(t *testing.T) {
	set, err := LoadSignatures("")
	if err != nil {
		t.Fatalf("LoadSignatures: %v", err)
	}
	if len(set.SQLi) == 0 || len(set.XSS) == 0 {
		t.Fatalf("empty signature set: %d sqli, %d xss", len(set.SQLi), len(set.XSS))
	}
	for _, sig := range append(append([]Signature{}, set.SQLi...), set.XSS...) {
		if sig.re == nil {
			t.Fatalf("signature %q was not compiled", sig.ID)
		}
	}
}

func TestSQLiRuleBlocksInjections(t *testing.T) {
	rule := loadRule(t, "sqli")

	cases := map[string]model.RequestContext{
		// The payload from the technical document's own worked example.
		"quoted tautology in query": {Path: "/products", Query: "id=1' OR '1'='1"},
		"percent-encoded tautology": {Path: "/products", Query: "id=1%27%20OR%20%271%27%3D%271"},
		"union select":              {Path: "/search", Query: "q=x' UNION SELECT username,password FROM users--"},
		"bare tautology":            {Path: "/items", Query: "id=5 OR 1=1"},
		"stacked destructive query": {Path: "/items", Query: "id=5; DROP TABLE users"},
		"comment terminator":        {Path: "/login", Body: "user=admin'--&pass=x"},
		"time-based blind":          {Path: "/items", Query: "id=1 AND sleep(5)"},
		"schema probe":              {Path: "/items", Query: "id=1 UNION SELECT table_name FROM information_schema.tables"},
		"injection in a cookie":     {Path: "/", Headers: map[string]string{"cookie": "sid=1' OR '1'='1"}},
		"injection in a body":       {Path: "/api/login", Body: `{"user":"admin'--","pass":"x"}`},
	}

	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			verdict, reason := rule.Evaluate(context.Background(), &req)
			if verdict != model.Block {
				t.Fatalf("allowed an injection: %+v", req)
			}
			if reason == "" {
				t.Fatal("blocked without a reason; the audit entry would say nothing")
			}
		})
	}
}

// A filter that blocks ordinary traffic is worse than no filter: it takes the
// protected site down and trains operators to disable it.
func TestSQLiRuleAllowsOrdinaryTraffic(t *testing.T) {
	rule := loadRule(t, "sqli")

	cases := map[string]model.RequestContext{
		"plain product page":     {Path: "/products/1234", Query: ""},
		"search with words":      {Path: "/search", Query: "q=selected+items+from+catalog"},
		"apostrophe in a name":   {Path: "/search", Query: "q=O'Reilly and sons"},
		"pagination":             {Path: "/items", Query: "page=2&per_page=50&order=name"},
		"iso date range":         {Path: "/reports", Query: "from=2026-01-01&to=2026-08-25"},
		"json body without sql":  {Path: "/api/orders", Body: `{"customer":"Ana Pérez","total":150.75,"items":3}`},
		"url with encoded space": {Path: "/search", Query: "q=open%20source%20proxy"},
		"user agent header":      {Path: "/", Headers: map[string]string{"user-agent": "Mozilla/5.0 (X11; Linux x86_64)"}},
	}

	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			verdict, reason := rule.Evaluate(context.Background(), &req)
			if verdict != model.Allow {
				t.Fatalf("false positive on ordinary traffic: %s", reason)
			}
		})
	}
}

func TestXSSRuleBlocksInjections(t *testing.T) {
	rule := loadRule(t, "xss")

	cases := map[string]model.RequestContext{
		"script tag in query":   {Path: "/search", Query: "q=<script>alert(1)</script>"},
		"script tag in body":    {Path: "/comments", Body: "text=<script>fetch('//evil')</script>"},
		"encoded script tag":    {Path: "/search", Query: "q=%3Cscript%3Ealert(1)%3C/script%3E"},
		"event handler":         {Path: "/p", Query: `name=<img src=x onerror=alert(1)>`},
		"javascript uri":        {Path: "/redirect", Query: "next=javascript:alert(document.cookie)"},
		"iframe injection":      {Path: "/p", Body: `bio=<iframe src="//evil"></iframe>`},
		"cookie exfiltration":   {Path: "/p", Query: "x=document.cookie"},
		"data uri html":         {Path: "/p", Query: "next=data:text/html;base64,PHNjcmlwdD4="},
		"closing tag breakout":  {Path: "/p", Query: "q=</script><img src=x onerror=alert(1)>"},
		"handler in the header": {Path: "/", Headers: map[string]string{"referer": "http://x/?a=<svg onload=alert(1)>"}},
	}

	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			verdict, reason := rule.Evaluate(context.Background(), &req)
			if verdict != model.Block {
				t.Fatalf("allowed an XSS payload: %+v", req)
			}
			if !strings.Contains(reason, "xss signature") {
				t.Fatalf("reason does not identify the rule: %s", reason)
			}
		})
	}
}

func TestXSSRuleAllowsOrdinaryTraffic(t *testing.T) {
	rule := loadRule(t, "xss")

	cases := map[string]model.RequestContext{
		"prose with punctuation": {Path: "/comments", Body: "text=Excelente servicio, gracias! 5/5"},
		"html-free markdown":     {Path: "/posts", Body: "body=# Título\n\nUn párrafo normal con *énfasis*."},
		"comparison operators":   {Path: "/filter", Query: "price<100&stock>0"},
		"email address":          {Path: "/signup", Body: "email=ana@example.com&name=Ana"},
		"path with dashes":       {Path: "/blog/2026/08/reverse-proxy-getting-started"},
	}

	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			verdict, reason := rule.Evaluate(context.Background(), &req)
			if verdict != model.Allow {
				t.Fatalf("false positive on ordinary traffic: %s", reason)
			}
		})
	}
}

// The reason string ends up in the audit log, which an operator reads to
// understand a block. It has to name the signature and the field.
func TestBlockReasonNamesSignatureAndField(t *testing.T) {
	rule := loadRule(t, "sqli")
	req := model.RequestContext{Path: "/products", Query: "id=1' OR '1'='1"}

	_, reason := rule.Evaluate(context.Background(), &req)
	for _, want := range []string{"sqli signature", "quoted_tautology", "query"} {
		if !strings.Contains(reason, want) {
			t.Fatalf("reason %q does not mention %q", reason, want)
		}
	}
}

func TestPatternRuleSkipsInfrastructureHeaders(t *testing.T) {
	rule := loadRule(t, "sqli")

	// X-Forwarded-For is written by the proxy, not the client, and scanning it
	// only costs time.
	req := model.RequestContext{
		Path:    "/",
		Headers: map[string]string{"x-forwarded-for": "1' OR '1'='1"},
	}
	if verdict, _ := rule.Evaluate(context.Background(), &req); verdict != model.Block {
		return // skipped as intended
	}
	t.Fatal("scanned a header that the proxy controls")
}

func TestExcerptIsBoundedAndPrintable(t *testing.T) {
	payload := strings.Repeat("A", 5000) + "' OR '1'='1" + strings.Repeat("B", 5000)
	rule := loadRule(t, "sqli")
	req := model.RequestContext{Path: "/", Query: payload}

	_, reason := rule.Evaluate(context.Background(), &req)
	if len(reason) > 300 {
		t.Fatalf("reason is %d bytes; audit entries must not carry the whole payload", len(reason))
	}
	if strings.ContainsAny(reason, "\x00\n\r") {
		t.Fatalf("reason contains control characters: %q", reason)
	}
}
