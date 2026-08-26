package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// canonical_test.go covers the properties of the encoding — sorted keys, no
// HTML escaping, preserved numeric literals. This file covers the type switch
// itself, one branch at a time.
//
// The branches matter because they are where a wrong answer would be invisible.
// Everything sealed into the chain goes through writeCanonical, and a type it
// handles slightly differently from the way the value comes back out of jsonb
// produces a chain that stops verifying with nothing to point at.

func canonical(t *testing.T, v any) string {
	t.Helper()

	out, err := CanonicalJSON(v)
	if err != nil {
		t.Fatalf("CanonicalJSON(%#v): %v", v, err)
	}
	return string(out)
}

func TestCanonicalJSONHandlesEveryValueKind(t *testing.T) {
	for name, c := range map[string]struct {
		in   any
		want string
	}{
		"nil":             {nil, "null"},
		"true":            {true, "true"},
		"false":           {false, "false"},
		"string":          {"hola", `"hola"`},
		"empty string":    {"", `""`},
		"int":             {403, "403"},
		"negative int":    {-1, "-1"},
		"int64":           {int64(9007199254740993), "9007199254740993"},
		"uint":            {uint(8192), "8192"},
		"float":           {1.5, "1.5"},
		"whole float":     {100.0, "100"},
		"json.Number":     {json.Number("1.50"), "1.50"},
		"empty array":     {[]any{}, "[]"},
		"array":           {[]any{1, "dos", true, nil}, `[1,"dos",true,null]`},
		"nested array":    {[]any{[]any{1, 2}, []any{3}}, "[[1,2],[3]]"},
		"empty object":    {map[string]any{}, "{}"},
		"string map":      {map[string]string{"b": "2", "a": "1"}, `{"a":"1","b":"2"}`},
		"nested object":   {map[string]any{"b": map[string]any{"z": 1, "a": 2}}, `{"b":{"a":2,"z":1}}`},
		"array in object": {map[string]any{"list": []any{3, 1, 2}}, `{"list":[3,1,2]}`},
	} {
		t.Run(name, func(t *testing.T) {
			if got := canonical(t, c.in); got != c.want {
				t.Fatalf("CanonicalJSON(%#v) = %s, want %s", c.in, got, c.want)
			}
		})
	}
}

// A json.Number is written out verbatim, which is the whole reason payloads are
// decoded with UseNumber. An empty one is not a number at all, and writing
// nothing would silently produce invalid JSON that still hashed to something.
func TestCanonicalJSONRefusesAnEmptyNumber(t *testing.T) {
	if out, err := CanonicalJSON(json.Number("")); err == nil {
		t.Fatalf("CanonicalJSON(json.Number(\"\")) = %s, want an error", out)
	}
}

// A named type or a struct is not something a payload read back from the store
// can contain, but it is easy for a caller to pass one. It goes through
// encoding/json first so that what is hashed is the shape the store would
// return, not the Go value.
func TestCanonicalJSONNormalisesStructsAndNamedTypes(t *testing.T) {
	type nested struct {
		Zulu  string `json:"zulu"`
		Alpha int    `json:"alpha"`
	}

	if got := canonical(t, nested{Zulu: "z", Alpha: 1}); got != `{"alpha":1,"zulu":"z"}` {
		t.Errorf("struct = %s, want the keys sorted", got)
	}

	// Verdict is a named string type, used in every traffic payload.
	if got := canonical(t, Block); got != `"block"` {
		t.Errorf("Verdict = %s, want %q", got, `"block"`)
	}

	// A time.Time marshals to a string, and must not recurse forever.
	stamp := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	if got := canonical(t, stamp); got != `"2026-08-25T12:00:00Z"` {
		t.Errorf("time.Time = %s", got)
	}
}

func TestCanonicalJSONReportsValuesItCannotEncode(t *testing.T) {
	// Channels and functions cannot appear in an entry read back from the
	// store, so this only fires on a caller mistake — but it has to fire, not
	// hash to something plausible.
	for name, v := range map[string]any{
		"a channel":      make(chan int),
		"a function":     func() {},
		"inside a map":   map[string]any{"ok": 1, "bad": make(chan int)},
		"inside a slice": []any{1, make(chan int)},
	} {
		t.Run(name, func(t *testing.T) {
			if out, err := CanonicalJSON(v); err == nil {
				t.Fatalf("CanonicalJSON succeeded with %s: %s", name, out)
			}
		})
	}
}

// When the payload cannot be canonicalised the digest is marked rather than
// computed over nothing. An entry that hashed as if it had an empty payload
// would verify happily while saying nothing about what actually happened.
func TestComputeHashMarksAnUnencodablePayload(t *testing.T) {
	broken := AuditEntry{
		ID:        "0f8fad5b-d9cb-469f-a165-70867728950e",
		Timestamp: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC),
		Kind:      KindTraffic,
		Payload:   map[string]any{"bad": make(chan int)},
		PrevHash:  GenesisHash,
	}

	empty := broken
	empty.Payload = map[string]any{}

	if broken.ComputeHash() == empty.ComputeHash() {
		t.Fatal("an unencodable payload hashes the same as an empty one")
	}
	if len(broken.ComputeHash()) != 64 {
		t.Fatalf("ComputeHash returned %d characters, want a hex SHA-256", len(broken.ComputeHash()))
	}
}

// --- NormalizePayload and DecodeJSONPayload ----------------------------------

func TestNormalizePayloadReportsValuesItCannotEncode(t *testing.T) {
	if out, err := NormalizePayload(map[string]any{"bad": make(chan int)}); err == nil {
		t.Fatalf("NormalizePayload succeeded: %v", out)
	}
}

func TestNormalizePayloadReachesNestedValues(t *testing.T) {
	// A float buried three levels down breaks the chain exactly as readily as
	// one at the top.
	out, err := NormalizePayload(map[string]any{
		"headers": map[string]any{"depth": map[string]any{"ms": 1.50}},
		"list":    []any{2.50},
	})
	if err != nil {
		t.Fatalf("NormalizePayload: %v", err)
	}

	headers := out["headers"].(map[string]any)
	depth := headers["depth"].(map[string]any)
	if _, ok := depth["ms"].(json.Number); !ok {
		t.Errorf("a nested number became %T, want json.Number", depth["ms"])
	}
	list := out["list"].([]any)
	if _, ok := list[0].(json.Number); !ok {
		t.Errorf("a number inside an array became %T, want json.Number", list[0])
	}
}

func TestDecodeJSONPayloadRejectsWhatIsNotAnObject(t *testing.T) {
	// The column is jsonb and could technically hold a scalar. An entry whose
	// payload is not an object is corrupt, and saying so beats returning a nil
	// map that every caller would then have to guard.
	for name, raw := range map[string]string{
		"an array":    `[1,2,3]`,
		"a string":    `"hola"`,
		"a number":    `42`,
		"truncated":   `{"ip":`,
		"not json":    `no es json`,
		"two objects": `{"a":1}{"b":2}`,
	} {
		t.Run(name, func(t *testing.T) {
			out, err := DecodeJSONPayload([]byte(raw))
			if name == "two objects" {
				// The decoder reads the first value and stops, which is the
				// behaviour every other JSON reader in the system has too.
				if err != nil {
					t.Fatalf("DecodeJSONPayload: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("DecodeJSONPayload(%s) = %v, want an error", raw, out)
			}
		})
	}
}

func TestDecodeJSONPayloadTurnsNullIntoAnEmptyObject(t *testing.T) {
	// A caller iterating the payload should not have to nil-check first.
	for _, raw := range []string{``, `null`, `{}`} {
		out, err := DecodeJSONPayload([]byte(raw))
		if err != nil {
			t.Fatalf("DecodeJSONPayload(%q): %v", raw, err)
		}
		if out == nil {
			t.Fatalf("DecodeJSONPayload(%q) returned a nil map", raw)
		}
		if len(out) != 0 {
			t.Fatalf("DecodeJSONPayload(%q) = %v, want empty", raw, out)
		}
	}
}

// --- RequestContext ----------------------------------------------------------

// The proxy lowercases header names before sending them, and Header does an
// exact lookup. A rule that searched for "Referer" would silently match nothing
// on every request.
func TestRequestContextHeaderLooksUpExactly(t *testing.T) {
	req := RequestContext{Headers: map[string]string{
		"user-agent": "curl/8.5.0",
		"referer":    "http://ejemplo.test/",
	}}

	if got := req.Header("user-agent"); got != "curl/8.5.0" {
		t.Errorf("Header(user-agent) = %q", got)
	}
	if got := req.Header("User-Agent"); got != "" {
		t.Errorf("Header(User-Agent) = %q; lookups are exact, and the proxy sends lowercase", got)
	}
	if got := req.Header("x-absent"); got != "" {
		t.Errorf("Header(x-absent) = %q, want empty", got)
	}

	var empty RequestContext
	if got := empty.Header("user-agent"); got != "" {
		t.Errorf("Header on a context with no headers = %q", got)
	}
}

// --- Sealing ------------------------------------------------------------------

func TestSealTreatsAnEmptyPrevHashAsGenesis(t *testing.T) {
	// The writer resumes from Head, which returns the genesis hash on an empty
	// log — but a caller passing "" must not produce an entry whose PrevHash is
	// blank, or the first link would be unverifiable.
	entry := AuditEntry{
		ID:        "0f8fad5b-d9cb-469f-a165-70867728950e",
		Timestamp: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC),
		Kind:      KindSystem,
		Payload:   map[string]any{},
	}
	hash := entry.Seal("")

	if entry.PrevHash != GenesisHash {
		t.Fatalf("PrevHash = %q, want the genesis hash", entry.PrevHash)
	}
	if hash != entry.Hash {
		t.Fatal("Seal returned a different hash from the one it stored")
	}
	if strings.Count(GenesisHash, "0") != 64 {
		t.Fatalf("the genesis hash is %q, want 64 zeros", GenesisHash)
	}
}
