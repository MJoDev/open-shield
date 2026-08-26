package model

import (
	"encoding/json"
	"testing"
)

func TestCanonicalJSONSortsKeysRecursively(t *testing.T) {
	value := map[string]any{
		"z": 1,
		"a": map[string]any{"n": true, "b": []any{3, 1, 2}},
		"m": "x",
	}

	got, err := CanonicalJSON(value)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}

	want := `{"a":{"b":[3,1,2],"n":true},"m":"x","z":1}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// Array order carries meaning; only object keys get sorted.
func TestCanonicalJSONPreservesArrayOrder(t *testing.T) {
	got, err := CanonicalJSON([]any{"c", "a", "b"})
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if string(got) != `["c","a","b"]` {
		t.Fatalf("array order was not preserved: %s", got)
	}
}

// Blocked XSS payloads end up in audit entries constantly. If the canonical
// encoder escaped them as <script>, the hashed bytes and the bytes
// read back from the store would disagree.
func TestCanonicalJSONDoesNotEscapeHTML(t *testing.T) {
	got, err := CanonicalJSON(map[string]any{"body": "<script>alert(1)</script>&"})
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	want := `{"body":"<script>alert(1)</script>&"}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestCanonicalJSONPreservesNumericLiterals(t *testing.T) {
	got, err := CanonicalJSON(map[string]any{
		"scale": json.Number("1.50"),
		"big":   json.Number("12345678901234567890"),
	})
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	want := `{"big":12345678901234567890,"scale":1.50}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestNormalizePayloadTurnsNumbersIntoJSONNumber(t *testing.T) {
	out, err := NormalizePayload(map[string]any{
		"count":   7,
		"latency": 3.5,
		"nested":  map[string]any{"n": int64(9)},
	})
	if err != nil {
		t.Fatalf("NormalizePayload: %v", err)
	}

	if _, ok := out["count"].(json.Number); !ok {
		t.Fatalf("count is %T, want json.Number", out["count"])
	}
	if _, ok := out["latency"].(json.Number); !ok {
		t.Fatalf("latency is %T, want json.Number", out["latency"])
	}
	nested, ok := out["nested"].(map[string]any)
	if !ok {
		t.Fatalf("nested is %T, want map[string]any", out["nested"])
	}
	if _, ok := nested["n"].(json.Number); !ok {
		t.Fatalf("nested.n is %T, want json.Number", nested["n"])
	}
}

func TestNormalizePayloadHandlesNil(t *testing.T) {
	out, err := NormalizePayload(nil)
	if err != nil {
		t.Fatalf("NormalizePayload(nil): %v", err)
	}
	if out == nil || len(out) != 0 {
		t.Fatalf("got %v, want an empty map", out)
	}
}

func TestDecodeJSONPayloadHandlesEmptyInput(t *testing.T) {
	out, err := DecodeJSONPayload(nil)
	if err != nil {
		t.Fatalf("DecodeJSONPayload(nil): %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("got %v, want an empty map", out)
	}
}
