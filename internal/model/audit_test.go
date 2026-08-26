package model

import (
	"encoding/json"
	"testing"
	"time"
)

func sampleEntry() AuditEntry {
	return AuditEntry{
		ID:        "b3f1c2a4-0000-4000-8000-000000000001",
		RequestID: "req-42",
		Timestamp: time.Date(2026, 8, 25, 14, 30, 0, 123456789, time.UTC),
		Kind:      KindTraffic,
		Payload: map[string]any{
			"ip":      "203.0.113.9",
			"verdict": "block",
			"rule":    "sqli",
			"path":    "/products",
			"query":   "id=1' OR '1'='1",
			"headers": map[string]any{"user-agent": "curl/8.5.0"},
			"latency": json.Number("3.5"),
		},
		PrevHash: GenesisHash,
	}
}

// The sketch in the technical document hashed fmt.Sprint of a map, which Go
// renders in a random order on every run. This is the test that would have
// caught it.
func TestComputeHashIsDeterministic(t *testing.T) {
	entry := sampleEntry()
	want := entry.ComputeHash()

	for i := 0; i < 1000; i++ {
		if got := entry.ComputeHash(); got != want {
			t.Fatalf("hash changed between calls at iteration %d: %s != %s", i, got, want)
		}
	}
}

func TestComputeHashIgnoresPayloadKeyOrder(t *testing.T) {
	a := sampleEntry()
	b := sampleEntry()

	// Rebuild b's payload by inserting the same keys in a different order.
	reordered := map[string]any{}
	keys := []string{"latency", "headers", "query", "path", "rule", "verdict", "ip"}
	for _, k := range keys {
		reordered[k] = a.Payload[k]
	}
	b.Payload = reordered

	if a.ComputeHash() != b.ComputeHash() {
		t.Fatal("hash depends on the insertion order of payload keys")
	}
}

func TestComputeHashSurvivesJSONRoundTrip(t *testing.T) {
	entry := sampleEntry()
	normalized, err := NormalizePayload(entry.Payload)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	entry.Payload = normalized
	sealed := entry.ComputeHash()

	raw, err := json.Marshal(entry.Payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	decoded, err := DecodeJSONPayload(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	entry.Payload = decoded
	if got := entry.ComputeHash(); got != sealed {
		t.Fatalf("hash changed after a store round trip: %s != %s", got, sealed)
	}
}

// Every hashed field must be tamper-evident. The document's sketch left ID,
// RequestID and Kind outside the digest, so they could be rewritten freely.
func TestComputeHashCoversEveryField(t *testing.T) {
	base := sampleEntry()
	baseHash := base.ComputeHash()

	mutations := map[string]func(*AuditEntry){
		"ID":         func(e *AuditEntry) { e.ID = "b3f1c2a4-0000-4000-8000-000000000002" },
		"RequestID":  func(e *AuditEntry) { e.RequestID = "req-43" },
		"Timestamp":  func(e *AuditEntry) { e.Timestamp = e.Timestamp.Add(time.Nanosecond) },
		"Kind":       func(e *AuditEntry) { e.Kind = KindAdmin },
		"PrevHash":   func(e *AuditEntry) { e.PrevHash = "ff" + GenesisHash[2:] },
		"Payload":    func(e *AuditEntry) { e.Payload["verdict"] = "allow" },
		"PayloadKey": func(e *AuditEntry) { e.Payload["injected"] = true },
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			entry := sampleEntry()
			mutate(&entry)
			if entry.ComputeHash() == baseHash {
				t.Fatalf("mutating %s did not change the hash", name)
			}
		})
	}
}

// A timestamp is the same instant whatever zone it is expressed in, so it must
// hash the same. Timestamp.String() in the original sketch did not.
func TestComputeHashIsTimezoneIndependent(t *testing.T) {
	utc := sampleEntry()
	caracas := sampleEntry()
	caracas.Timestamp = caracas.Timestamp.In(time.FixedZone("-04", -4*3600))

	if utc.ComputeHash() != caracas.ComputeHash() {
		t.Fatal("hash depends on the timestamp's location")
	}
}

// Length-prefixing the fields means no shuffle of content across field
// boundaries can produce the same digest.
func TestComputeHashFieldsAreUnambiguous(t *testing.T) {
	a := sampleEntry()
	a.ID, a.RequestID = "ab", "c"

	b := sampleEntry()
	b.ID, b.RequestID = "a", "bc"

	if a.ComputeHash() == b.ComputeHash() {
		t.Fatal("field boundaries are ambiguous: concatenation collision")
	}
}

func TestSealUsesGenesisHashForFirstEntry(t *testing.T) {
	entry := sampleEntry()
	entry.PrevHash = ""

	head := entry.Seal("")
	if entry.PrevHash != GenesisHash {
		t.Fatalf("PrevHash = %q, want the genesis hash", entry.PrevHash)
	}
	if head != entry.Hash || entry.Hash == "" {
		t.Fatalf("Seal returned %q but entry.Hash is %q", head, entry.Hash)
	}
	if len(entry.Hash) != 64 {
		t.Fatalf("hash is %d hex chars, want 64", len(entry.Hash))
	}
}
