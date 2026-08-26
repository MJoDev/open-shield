package model

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
	"unicode/utf8"
)

// The hash chain is the project's central claim, and the property it rests on
// is narrow: the same entry must hash to the same value every time, including
// after a round trip through PostgreSQL. The table-driven tests next door check
// that against inputs a person thought of. These check it against inputs nobody
// thought of.
//
// The seed corpora are the shapes real payloads take — nested maps, unicode,
// numbers that do not survive float64, HTML from a blocked payload. `go test`
// runs those alone; the nightly workflow runs the generator with -fuzz.

func seedPayloads(f *testing.F) {
	for _, seed := range []string{
		`{}`,
		`{"ip":"203.0.113.7","verdict":"block","rule":"sqli"}`,
		`{"nested":{"b":2,"a":1},"list":[3,1,2]}`,
		`{"decision_ms":1.50}`,
		`{"big":123456789012345678901234567890}`,
		`{"tiny":0.000000000000000001}`,
		`{"unicode":"acción · 日本語 · áéí"}`,
		`{"html":"<script>alert(1)</script>"}`,
		`{"empty_list":[],"empty_obj":{},"null":null,"true":true}`,
		`{"reason":"sqli signature \"union_select\" matched in query: …x' UNION SELECT…"}`,
	} {
		f.Add([]byte(seed))
	}
}

// FuzzCanonicalJSONIsDeterministic is the property VerifyChain depends on: the
// same payload always serialises to the same bytes, whatever order Go happens
// to iterate its map in this run.
func FuzzCanonicalJSONIsDeterministic(f *testing.F) {
	seedPayloads(f)

	f.Fuzz(func(t *testing.T, raw []byte) {
		payload, err := DecodeJSONPayload(raw)
		if err != nil {
			t.Skip() // not a JSON object; the store never holds one
		}

		first, err := CanonicalJSON(payload)
		if err != nil {
			t.Fatalf("CanonicalJSON on a decoded payload: %v", err)
		}
		for i := 0; i < 8; i++ {
			again, err := CanonicalJSON(payload)
			if err != nil {
				t.Fatalf("CanonicalJSON: %v", err)
			}
			if !bytes.Equal(first, again) {
				t.Fatalf("canonical form is not stable:\n  %s\n  %s", first, again)
			}
		}
	})
}

// FuzzCanonicalJSONSurvivesItsOwnOutput checks the round trip the store
// performs on every read: canonical bytes go into jsonb, come back out, and
// must canonicalise to the same thing. If they do not, an untouched chain
// stops verifying after a restart.
func FuzzCanonicalJSONSurvivesItsOwnOutput(f *testing.F) {
	seedPayloads(f)

	f.Fuzz(func(t *testing.T, raw []byte) {
		payload, err := DecodeJSONPayload(raw)
		if err != nil {
			t.Skip()
		}
		normalized, err := NormalizePayload(payload)
		if err != nil {
			t.Skip() // cannot occur for values that came out of JSON
		}

		first, err := CanonicalJSON(normalized)
		if err != nil {
			t.Fatalf("CanonicalJSON: %v", err)
		}

		reread, err := DecodeJSONPayload(first)
		if err != nil {
			t.Fatalf("canonical output does not parse as JSON: %v\n  %s", err, first)
		}
		second, err := CanonicalJSON(reread)
		if err != nil {
			t.Fatalf("CanonicalJSON on the re-read payload: %v", err)
		}

		if !bytes.Equal(first, second) {
			t.Fatalf("a round trip changed the canonical form:\n  before: %s\n  after:  %s", first, second)
		}
	})
}

// FuzzEntryHashSurvivesAStoreRoundTrip is the same property one level up: seal
// an entry, put it through the encode/decode the store performs, and the hash
// recomputed from what comes back must match what went in.
//
// This is what NormalizePayload and the microsecond truncation in Writer.build
// exist for, and it is where a regression in either would show up.
func FuzzEntryHashSurvivesAStoreRoundTrip(f *testing.F) {
	f.Add([]byte(`{"ip":"203.0.113.7","decision_ms":1.50}`), "traffic", "req-1", int64(0))
	f.Add([]byte(`{"actor":"admin","enabled":true}`), "admin", "", int64(1_700_000_000_000_000))
	f.Add([]byte(`{"n":9007199254740993}`), "system", "req-ñ", int64(-1))

	f.Fuzz(func(t *testing.T, raw []byte, kind, requestID string, micros int64) {
		// encoding/json replaces invalid UTF-8 with U+FFFD on the way out, so a
		// field that is not valid UTF-8 cannot survive a round trip. It cannot
		// reach the store either: PostgreSQL rejects it at the jsonb boundary.
		if !utf8.ValidString(kind) || !utf8.ValidString(requestID) {
			t.Skip()
		}

		payload, err := DecodeJSONPayload(raw)
		if err != nil {
			t.Skip()
		}
		normalized, err := NormalizePayload(payload)
		if err != nil {
			t.Skip()
		}

		entry := AuditEntry{
			ID:        "0f8fad5b-d9cb-469f-a165-70867728950e",
			RequestID: requestID,
			// The store keeps microseconds, so the value that is hashed is
			// truncated to what will come back on a read.
			Timestamp: time.UnixMicro(micros).UTC().Truncate(time.Microsecond),
			Kind:      kind,
			Payload:   normalized,
		}
		sealed := entry.Seal(GenesisHash)

		encoded, err := json.Marshal(entry)
		if err != nil {
			t.Skip() // an entry that cannot be encoded never reaches the store
		}
		var restored AuditEntry
		dec := json.NewDecoder(bytes.NewReader(encoded))
		dec.UseNumber()
		if err := dec.Decode(&restored); err != nil {
			t.Fatalf("a sealed entry did not decode: %v\n  %s", err, encoded)
		}

		if got := restored.ComputeHash(); got != sealed {
			t.Fatalf("the hash changed across a round trip\n  sealed:  %s\n  reread:  %s\n  payload: %s",
				sealed, got, encoded)
		}
	})
}

// FuzzHashFieldsCannotBeRepartitioned is why every field is length-prefixed
// with eight bytes before hashing.
//
// Without the prefix, sha256(prevHash + id + requestID + …) would let an
// attacker move a byte from the end of one field to the start of the next and
// produce the same digest for a different entry — rewriting who made a request
// while the chain still verified. Splitting the same total bytes differently
// must always give a different hash.
func FuzzHashFieldsCannotBeRepartitioned(f *testing.F) {
	f.Add("abc", "def")
	f.Add("", "abcdef")
	f.Add("req", "-1")
	f.Add("a", "")

	f.Fuzz(func(t *testing.T, left, right string) {
		joined := left + right
		// Every split is hashed, so the work is quadratic in the length. The
		// property does not get truer with longer inputs.
		if len(joined) == 0 || len(joined) > 64 {
			t.Skip()
		}

		base := AuditEntry{
			Timestamp: time.UnixMicro(0).UTC(),
			Kind:      "traffic",
			Payload:   map[string]any{},
			PrevHash:  GenesisHash,
		}

		a := base
		a.ID, a.RequestID = left, right

		// Every other split of the same bytes across the same two fields.
		for i := 0; i <= len(joined); i++ {
			if i == len(left) {
				continue
			}
			b := base
			b.ID, b.RequestID = joined[:i], joined[i:]

			if a.ComputeHash() == b.ComputeHash() {
				t.Fatalf("(%q,%q) and (%q,%q) hash the same; the fields are ambiguous",
					a.ID, a.RequestID, b.ID, b.RequestID)
			}
		}
	})
}
