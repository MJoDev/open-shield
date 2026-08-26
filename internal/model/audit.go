package model

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"time"
)

// GenesisHash is the PrevHash of the first entry in a chain: 64 zeros, the
// width of a hex-encoded SHA-256 digest.
var GenesisHash = strings.Repeat("0", 64)

// AuditEntry is one link of the forensic chain described in section 6.2. Each
// entry carries the hash of the previous one, so removing or altering an entry
// in the middle of the history breaks every hash after it.
type AuditEntry struct {
	ID        string         `json:"id"`         // UUID of this entry
	RequestID string         `json:"request_id"` // correlates with the original HTTP request
	Timestamp time.Time      `json:"timestamp"`
	Kind      string         `json:"kind"` // KindTraffic | KindSystem | KindAdmin
	Payload   map[string]any `json:"payload"`
	PrevHash  string         `json:"prev_hash"`
	Hash      string         `json:"hash"`
}

// ComputeHash derives the entry's hash from its content and the previous hash.
//
// The technical document (§6.2) sketches this as
//
//	sha256(PrevHash + Timestamp.String() + fmt.Sprint(Payload))
//
// which cannot work in practice: Payload is a map, and Go randomises map
// iteration order on every run, so the same entry hashes differently each time
// and VerifyChain would report tampering on an intact chain. Timestamp.String()
// has the same problem in a smaller way — its output depends on the location
// and on whether a monotonic reading is attached.
//
// The fix is a canonical encoding. Every field is serialised deterministically
// (sorted keys, UTC RFC3339Nano) and length-prefixed before hashing, so that no
// combination of field values can be re-split into a different set of fields.
// ID, RequestID and Kind are hashed too — in the sketch they were outside the
// digest and could be rewritten without breaking the chain.
func (e AuditEntry) ComputeHash() string {
	payload, err := CanonicalJSON(e.Payload)
	if err != nil {
		// CanonicalJSON only fails on values that cannot appear in an entry
		// read back from the store (channels, funcs). Marking the digest keeps
		// the failure loud and verifiable instead of silently hashing nothing.
		payload = []byte("\x00uncanonicalizable")
	}

	h := sha256.New()
	writeField(h, []byte(e.PrevHash))
	writeField(h, []byte(e.ID))
	writeField(h, []byte(e.RequestID))
	writeField(h, []byte(e.Timestamp.UTC().Format(time.RFC3339Nano)))
	writeField(h, []byte(e.Kind))
	writeField(h, payload)
	return hex.EncodeToString(h.Sum(nil))
}

// writeField length-prefixes a field so that concatenation stays unambiguous:
// {"ab", "c"} and {"a", "bc"} must not produce the same digest.
func writeField(h interface{ Write([]byte) (int, error) }, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(b)
}

// Seal fills PrevHash and Hash, linking the entry to the current head of the
// chain. It returns the new head.
func (e *AuditEntry) Seal(prevHash string) string {
	if prevHash == "" {
		prevHash = GenesisHash
	}
	e.PrevHash = prevHash
	e.Hash = e.ComputeHash()
	return e.Hash
}
