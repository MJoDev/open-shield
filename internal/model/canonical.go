package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

// CanonicalJSON encodes a value as JSON with a single possible byte
// representation: object keys sorted, no insignificant whitespace, no HTML
// escaping. Two payloads that are equal as data always encode identically,
// which is what makes the audit hash chain verifiable across processes and
// across a round trip through the database.
//
// Go's encoding/json already sorts map keys, but the guarantee is not stated
// for every value shape we handle here, and the hash of the entire forensic
// history depends on it — so the encoding is written out explicitly.
func CanonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
		return nil

	case bool:
		buf.WriteString(strconv.FormatBool(t))
		return nil

	case string:
		return writeCanonicalString(buf, t)

	case json.Number:
		// Preserve the literal exactly as it was parsed. This is why payloads
		// are decoded with UseNumber both here and in the store: a float64
		// round trip could turn 1.50 into 1.5 and break the chain.
		if t == "" {
			return fmt.Errorf("canonical json: empty json.Number")
		}
		buf.WriteString(string(t))
		return nil

	case float64, float32, int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		// Delegate to encoding/json so the digits match what the encoder would
		// have written when the value was stored.
		b, err := json.Marshal(t)
		if err != nil {
			return err
		}
		buf.Write(b)
		return nil

	case []any:
		buf.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil

	case map[string]any:
		return writeCanonicalObject(buf, t)

	case map[string]string:
		obj := make(map[string]any, len(t))
		for k, val := range t {
			obj[k] = val
		}
		return writeCanonicalObject(buf, obj)

	default:
		// Anything else (a struct, a named type) is normalised through
		// encoding/json first, then re-encoded canonically.
		normalized, err := normalizeValue(t)
		if err != nil {
			return err
		}
		if _, again := normalized.(map[string]any); !again {
			if _, isSlice := normalized.([]any); !isSlice {
				// Scalar after normalisation: encode it directly to avoid
				// recursing forever on an unsupported type.
				b, err := json.Marshal(normalized)
				if err != nil {
					return err
				}
				buf.Write(b)
				return nil
			}
		}
		return writeCanonical(buf, normalized)
	}
}

func writeCanonicalObject(buf *bytes.Buffer, obj map[string]any) error {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := writeCanonicalString(buf, k); err != nil {
			return err
		}
		buf.WriteByte(':')
		if err := writeCanonical(buf, obj[k]); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

// writeCanonicalString encodes a string with HTML escaping disabled, so that
// "<script>" hashes as itself rather than as "<script>". Blocked XSS
// payloads land in audit entries constantly; escaping them would make the
// stored bytes and the hashed bytes disagree after a database round trip.
func writeCanonicalString(buf *bytes.Buffer, s string) error {
	var tmp bytes.Buffer
	enc := json.NewEncoder(&tmp)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return err
	}
	// Encode appends a newline.
	buf.Write(bytes.TrimRight(tmp.Bytes(), "\n"))
	return nil
}

// NormalizePayload converts a payload into the exact value shape it will have
// when it is read back from the audit store: objects as map[string]any, arrays
// as []any and every number as json.Number.
//
// Sealing an entry over the normalised payload is what makes verification
// stable. Without it an entry sealed from a Go float64 could be re-read as a
// json.Number that formats differently, and the chain would report tampering
// where none happened.
func NormalizePayload(payload map[string]any) (map[string]any, error) {
	if payload == nil {
		return map[string]any{}, nil
	}
	v, err := normalizeValue(payload)
	if err != nil {
		return nil, err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("canonical json: payload normalised to %T, want object", v)
	}
	return obj, nil
}

func normalizeValue(v any) (any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonical json: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("canonical json: %w", err)
	}
	return out, nil
}

// DecodeJSONPayload parses stored JSON into the normalised shape used for
// hashing. The audit store uses it on every read.
func DecodeJSONPayload(raw []byte) (map[string]any, error) {
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("decode audit payload: %w", err)
	}
	if out == nil {
		return map[string]any{}, nil
	}
	return out, nil
}
