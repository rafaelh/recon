package config

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
)

const mask = "****"

// Secret is an API key. It never formats its value; use Reveal to read it.
type Secret string

func (Secret) String() string   { return mask }
func (Secret) GoString() string { return `"` + mask + `"` }
func (Secret) Format(f fmt.State, verb rune) {
	fmt.Fprint(f, mask)
}
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + mask + `"`), nil }
func (Secret) MarshalText() ([]byte, error) { return []byte(mask), nil }

// Reveal returns the secret value.
func (s Secret) Reveal() string { return string(s) }

// Redactor masks configured key values in strings.
type Redactor struct{ values []string }

// NewRedactor builds a Redactor from key values. Empty values are ignored.
// Each value's URL-encoded forms are masked too, since net/http errors embed
// the request URL with any query-parameter key percent-encoded.
func NewRedactor(values ...string) *Redactor {
	r := &Redactor{}
	for _, v := range values {
		if v == "" {
			continue
		}
		r.values = append(r.values, v)
		for _, enc := range []string{url.QueryEscape(v), url.PathEscape(v)} {
			if enc != v && !slices.Contains(r.values, enc) {
				r.values = append(r.values, enc)
			}
		}
	}
	return r
}

// Redact replaces every key value in s with a mask. A nil Redactor passes s through.
func (r *Redactor) Redact(s string) string {
	if r == nil {
		return s
	}
	for _, v := range r.values {
		s = strings.ReplaceAll(s, v, mask)
	}
	return s
}

// Any redacts every string reachable in v (maps, slices and strings).
func (r *Redactor) Any(v any) any {
	if r == nil || len(r.values) == 0 {
		return v
	}
	switch x := v.(type) {
	case string:
		return r.Redact(x)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[r.Redact(k)] = r.Any(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = r.Any(e)
		}
		return out
	case []string:
		out := make([]string, len(x))
		for i, e := range x {
			out[i] = r.Redact(e)
		}
		return out
	case []map[string]any:
		out := make([]map[string]any, len(x))
		for i, e := range x {
			out[i] = r.Any(e).(map[string]any)
		}
		return out
	case map[string]string:
		out := make(map[string]string, len(x))
		for k, e := range x {
			out[r.Redact(k)] = r.Redact(e)
		}
		return out
	case map[string]int:
		out := make(map[string]int, len(x))
		for k, e := range x {
			out[r.Redact(k)] = e
		}
		return out
	}
	return v
}
