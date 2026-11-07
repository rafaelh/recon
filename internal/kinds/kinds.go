// Package kinds defines the record kinds: for each, its name, the attributes
// its observations carry (a struct, in table.go), and how its records are shown
// (counted in the summary, printed when found, written to the files and used to
// derive findings; see Visibility).
//
// Stages write observations through a kind's handle and readers decode records
// through the same handle, so a kind's attributes are defined once. The JSON
// names of the attribute structs are what the state database stores: renaming
// one breaks resuming an existing engagement.
package kinds

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/rafaelh/recon/internal/store"
)

// Kind describes how the records of a kind are shown.
type Kind struct {
	Name string
	// Singular and Category are the console label of one record ("web service")
	// and the summary category ("web services").
	Singular, Category string
	// Entity kinds (hostname, root, netblock, excluded) are classified against
	// the scope: their category is in-scope, candidate or excluded.
	Entity bool
	// Printed kinds are printed as a line the first time they are seen in an engagement.
	Printed bool
	// Counted kinds are only counted, never printed (URLs).
	Counted bool
	// HostAttr names the attribute holding the host of a web record. Such a
	// record is shown only while that host is in scope, decided when it is read.
	HostAttr string
	// PortKey kinds are keyed by a target address and port. Such a record is
	// shown only while that address is port-eligible, decided when it is read.
	PortKey bool
	// HostKey kinds are keyed by a hostname. Such a record is shown only while
	// that name is in scope, decided when it is read.
	HostKey bool
}

// scoped reports whether showing a record of k depends on the scope.
func (k Kind) scoped() bool { return k.Entity || k.HostAttr != "" || k.PortKey || k.HostKey }

// Summary categories of entity kinds.
const (
	Hosts      = "hosts"
	Netblocks  = "netblocks"
	Candidates = "candidates"
	Excluded   = "excluded"
)

// Named is a kind handle: an Of or a Bare.
type Named interface {
	Name() string
	kind() Kind
}

// Of is the handle of a kind whose observations carry attributes A. Its zero
// value is not usable; the handles are the variables in table.go.
type Of[A any] struct{ k Kind }

// Name is the kind's name, as the store keys its records.
func (k Of[A]) Name() string { return k.k.Name }

func (k Of[A]) kind() Kind { return k.k }

// Obs is an observation of the kind.
func (k Of[A]) Obs(key string, a A) store.Obs {
	return store.Obs{Kind: k.k.Name, Key: key, Attrs: encode(a)}
}

// Attrs decodes a record's merged attributes, as encoding/json would from the
// stored JSON. A stored value that does not fit its field (a record written
// before the field's type changed) decodes as the field's zero value.
func (k Of[A]) Attrs(r store.Record) A {
	var a A
	if len(r.Attrs) > 0 {
		decode(r.Attrs, &a)
	}
	return a
}

// Bare is the handle of a kind whose observations carry no attributes.
type Bare struct{ k Kind }

// Name is the kind's name, as the store keys its records.
func (k Bare) Name() string { return k.k.Name }

func (k Bare) kind() Kind { return k.k }

// Obs is an observation of the kind.
func (k Bare) Obs(key string) store.Obs { return store.Obs{Kind: k.k.Name, Key: key} }

// encode turns attributes into the map the store keeps, in the form the store
// returns them (numbers as float64, lists as []any).
func encode(a any) map[string]any {
	b, err := json.Marshal(a)
	if err != nil {
		panic(fmt.Sprintf("kinds: attributes %T do not encode: %v", a, err)) // a programming error
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		panic(fmt.Sprintf("kinds: attributes %T are not an object: %v", a, err))
	}
	return m
}

var table []Kind // sorted by name once the handles are defined

func define[A any](k Kind) Of[A] { table = append(table, k); return Of[A]{k} }

func defineBare(k Kind) Bare { table = append(table, k); return Bare{k} }

func init() {
	slices.SortFunc(table, func(a, b Kind) int { return strings.Compare(a.Name, b.Name) })
}

// Get returns a kind by name.
func Get(name string) (Kind, bool) {
	i, ok := slices.BinarySearchFunc(table, name, func(k Kind, n string) int { return strings.Compare(k.Name, n) })
	if !ok {
		return Kind{}, false
	}
	return table[i], true
}

// All returns every kind sorted by name.
func All() []Kind { return slices.Clone(table) }

// Size is a byte count, or "<n>+" when the body was cut short and its real
// size is unknown. An exact size is stored as a number.
type Size string

// SizeOf is an exact size.
func SizeOf(n int64) Size { return Size(strconv.FormatInt(n, 10)) }

func (s Size) MarshalJSON() ([]byte, error) {
	if _, err := strconv.ParseInt(string(s), 10, 64); err == nil {
		return []byte(s), nil
	}
	return json.Marshal(string(s))
}

func (s *Size) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err == nil {
		*s = Size(str)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*s = Size(n.String())
	return nil
}
