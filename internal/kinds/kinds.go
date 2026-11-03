// Package kinds is the registry of record kinds: how each is counted,
// printed and summarised. Later specs register their own kinds here.
package kinds

import "sort"

// Kind describes a record kind.
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
}

// Registry maps kind names to Kinds.
type Registry struct{ m map[string]Kind }

// Register adds or replaces a kind.
func (r *Registry) Register(k Kind) { r.m[k.Name] = k }

// Get returns a kind by name.
func (r *Registry) Get(name string) (Kind, bool) { k, ok := r.m[name]; return k, ok }

// All returns every kind sorted by name.
func (r *Registry) All() []Kind {
	out := make([]Kind, 0, len(r.m))
	for _, k := range r.m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Summary categories of entity kinds.
const (
	Hosts      = "hosts"
	Netblocks  = "netblocks"
	Candidates = "candidates"
	Excluded   = "excluded"
)

// Default returns the registry of Spec 1 kinds.
func Default() *Registry {
	r := &Registry{m: map[string]Kind{}}
	for _, k := range []Kind{
		{Name: "hostname", Singular: "host", Category: Hosts, Entity: true, Printed: true},
		{Name: "root", Singular: "root", Category: Candidates, Entity: true},
		{Name: "netblock", Singular: "netblock", Category: Netblocks, Entity: true},
		{Name: "excluded", Singular: "excluded", Category: Excluded, Entity: true},
		{Name: "resolution"},
		{Name: "web_service", Singular: "web service", Category: "web services", Printed: true},
		{Name: "open_port", Singular: "open port", Category: "open ports", Printed: true},
		{Name: "finding", Singular: "finding", Category: "findings", Printed: true},
		{Name: "url", Singular: "url", Category: "urls", Counted: true},
	} {
		r.Register(k)
	}
	return r
}
