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
	// HostAttr names the attribute holding the host of a web record. Such a
	// record is shown (counted, printed, written to a CSV) only while that host
	// is in scope, which is decided when it is read.
	HostAttr string
	// PortKey kinds are keyed by a target address and port. Such a record is
	// shown only while that address is port-eligible, decided when it is read.
	PortKey bool
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

// Default returns the registry of the kinds registered so far.
func Default() *Registry {
	r := &Registry{m: map[string]Kind{}}
	for _, k := range []Kind{
		{Name: "hostname", Singular: "host", Category: Hosts, Entity: true, Printed: true},
		{Name: "root", Singular: "root", Category: Candidates, Entity: true},
		{Name: "netblock", Singular: "netblock", Category: Netblocks, Entity: true},
		{Name: "excluded", Singular: "excluded", Category: Excluded, Entity: true},
		{Name: "resolution"},
		{Name: "ip", Singular: "ip", Category: "ips", Counted: true},
		{Name: "unresolved", Singular: "unresolved name", Category: "unresolved names", Counted: true},
		{Name: "wildcard"},
		{Name: "ip_owner"},
		{Name: "ip_hostname"},
		{Name: "provider_range"},
		{Name: "web_service", Singular: "web service", Category: "web services", Printed: true, HostAttr: "host"},
		{Name: "http_port"},
		{Name: "open_port", Singular: "open port", Category: "open ports", Printed: true, PortKey: true},
		{Name: "finding", Singular: "finding", Category: "findings", Printed: true},
		// Spec 5 evidence: stages store these, the findings package derives findings from them.
		{Name: "takeover_http"},
		{Name: "storage"},
		{Name: "storage_account"},
		{Name: "storage_object"},
		{Name: "storage_ref"},
		{Name: "sensitive_hit"},
		{Name: "email_posture"},
		{Name: "url", Singular: "url", Category: "urls", Counted: true, HostAttr: "host"},
	} {
		r.Register(k)
	}
	return r
}
