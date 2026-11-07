// Package kinds is the table of record kinds and the rules for showing their
// records: whether a record is shown (counted in the summary, printed when
// found, written to the files and used to derive findings), and which summary
// category it is counted under. Later specs add their kinds to the table.
package kinds

import (
	"slices"
	"strings"
)

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
	// record is shown only while that host is in scope, decided when it is read.
	HostAttr string
	// PortKey kinds are keyed by a target address and port. Such a record is
	// shown only while that address is port-eligible, decided when it is read.
	PortKey bool
}

// scoped reports whether showing a record of k depends on the scope.
func (k Kind) scoped() bool { return k.Entity || k.HostAttr != "" || k.PortKey }

// Summary categories of entity kinds.
const (
	Hosts      = "hosts"
	Netblocks  = "netblocks"
	Candidates = "candidates"
	Excluded   = "excluded"
)

// table is every kind, sorted by name.
var table = func() []Kind {
	t := []Kind{
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
	}
	slices.SortFunc(t, func(a, b Kind) int { return strings.Compare(a.Name, b.Name) })
	return t
}()

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
