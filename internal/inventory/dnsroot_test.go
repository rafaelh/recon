package inventory_test

import (
	"maps"
	"net/netip"
	"slices"
	"testing"

	"github.com/rafaelh/recon/internal/inventory"
	"github.com/rafaelh/recon/internal/provider"
)

// NS, SOA, TXT and CAA rows are not addresses, aliases or zones: adding them,
// even with values that look like addresses or provider hosts, changes
// nothing the inventory reports.
func TestRootRecordRowsChangeNothing(t *testing.T) {
	var base inventory.Data
	base.Wildcards = []inventory.Wildcard{{Zone: "example.com", Addrs: ips("203.0.113.1")}}
	resolve(&base, "www.example.com", "203.0.113.50")
	resolve(&base, "wild.example.com", "203.0.113.1")
	base.Owners = map[netip.Addr]provider.Owner{ip("203.0.113.50"): {ASN: 64500, Holder: "ACME-NET", Known: true}}

	extra := base
	extra.Resolutions = append(slices.Clone(base.Resolutions), []inventory.Resolution{
		{Name: "example.com", Type: "NS", Value: "ns1.cloudfront.net"},
		{Name: "example.com", Type: "SOA", Value: "ns1.cloudfront.net hostmaster@example.com"},
		{Name: "example.com", Type: "TXT", Value: "203.0.113.9"},
		{Name: "www.example.com", Type: "TXT", Value: "203.0.113.10"},
		{Name: "example.com", Type: "CAA", Value: `0 issue "d111.cloudfront.net"`},
		{Name: "wild.example.com", Type: "TXT", Value: "203.0.113.50"},
	}...)

	db := provider.Default()
	a, b := inventory.New(base, db), inventory.New(extra, db)
	sa, sb := newScope(a, base), newScope(b, extra)

	if !maps.EqualFunc(a.Addrs(), b.Addrs(), slices.Equal) {
		t.Errorf("addresses changed: %v -> %v", a.Addrs(), b.Addrs())
	}
	if !maps.Equal(a.WildcardOnly(), b.WildcardOnly()) {
		t.Errorf("wildcard-only changed: %v -> %v", a.WildcardOnly(), b.WildcardOnly())
	}
	for _, addr := range []string{"203.0.113.9", "203.0.113.10", "203.0.113.50", "203.0.113.1"} {
		if a.PortEligible(ip(addr), sa) != b.PortEligible(ip(addr), sb) {
			t.Errorf("port eligibility of %s changed", addr)
		}
	}
	if b.PortEligible(ip("203.0.113.9"), sb) {
		t.Error("an address inside a TXT value is port-eligible")
	}
	if len(a.ProviderHosts(sa)) != len(b.ProviderHosts(sb)) {
		t.Errorf("provider hosts changed: %v -> %v", a.ProviderHosts(sa), b.ProviderHosts(sb))
	}
	if !slices.Equal(a.ProbeHostnames(sa), b.ProbeHostnames(sb)) {
		t.Errorf("probe hostnames changed: %v -> %v", a.ProbeHostnames(sa), b.ProbeHostnames(sb))
	}
}
