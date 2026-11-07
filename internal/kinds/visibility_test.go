package kinds_test

import (
	"net/netip"
	"testing"

	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/inventory"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/provider"
	"github.com/rafaelh/recon/internal/scope"
	"github.com/rafaelh/recon/internal/store"
)

// world is example.com and 198.51.100.0/24, with www resolving to a dedicated
// address and cdn to a shared provider address, minus the exclusions.
func world(t *testing.T, excl ...string) *kinds.Visibility {
	t.Helper()
	d := inventory.Data{
		Resolutions: []inventory.Resolution{{Name: "www.example.com", Type: "A", Value: "203.0.113.5"}, {Name: "cdn.example.com", Type: "A", Value: "104.16.0.1"}},
		IPs:         []netip.Addr{netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("104.16.0.1")},
		Owners: map[netip.Addr]provider.Owner{
			netip.MustParseAddr("203.0.113.5"): {ASN: 64500, Holder: "ACME-NET", Known: true},
			netip.MustParseAddr("104.16.0.1"):  {ASN: 13335, Holder: "CLOUDFLARENET", Known: true},
		},
	}
	inv := inventory.New(d, provider.Default())
	var xs []input.Exclusion
	for _, e := range excl {
		x, err := input.ParseExclusion(e)
		if err != nil {
			t.Fatal(err)
		}
		xs = append(xs, x)
	}
	sc := scope.New(scope.Config{Roots: []string{"example.com"}, Netblocks: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		Exclusions: xs, Resolutions: inv.Addrs(), WildcardOnly: inv.WildcardOnly()})
	return kinds.NewVisibility(sc, inv)
}

func rec(key string, kv ...string) store.Record {
	a := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		a[kv[i]] = kv[i+1]
	}
	return store.Record{Key: key, Current: true, Attrs: a}
}

// Spec 4 D9: an open_port is shown only while its address is port-eligible.
func TestPortShown(t *testing.T) {
	for _, c := range []struct {
		name, key string
		excl      []string
		want      bool
	}{
		{"hostname-resolved address", "203.0.113.5:8080", nil, true},
		{"address in an in-scope netblock", "198.51.100.7:22", nil, true},
		{"IPv4-mapped IPv6 key", "[::ffff:203.0.113.5]:8080", nil, true},
		{"shared provider address", "104.16.0.1:443", nil, false},
		{"address nothing is known about", "192.0.2.9:80", nil, false},
		{"address excluded later", "203.0.113.5:8080", []string{"203.0.113.5/32"}, false},
		{"netblock address excluded later", "198.51.100.7:22", []string{"198.51.100.0/28"}, false},
		{"key that is not an address and port", "203.0.113.5", nil, false},
	} {
		if got := world(t, c.excl...).Shown(kinds.OpenPort, rec(c.key)); got != c.want {
			t.Errorf("%s: Shown(open_port %s) = %v, want %v", c.name, c.key, got, c.want)
		}
	}
}

// Spec 3 D17: a web record is shown while its host is in scope; without a host
// attribute the host comes from its key.
func TestWebShown(t *testing.T) {
	for _, c := range []struct {
		name string
		r    store.Record
		excl []string
		want bool
	}{
		{"in-scope host", rec("https://www.example.com", "host", "www.example.com"), nil, true},
		{"host excluded later", rec("https://www.example.com", "host", "www.example.com"), []string{"www.example.com"}, false},
		{"candidate host", rec("https://www.other.org", "host", "www.other.org"), nil, false},
		{"host from the key", rec("https://www.example.com/a"), nil, true},
		{"candidate host from the key", rec("https://www.other.org/a"), nil, false},
	} {
		v := world(t, c.excl...)
		for _, kind := range []kinds.Named{kinds.WebService, kinds.URL} {
			if got := v.Shown(kind, c.r); got != c.want {
				t.Errorf("%s: Shown(%s) = %v, want %v", c.name, kind.Name(), got, c.want)
			}
		}
	}
}

func TestOtherKindsShown(t *testing.T) {
	v := world(t)
	if !v.Shown(kinds.Finding, rec("ports|risky-port|192.0.2.9:445")) || !v.Shown(kinds.Hostname, rec("www.other.org")) {
		t.Error("kinds without a showing rule, and entities, are always shown")
	}
	var none *kinds.Visibility // before the first Scope is built
	if !none.Shown(kinds.Finding, rec("x")) || none.Shown(kinds.WebService, rec("https://www.example.com")) || none.Shown(kinds.OpenPort, rec("203.0.113.5:80")) {
		t.Error("with no Scope, only kinds whose rules need none are shown")
	}
}

func TestCategory(t *testing.T) {
	v := world(t, "old.example.com")
	for _, c := range []struct {
		kind      kinds.Named
		key, want string
	}{
		{kinds.Hostname, "www.example.com", kinds.Hosts},
		{kinds.Hostname, "www.other.org", kinds.Candidates},
		{kinds.Hostname, "old.example.com", kinds.Excluded},
		{kinds.Root, "example.com", ""},
		{kinds.Root, "other.org", kinds.Candidates},
		{kinds.Netblock, "198.51.100.0/24", kinds.Netblocks},
		{kinds.Netblock, "192.0.2.0/24", kinds.Candidates},
		{kinds.ExcludedKind, "192.0.2.9", kinds.Excluded},
		{kinds.OpenPort, "203.0.113.5:80", "open ports"},
		{kinds.OpenPort, "104.16.0.1:80", ""},
		{kinds.WebService, "https://www.other.org", ""},
		{kinds.Resolution, "www.example.com|A|203.0.113.5", ""},
	} {
		if got := v.Category(c.kind, rec(c.key)); got != c.want {
			t.Errorf("Category(%s %s) = %q, want %q", c.kind.Name(), c.key, got, c.want)
		}
	}
}

func TestPrinted(t *testing.T) {
	v := world(t)
	for _, c := range []struct {
		kind, key string
		want      bool
	}{
		{"hostname", "www.example.com", true},
		{"hostname", "www.other.org", false}, // candidates are not printed
		{"web_service", "https://www.example.com", true},
		{"web_service", "https://www.other.org", false},
		{"open_port", "104.16.0.1:80", false},
		{"finding", "email|spf-missing|example.com", true},
		{"url", "https://www.example.com/a", false}, // counted, never printed
		{"resolution", "www.example.com|A|203.0.113.5", false},
	} {
		if got := v.Printed(c.kind, rec(c.key)); got != c.want {
			t.Errorf("Printed(%s %s) = %v, want %v", c.kind, c.key, got, c.want)
		}
	}
	var none *kinds.Visibility
	if none.Printed("hostname", rec("www.example.com")) || !none.Printed("finding", rec("x")) {
		t.Error("with no Scope, only kinds whose rules need none are printed")
	}
}

// Spec 3 D17: totals count current, shown records, and list empty categories.
func TestTotals(t *testing.T) {
	gone := rec("https://www.example.com/b")
	gone.Current = false
	got := world(t).Totals(map[string][]store.Record{
		"hostname": {rec("www.example.com"), rec("www.other.org")},
		"url":      {rec("https://www.example.com/a"), rec("https://www.other.org/a"), gone},
	})
	want := map[string]int{kinds.Hosts: 1, kinds.Candidates: 1, "urls": 1, "ips": 0, "unresolved names": 0, "web services": 0, "open ports": 0, "findings": 0}
	if len(got) != len(want) {
		t.Errorf("totals = %v, want %v", got, want)
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("totals[%s] = %d, want %d", k, got[k], n)
		}
	}
}
