package scope_test

import (
	"net/netip"
	"testing"

	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/scope"
)

func excl(t *testing.T, entries ...string) []input.Exclusion {
	t.Helper()
	var out []input.Exclusion
	for _, e := range entries {
		x, err := input.ParseExclusion(e)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, x)
	}
	return out
}

func addrs(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, a := range s {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

// B16, definitions: classification of hostnames.
func TestClassifyHost(t *testing.T) {
	s := scope.New(scope.Config{
		Roots:      []string{"example.com"},
		Exclusions: excl(t, "admin.example.com", "*.dev.example.com", "198.51.100.0/24"),
		Resolutions: map[string][]netip.Addr{
			"db.example.com":    addrs("198.51.100.7"),
			"www.example.com":   addrs("203.0.113.5"),
			"other.example.org": addrs("198.51.100.9"),
		},
	})
	for _, c := range []struct {
		host string
		want scope.Class
	}{
		{"example.com", scope.InScope},
		{"www.example.com", scope.InScope},
		{"a.b.example.com", scope.InScope},
		{"WWW.Example.COM.", scope.InScope},
		{"notexample.com", scope.Candidate},
		{"example.com.evil.net", scope.Candidate},
		{"admin.example.com", scope.Excluded},
		{"x.dev.example.com", scope.Excluded},
		{"dev.example.com", scope.InScope},
		{"db.example.com", scope.Excluded},    // resolves into an excluded CIDR
		{"other.example.org", scope.Excluded}, // out of scope but excluded still wins
	} {
		got := s.ClassifyHost(c.host)
		if got.Class != c.want {
			t.Errorf("%s = %v (%s), want %v", c.host, got.Class, got.Reason, c.want)
		}
		if got.Class == scope.Excluded && got.Reason == "" {
			t.Errorf("%s excluded without a reason", c.host)
		}
	}
}

func TestExcludedAddr(t *testing.T) {
	s := scope.New(scope.Config{
		Roots:       []string{"example.com"},
		Exclusions:  excl(t, "admin.example.com", "198.51.100.0/24"),
		Resolutions: map[string][]netip.Addr{"admin.example.com": addrs("203.0.113.50"), "www.example.com": addrs("203.0.113.5")},
	})
	if ok, why := s.ExcludedAddr(netip.MustParseAddr("198.51.100.1")); !ok || why == "" {
		t.Errorf("cidr: %v %q", ok, why)
	}
	if ok, why := s.ExcludedAddr(netip.MustParseAddr("203.0.113.50")); !ok || why == "" {
		t.Errorf("address of excluded host: %v %q", ok, why)
	}
	if ok, _ := s.ExcludedAddr(netip.MustParseAddr("203.0.113.5")); ok {
		t.Error("address of a normal host is not excluded")
	}
	if !s.ExcludedCIDR(netip.MustParseAddr("198.51.100.1")) || s.ExcludedCIDR(netip.MustParseAddr("203.0.113.50")) {
		t.Error("ExcludedCIDR must only report CIDR exclusions")
	}
}

func TestInScopeIP(t *testing.T) {
	s := scope.New(scope.Config{
		Netblocks:  []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		Exclusions: excl(t, "203.0.113.128/25"),
	})
	if !s.InScopeIP(netip.MustParseAddr("203.0.113.10")) {
		t.Error("in netblock")
	}
	if s.InScopeIP(netip.MustParseAddr("203.0.114.10")) {
		t.Error("outside netblock")
	}
	// IPs that hostnames resolve to are not themselves in scope.
	s2 := scope.New(scope.Config{Roots: []string{"example.com"}, Resolutions: map[string][]netip.Addr{"a.example.com": addrs("192.0.2.1")}})
	if s2.InScopeIP(netip.MustParseAddr("192.0.2.1")) {
		t.Error("resolved IP must not be in scope by itself")
	}
}

// B15: overlapping netblocks are counted once; IPv6 is not counted.
func TestIPv4AddressCount(t *testing.T) {
	s := scope.New(scope.Config{Netblocks: []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("10.0.0.0/25"),   // inside the /24
		netip.MustParsePrefix("10.0.1.0/24"),   // adjacent
		netip.MustParsePrefix("10.0.0.128/25"), // inside the /24
		netip.MustParsePrefix("2001:db8::/32"),
	}})
	if got := s.IPv4AddressCount(); got != 512 {
		t.Errorf("count = %d, want 512", got)
	}
	empty := scope.New(scope.Config{})
	if empty.IPv4AddressCount() != 0 {
		t.Error("empty")
	}
}

// B9, D18: the single eligibility function.
func TestPortEligible(t *testing.T) {
	res := map[string][]netip.Addr{
		"www.example.com":   addrs("203.0.113.5"),
		"wild.example.com":  addrs("203.0.113.20"),
		"admin.example.com": addrs("203.0.113.6", "198.51.100.7"),
		"v6.example.com":    addrs("2001:db8::5"),
		"db.example.com":    addrs("192.0.2.9"),
		"other.example.org": addrs("203.0.113.40"),
	}
	s := scope.New(scope.Config{
		Roots:        []string{"example.com"},
		Netblocks:    []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		Exclusions:   excl(t, "admin.example.com", "192.0.2.0/24"),
		Resolutions:  res,
		WildcardOnly: map[string]bool{"wild.example.com": true},
	})
	cases := []struct {
		name            string
		addr            string
		shared, unknown bool
		want            bool
	}{
		{"in-scope IP", "198.51.100.1", false, false, true},
		{"in-scope IP, shared", "198.51.100.1", true, false, true},
		{"hostname-resolved IP", "203.0.113.5", false, false, true},
		{"hostname-resolved IP that is shared", "203.0.113.5", true, false, false},
		{"hostname-resolved IP whose owner is unknown", "203.0.113.5", false, true, false},
		{"IPv6 hostname-resolved IP", "2001:db8::5", false, false, true},
		{"wildcard-only name does not make an IP eligible", "203.0.113.20", false, false, false},
		{"address of an excluded host", "203.0.113.6", false, false, false},
		{"address of an excluded host whose owner is unknown", "203.0.113.6", false, true, false},
		{"in-scope shared IP that an excluded host also uses", "198.51.100.7", true, false, true},
		{"in-scope IP of an excluded host, not shared", "198.51.100.7", false, false, false},
		{"excluded CIDR always refuses", "192.0.2.9", true, false, false},
		{"candidate hostname's IP", "203.0.113.40", false, false, false},
		{"unrelated IP", "8.8.8.8", false, false, false},
	}
	for _, c := range cases {
		ok, why, _ := s.PortEligible(netip.MustParseAddr(c.addr), c.shared, !c.unknown)
		if ok != c.want {
			t.Errorf("%s: PortEligible = %v (%s), want %v", c.name, ok, why, c.want)
		}
		if !ok && why == "" {
			t.Errorf("%s: a refusal needs a reason", c.name)
		}
	}
}
