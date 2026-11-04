package scope_test

import (
	"net/netip"
	"testing"

	"github.com/rafaelh/recon/internal/scope"
)

// Spec 3 D17: the one function that decides whether a web service or URL host
// is shown. An IP literal is in scope iff it is inside an in-scope netblock and
// not excluded; a name iff it classifies as in scope.
func TestWebHostInScope(t *testing.T) {
	s := scope.New(scope.Config{
		Roots:      []string{"example.com"},
		Netblocks:  []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("2001:db8:1::/64")},
		Exclusions: excl(t, "admin.example.com", "198.51.100.128/25"),
		Resolutions: map[string][]netip.Addr{
			"db.example.com": addrs("198.51.100.200"),
		},
	})
	for _, c := range []struct {
		host string
		want bool
	}{
		{"www.example.com", true},
		{"WWW.Example.COM.", true},
		{"example.org", false},       // candidate
		{"admin.example.com", false}, // excluded by name
		{"db.example.com", false},    // resolves into an excluded CIDR
		{"198.51.100.7", true},
		{"198.51.100.200", false}, // in scope, but in an excluded CIDR
		{"203.0.113.9", false},    // outside every netblock
		{"2001:db8:1::5", true},
		{"2001:db8:2::5", false},
		{"[2001:db8:1::5]", false}, // brackets are a URL form, not a host
		{"", false},
	} {
		if got := s.WebHostInScope(c.host); got != c.want {
			t.Errorf("WebHostInScope(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}
