package dnsname_test

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/recon/internal/dnsname"
)

// B7/B8: reverse names for PTR sweeps and Team Cymru lookups.
func TestReverseNames(t *testing.T) {
	cases := []struct{ addr, ptr, cymru string }{
		{"192.0.2.10", "10.2.0.192.in-addr.arpa", "10.2.0.192.origin.asn.cymru.com"},
		{"2001:db8::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
			"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.origin6.asn.cymru.com"},
	}
	for _, c := range cases {
		a := netip.MustParseAddr(c.addr)
		if got := dnsname.ReverseName(a); got != c.ptr {
			t.Errorf("ReverseName(%s) = %s, want %s", c.addr, got, c.ptr)
		}
		if got := dnsname.CymruOrigin(a); got != c.cymru {
			t.Errorf("CymruOrigin(%s) = %s, want %s", c.addr, got, c.cymru)
		}
	}
}

// B4: wildcard zones are the registrable parents of a name, nearest first.
func TestParents(t *testing.T) {
	got := dnsname.Parents("a.b.example.com")
	if !slices.Equal(got, []string{"b.example.com", "example.com"}) {
		t.Errorf("Parents = %v", got)
	}
	if got := dnsname.Parents("example.com"); len(got) != 0 {
		t.Errorf("a registrable domain has no parents, got %v", got)
	}
	if got := dnsname.Parents("a.example.co.uk"); !slices.Equal(got, []string{"example.co.uk"}) {
		t.Errorf("public suffix handling: %v", got)
	}
}

// B6: names reduce to their registrable domain.
func TestETLDPlusOne(t *testing.T) {
	for in, want := range map[string]string{"www.example.com": "example.com", "a.b.example.co.uk": "example.co.uk"} {
		if got, ok := dnsname.ETLDPlusOne(in); !ok || got != want {
			t.Errorf("ETLDPlusOne(%s) = %q, %v", in, got, ok)
		}
	}
	if _, ok := dnsname.ETLDPlusOne("com"); ok {
		t.Error("a public suffix has no registrable domain")
	}
}

// B2: permutations are deterministic, valid, unique, never the seed, and capped.
func TestPermute(t *testing.T) {
	words := []string{"dev", "staging"}
	got := dnsname.Permute("api", words, 200)
	for _, want := range []string{"api-dev", "dev-api", "api.dev", "dev.api", "apidev", "devapi", "api1", "api2"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	if slices.Contains(got, "api") {
		t.Error("the seed itself must not be generated")
	}
	if !slices.Equal(got, dnsname.Permute("api", words, 200)) {
		t.Error("not deterministic")
	}
	seen := map[string]bool{}
	for _, g := range got {
		if seen[g] {
			t.Errorf("duplicate %q", g)
		}
		seen[g] = true
	}
	if capped := dnsname.Permute("api", words, 5); len(capped) != 5 || !slices.Equal(capped, got[:5]) {
		t.Errorf("cap: %v", capped)
	}
	if n := dnsname.Permute("web07", nil, 200); !slices.Contains(n, "web08") || !slices.Contains(n, "web06") {
		t.Errorf("digit increments keep padding: %v", n)
	}
	for _, g := range dnsname.Permute(strings.Repeat("a", 60), []string{"long-word"}, 200) {
		for _, part := range strings.Split(g, ".") {
			if !dnsname.ValidLabel(part) {
				t.Errorf("invalid label generated: %q", g)
			}
		}
	}
}
