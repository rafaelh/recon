package kinds_test

import (
	"testing"

	"github.com/rafaelh/recon/internal/kinds"
)

// A third party is shown while its root is in scope and, when it names a
// domain, only while that domain is not. The rule is read-time: a root added
// later hides the row.
func TestThirdPartyShown(t *testing.T) {
	for _, c := range []struct {
		name string
		excl []string
		rec  []string
		want bool
	}{
		{"a name server's domain outside scope", nil, []string{"root", "example.com", "domain", "cloudflare.com"}, true},
		{"a verification has no domain", nil, []string{"root", "example.com", "provider", "Google"}, true},
		{"the domain is in scope", nil, []string{"root", "example.com", "domain", "ns.example.com"}, false},
		{"the root is not in scope", nil, []string{"root", "other.test", "domain", "cloudflare.com"}, false},
		{"the root is excluded", []string{"example.com"}, []string{"root", "example.com", "domain", "cloudflare.com"}, false},
		{"the domain is excluded, so not in scope", []string{"dns-host.test"}, []string{"root", "example.com", "domain", "dns-host.test"}, true},
	} {
		r := rec("example.com|x|y", c.rec...)
		if got := world(t, c.excl...).Shown(kinds.ThirdParty, r); got != c.want {
			t.Errorf("%s: shown = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestThirdPartyCountedAndPrinted(t *testing.T) {
	k, ok := kinds.Get("third_party")
	if !ok || k.Category != "third parties" || k.Singular != "third party" || !k.Printed || k.Entity {
		t.Fatalf("third_party = %+v, %v", k, ok)
	}
	v := world(t)
	shown := rec("example.com|ns|cloudflare.com", "root", "example.com", "domain", "cloudflare.com")
	hidden := rec("example.com|ns|ns.example.com", "root", "example.com", "domain", "ns.example.com")
	if got := v.Category(kinds.ThirdParty, shown); got != "third parties" {
		t.Errorf("category = %q", got)
	}
	if got := v.Category(kinds.ThirdParty, hidden); got != "" {
		t.Errorf("a hidden third party is counted under %q", got)
	}
	if !v.Printed("third_party", shown) || v.Printed("third_party", hidden) {
		t.Error("only a shown third party is printed")
	}
	// Without a scope, a record whose showing depends on it is not shown.
	var none *kinds.Visibility
	if none.Shown(kinds.ThirdParty, shown) {
		t.Error("shown without a scope")
	}
}

// A third party describes its own found line.
func TestThirdPartyFound(t *testing.T) {
	k, _ := kinds.Get("third_party")
	if k.Found == nil {
		t.Fatal("third_party has no Found")
	}
	for _, c := range []struct {
		rec  []string
		text string
		plat string
	}{
		{[]string{"root", "example.com", "mechanism", "txt-verification", "provider", "Google"}, "third-party Google via txt-verification on example.com", "Google"},
		{[]string{"root", "example.com", "mechanism", "ns", "domain", "cloudflare.com", "provider", "Cloudflare"}, "third-party Cloudflare via ns on example.com", "Cloudflare"},
		{[]string{"root", "example.com", "mechanism", "ns", "domain", "dns-host.test"}, "third-party dns-host.test via ns on example.com", "dns-host.test"},
	} {
		r := rec("k", c.rec...)
		fields := k.Found(r)
		if fields["text"] != c.text || fields["platform"] != c.plat || fields["mechanism"] != r.Str("mechanism") || fields["root"] != "example.com" {
			t.Errorf("Found = %v, want text %q", fields, c.text)
		}
	}
}
