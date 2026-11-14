package provider_test

import (
	"testing"

	"github.com/rafaelh/recon/internal/provider"
)

// The cname entries carry a class, an nxdomain flag and a body fingerprint.
func TestCNAMEEntries(t *testing.T) {
	db := provider.Default()
	cases := []struct {
		target   string
		class    string
		nxdomain bool
		body     string // a body the fingerprint must match; "" means no fingerprint
	}{
		{"acme.s3.amazonaws.com", "", false, "<Error><Code>NoSuchBucket</Code></Error>"},
		{"acme.herokuapp.com", "", false, "<title>No such app</title>"},
		{"acme.github.io", "saas", false, "There isn't a GitHub Pages site here."},
		{"acme.myshopify.com", "saas", false, "Sorry, this shop is currently unavailable."},
		{"acme.zendesk.com", "saas", false, "Help Center Closed"},
		{"acme.statuspage.io", "saas", false, "You are being <a href=\"https://www.statuspage.io\">redirected</a>."},
		{"acme.unbouncepages.com", "saas", false, "The requested URL was not found on this server."},
		{"acme.ghost.io", "saas", false, "Failed to resolve DNS path for this host"},
		{"acme.readme.io", "saas", false, "Project doesnt exist... yet!"},
		{"acme.cloudapp.net", "", true, ""},
		{"acme.westeurope.cloudapp.azure.com", "", true, ""},
		{"acme.azurewebsites.net", "", true, ""},
		{"acme.trafficmanager.net", "", true, ""},
		{"acme.blob.core.windows.net", "", true, ""},
		{"acme.us-east-1.elasticbeanstalk.com", "", true, ""},
		{"acme.squarespace.com", "saas", false, ""},
		{"acme.wixdns.net", "saas", false, ""},
	}
	for _, c := range cases {
		e, ok := db.CNAMEEntry(c.target)
		if !ok {
			t.Errorf("%s: no entry", c.target)
			continue
		}
		if e.Class != c.class || e.NXDomain != c.nxdomain {
			t.Errorf("%s: class %q nxdomain %v, want %q %v", c.target, e.Class, e.NXDomain, c.class, c.nxdomain)
		}
		if (e.Body != "") != (c.body != "") {
			t.Errorf("%s: body %q", c.target, e.Body)
		}
		if c.body != "" && !e.BodyMatches([]byte(c.body)) {
			t.Errorf("%s: fingerprint %q does not match %q", c.target, e.Body, c.body)
		}
		if e.Body != "" && e.BodyMatches([]byte("<html>welcome to our ordinary site</html>")) {
			t.Errorf("%s: fingerprint matches an ordinary page", c.target)
		}
	}
	// Match still reports provider and service.
	if m, ok := db.CNAME("acme.s3.amazonaws.com"); !ok || m.Provider != "aws" || m.Service != "S3" {
		t.Errorf("CNAME = %+v %v", m, ok)
	}
}

// A matched entry has a short stable hash that changes when the entry does.
func TestEntryHash(t *testing.T) {
	a, err := provider.Parse([]byte("cname:\n  - {suffix: x.test, provider: p, service: S, body: 'foo'}\n"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := provider.Parse([]byte("cname:\n  - {suffix: x.test, provider: p, service: S, body: 'bar'}\n"))
	ea, _ := a.CNAMEEntry("q.x.test")
	eb, _ := b.CNAMEEntry("q.x.test")
	ea2, _ := a.CNAMEEntry("other.x.test")
	if len(ea.Hash()) != 8 || ea.Hash() == eb.Hash() || ea.Hash() != ea2.Hash() {
		t.Errorf("hashes %q %q %q", ea.Hash(), eb.Hash(), ea2.Hash())
	}
}

func TestParseRejectsBadFingerprint(t *testing.T) {
	if _, err := provider.Parse([]byte("cname:\n  - {suffix: x.test, provider: p, service: S, body: '(['}\n")); err == nil {
		t.Error("an invalid RE2 body must be an error")
	}
	if _, err := provider.Parse([]byte("ranges:\n  - {cidr: not-a-cidr, provider: p, service: S, class: saas}\n")); err == nil {
		t.Error("an invalid range must be an error")
	}
}

// SaaS is recognised by CNAME, ASN or address range.
func TestSaaSRecognition(t *testing.T) {
	db := provider.Default()
	// By address range (apex records): GitHub Pages.
	res := db.Classify(ip("185.199.108.153"), provider.Owner{}, nil)
	if !res.Shared || res.Provider != "github" || res.Class != "saas" || res.Evidence != "range" {
		t.Errorf("github pages range = %+v", res)
	}
	// By ASN: Shopify.
	res = db.Classify(ip("23.227.38.65"), provider.Owner{ASN: 62679, Known: true}, nil)
	if !res.Shared || res.Provider != "shopify" || res.Class != "saas" || res.Evidence != "asn" {
		t.Errorf("shopify asn = %+v", res)
	}
	// A CDN ASN is a CDN, not SaaS.
	if res = db.Classify(ip("104.16.0.1"), provider.Owner{ASN: 13335, Known: true}, nil); res.Class != provider.ClassCDN {
		t.Errorf("cloudflare class = %q, want %q", res.Class, provider.ClassCDN)
	}
	// An ordinary address is none of these.
	if res = db.Classify(ip("203.0.113.5"), provider.Owner{ASN: 64500, Known: true}, nil); res.Shared || res.Class != "" {
		t.Errorf("ordinary = %+v", res)
	}
}
