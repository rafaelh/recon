package provider_test

import (
	"testing"

	"github.com/rafaelh/recon/internal/provider"
)

// A TXT value that starts with a listed prefix, in any case, names its platform.
func TestVerification(t *testing.T) {
	db := provider.Default()
	for value, want := range map[string]string{
		"google-site-verification=abc":        "Google",
		"GOOGLE-SITE-VERIFICATION=abc":        "Google",
		"MS=ms123":                            "Microsoft 365",
		"ms=ms123":                            "Microsoft 365",
		"atlassian-domain-verification=x":     "Atlassian",
		"docusign=x":                          "DocuSign",
		"facebook-domain-verification=x":      "Facebook",
		"apple-domain-verification=x":         "Apple",
		"stripe-verification=x":               "Stripe",
		"adobe-idp-site-verification=x":       "Adobe",
		"hubspot-developer-verification=x":    "HubSpot",
		"zoom-domain-verification=x":          "Zoom",
		"dropbox-domain-verification=x":       "Dropbox",
		"salesforce-domain-verification=x":    "Salesforce",
		"have-i-been-pwned-verification=x":    "Have I Been Pwned",
		"webexdomainverification.ABC=x":       "Cisco Webex",
		"  google-site-verification=padded  ": "Google",
	} {
		if got, ok := db.Verification(value); !ok || got != want {
			t.Errorf("Verification(%q) = %q, %v, want %q", value, got, ok, want)
		}
	}
	for _, value := range []string{"", "v=spf1 -all", "xgoogle-site-verification=abc", "a google-site-verification=abc", "MSFT=1", "some text"} {
		if got, ok := db.Verification(value); ok {
			t.Errorf("Verification(%q) = %q; only a prefix matches", value, got)
		}
	}
}

// A name server's domain names its provider when its suffix is listed, on label boundaries.
func TestDomainOwner(t *testing.T) {
	db := provider.Default()
	for name, want := range map[string]string{
		"ns1.cloudflare.com":            "Cloudflare",
		"NS1.Cloudflare.com.":           "Cloudflare",
		"cloudflare.com":                "Cloudflare",
		"ns51.domaincontrol.com":        "GoDaddy",
		"ns1-01.azure-dns.com":          "Microsoft Azure DNS",
		"ns-cloud-a1.googledomains.com": "Google Cloud DNS",
	} {
		if got, ok := db.DomainOwner(name); !ok || got != want {
			t.Errorf("DomainOwner(%q) = %q, %v, want %q", name, got, ok, want)
		}
	}
	for _, name := range []string{"ns1.example.net", "notcloudflare.com", "cloudflare.com.evil.test", ""} {
		if got, ok := db.DomainOwner(name); ok {
			t.Errorf("DomainOwner(%q) = %q; suffixes match on label boundaries only", name, got)
		}
	}
}

func TestParseTXTAndDomains(t *testing.T) {
	db, err := provider.Parse([]byte("txt:\n  - {prefix: 'X-Verify=', platform: Example}\ndomains:\n  - {suffix: Dns.Example.Test, provider: ExampleDNS}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := db.Verification("x-verify=1"); !ok || p != "Example" {
		t.Errorf("Verification = %q, %v", p, ok)
	}
	if p, ok := db.DomainOwner("a.dns.example.test"); !ok || p != "ExampleDNS" {
		t.Errorf("DomainOwner = %q, %v", p, ok)
	}
}
