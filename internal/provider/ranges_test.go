package provider_test

import (
	"testing"

	"github.com/rafaelh/recon/internal/provider"
)

func rng(prefix, prov, service, region string) provider.Range {
	return provider.Range{Prefix: pfx(prefix), Provider: prov, Service: service, Region: region}
}

// Each provider's published ranges settle an address by that provider's own rule.
func TestClassify_PublishedRangeRules(t *testing.T) {
	db := provider.Default()
	ranges := []provider.Range{
		rng("104.16.0.0/13", "cloudflare", "", ""),
		rng("2606:4700::/32", "cloudflare", "", ""),
		rng("151.101.0.0/16", "fastly", "", ""),
		rng("143.198.0.0/16", "digitalocean", "", "US-NJ"),
		rng("45.79.0.0/16", "linode", "", "US-TX"),
		rng("129.146.0.0/21", "oracle", "OCI", "us-phoenix-1"),
		rng("64.181.146.0/23", "oracle", "OSN", "mx-monterrey-1"),
		rng("134.70.200.0/23", "oracle", "OBJECT_STORAGE", "mx-monterrey-1"),
		rng("134.70.200.0/23", "oracle", "OSN", "mx-monterrey-1"),
		// An OCI range and an OSN range covering one address: fail closed.
		rng("130.35.0.0/16", "oracle", "OCI", "us-ashburn-1"),
		rng("130.35.8.0/24", "oracle", "OSN", "us-ashburn-1"),
	}
	cases := []struct {
		name, addr string
		owner      provider.Owner
		want       provider.Result
	}{
		{"cloudflare is shared and a cdn", "104.16.0.5", provider.Owner{},
			provider.Result{Known: true, Shared: true, Provider: "cloudflare", Evidence: "range", Class: provider.ClassCDN}},
		{"cloudflare over IPv6", "2606:4700::1", provider.Owner{},
			provider.Result{Known: true, Shared: true, Provider: "cloudflare", Evidence: "range", Class: provider.ClassCDN}},
		{"fastly is shared and a cdn", "151.101.1.1", provider.Owner{ASN: 54113, Known: true},
			provider.Result{Known: true, Shared: true, Provider: "fastly", Evidence: "range", Class: provider.ClassCDN}},
		{"digitalocean is dedicated and keeps its region", "143.198.1.1", provider.Owner{},
			provider.Result{Known: true, Provider: "digitalocean", Region: "US-NJ", Evidence: "range"}},
		{"linode is dedicated", "45.79.1.1", provider.Owner{},
			provider.Result{Known: true, Provider: "linode", Region: "US-TX", Evidence: "range"}},
		{"oracle OCI is dedicated", "129.146.1.1", provider.Owner{},
			provider.Result{Known: true, Provider: "oracle", Service: "OCI", Region: "us-phoenix-1", Evidence: "range"}},
		{"oracle OSN is shared", "64.181.146.9", provider.Owner{},
			provider.Result{Known: true, Shared: true, Provider: "oracle", Service: "OSN", Region: "mx-monterrey-1", Evidence: "range"}},
		{"oracle object storage is shared", "134.70.200.9", provider.Owner{},
			provider.Result{Known: true, Shared: true, Provider: "oracle", Service: "OBJECT_STORAGE", Region: "mx-monterrey-1", Evidence: "range"}},
		{"oracle OCI inside an OSN range fails closed", "130.35.8.9", provider.Owner{},
			provider.Result{Known: true, Shared: true, Provider: "oracle", Service: "OSN", Region: "us-ashburn-1", Evidence: "range"}},
		{"oracle OCI outside the OSN range stays dedicated", "130.35.9.9", provider.Owner{},
			provider.Result{Known: true, Provider: "oracle", Service: "OCI", Region: "us-ashburn-1", Evidence: "range"}},
	}
	idx := provider.NewRanges(ranges)
	for _, c := range cases {
		if got := db.Classify(ip(c.addr), c.owner, idx); got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

// A published range beats the ASN: DigitalOcean's ASN says shared hosting, its
// list says the address is a customer's own machine. Without the list the ASN
// still applies.
func TestClassify_RangeBeatsASN(t *testing.T) {
	db := provider.Default()
	doASN := provider.Owner{ASN: 14061, Holder: "DIGITALOCEAN-ASN", Known: true}
	withList := db.Classify(ip("143.198.1.1"), doASN, provider.NewRanges([]provider.Range{rng("143.198.0.0/16", "digitalocean", "", "US-NJ")}))
	if withList.Shared || withList.Provider != "digitalocean" || withList.Evidence != "range" {
		t.Errorf("with the list: %+v, want dedicated digitalocean by range", withList)
	}
	without := db.Classify(ip("143.198.1.1"), doASN, nil)
	if !without.Shared || without.Provider != "digitalocean" || without.Evidence != "asn" {
		t.Errorf("without the list: %+v, want shared digitalocean by asn", without)
	}
	// A Linode range wins over an unrelated owner too.
	got := db.Classify(ip("45.79.1.1"), provider.Owner{ASN: 64500, Known: true}, provider.NewRanges([]provider.Range{rng("45.79.0.0/16", "linode", "", "")}))
	if got.Shared || got.Provider != "linode" {
		t.Errorf("linode over an ordinary owner: %+v", got)
	}
}

// An address two providers' lists cover shows both, in name order, and is shared
// if either result is shared.
func TestClassify_AddressInTwoLists(t *testing.T) {
	db := provider.Default()
	cases := []struct {
		name   string
		ranges []provider.Range
		want   provider.Result
	}{
		{"shared and dedicated is shared, joined in name order",
			[]provider.Range{rng("192.0.2.0/24", "fastly", "", ""), rng("192.0.2.0/24", "aws", "EC2", "eu-west-1")},
			provider.Result{Known: true, Shared: true, Provider: "aws;fastly", Service: "EC2", Region: "eu-west-1", Evidence: "range", Class: provider.ClassCDN}},
		{"two dedicated lists stay dedicated",
			[]provider.Range{rng("192.0.2.0/24", "linode", "", "US-TX"), rng("192.0.2.0/24", "digitalocean", "", "US-NJ")},
			provider.Result{Known: true, Provider: "digitalocean;linode", Region: "US-NJ;US-TX", Evidence: "range"}},
		{"order of the lists does not change the answer",
			[]provider.Range{rng("192.0.2.0/24", "digitalocean", "", "US-NJ"), rng("192.0.2.0/24", "linode", "", "US-TX")},
			provider.Result{Known: true, Provider: "digitalocean;linode", Region: "US-NJ;US-TX", Evidence: "range"}},
	}
	for _, c := range cases {
		if got := db.Classify(ip("192.0.2.7"), provider.Owner{}, provider.NewRanges(c.ranges)); got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

// Each provider settles its own lists first, so an EC2 range still wins over the
// AMAZON superset that also covers the address.
func TestClassify_EC2InsideAmazonStaysDedicated(t *testing.T) {
	db := provider.Default()
	got := db.Classify(ip("203.0.113.5"), provider.Owner{ASN: 16509, Known: true}, provider.NewRanges([]provider.Range{
		rng("203.0.112.0/22", "aws", "AMAZON", "eu-west-1"),
		rng("203.0.113.0/24", "aws", "EC2", "eu-west-1"),
	}))
	want := provider.Result{Known: true, Provider: "aws", Service: "EC2", Region: "eu-west-1", Evidence: "range"}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

// The class of every ASN entry reaches the caller, not only saas: Akamai's and
// Cloudflare's ASNs are cdn.
func TestClassify_ASNClassIsPassedThrough(t *testing.T) {
	db := provider.Default()
	for _, c := range []struct {
		asn      int
		provider string
		class    string
	}{
		{20940, "akamai", provider.ClassCDN},
		{13335, "cloudflare", provider.ClassCDN},
		{54113, "fastly", provider.ClassCDN},
		{53831, "squarespace", provider.ClassSaaS},
		{14061, "digitalocean", "shared-hosting"},
		{8075, "azure", "hyperscaler"},
	} {
		got := db.Classify(ip("100.64.0.1"), provider.Owner{ASN: c.asn, Known: true}, nil)
		if !got.Shared || got.Provider != c.provider || got.Class != c.class || got.Evidence != "asn" {
			t.Errorf("AS%d: %+v, want shared %s by asn with class %q", c.asn, got, c.provider, c.class)
		}
	}
}

// A range from a provider with no rule says nothing, as before.
func TestClassify_UnknownProviderRangeIsIgnored(t *testing.T) {
	db := provider.Default()
	got := db.Classify(ip("192.0.2.7"), provider.Owner{ASN: 64500, Known: true}, provider.NewRanges([]provider.Range{rng("192.0.2.0/24", "someone-else", "x", "y")}))
	if got != (provider.Result{Known: true}) {
		t.Errorf("got %+v, want a known, unshared address", got)
	}
}
