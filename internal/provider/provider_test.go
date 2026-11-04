package provider_test

import (
	"net/netip"
	"testing"

	"github.com/rafaelh/recon/internal/provider"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func ip(s string) netip.Addr    { return netip.MustParseAddr(s) }

// B5/B8: CNAME suffix labels.
func TestCNAMESuffix(t *testing.T) {
	db := provider.Default()
	for target, want := range map[string]provider.Match{
		"d111.cloudfront.net":       {Provider: "aws", Service: "CloudFront"},
		"mybucket.s3.amazonaws.com": {Provider: "aws", Service: "S3"},
		"foo.azurewebsites.net":     {Provider: "azure", Service: "App Service"},
	} {
		m, ok := db.CNAME(target)
		if !ok || m.Provider != want.Provider || m.Service != want.Service {
			t.Errorf("CNAME(%s) = %+v %v, want %+v", target, m, ok, want)
		}
	}
	for _, target := range []string{"mail.example.net", "notcloudfront.net", "cloudfront.net.evil.example"} {
		if m, ok := db.CNAME(target); ok {
			t.Errorf("CNAME(%s) matched %+v; suffixes match on label boundaries only", target, m)
		}
	}
}

func TestClassify(t *testing.T) {
	db := provider.Default()
	ranges := []provider.Range{
		{Prefix: pfx("203.0.113.0/24"), Provider: "aws", Service: "AMAZON", Region: "eu-west-1"},
		{Prefix: pfx("203.0.113.0/24"), Provider: "aws", Service: "EC2", Region: "eu-west-1"},
		{Prefix: pfx("198.51.100.0/24"), Provider: "aws", Service: "AMAZON", Region: "us-east-1"},
		{Prefix: pfx("198.51.100.0/24"), Provider: "aws", Service: "CLOUDFRONT", Region: "GLOBAL"},
		{Prefix: pfx("198.18.0.0/24"), Provider: "aws", Service: "AMAZON", Region: "us-east-1"},
		{Prefix: pfx("192.0.2.0/24"), Provider: "gcp", Service: "Google Cloud", Region: "europe-west1"},
	}
	cases := []struct {
		name  string
		addr  string
		owner provider.Owner
		want  provider.Result
	}{
		{"ec2 only is not shared", "203.0.113.5", provider.Owner{ASN: 16509, Holder: "AMAZON-02", Known: true},
			provider.Result{Known: true, Shared: false, Provider: "aws", Service: "EC2", Evidence: "range"}},
		{"amazon superset only is shared, not labelled EC2", "198.18.0.5", provider.Owner{ASN: 16509, Known: true},
			provider.Result{Known: true, Shared: true, Provider: "aws", Evidence: "range"}},
		{"cloudfront range is shared", "198.51.100.7", provider.Owner{ASN: 16509, Known: true},
			provider.Result{Known: true, Shared: true, Provider: "aws", Service: "CLOUDFRONT", Evidence: "range"}},
		{"gcp is shared, no service discrimination", "192.0.2.9", provider.Owner{ASN: 15169, Known: true},
			provider.Result{Known: true, Shared: true, Provider: "gcp", Evidence: "range"}},
		{"cdn asn is shared", "104.16.0.1", provider.Owner{ASN: 13335, Holder: "CLOUDFLARENET", Known: true},
			provider.Result{Known: true, Shared: true, Provider: "cloudflare", Evidence: "asn"}},
		{"azure asn fails closed", "20.0.0.1", provider.Owner{ASN: 8075, Holder: "MICROSOFT", Known: true},
			provider.Result{Known: true, Shared: true, Provider: "azure", Evidence: "asn"}},
		{"hyperscaler address with no range data is shared", "54.0.0.1", provider.Owner{ASN: 16509, Known: true},
			provider.Result{Known: true, Shared: true, Provider: "aws", Evidence: "asn"}},
		{"ordinary owner is known, not shared", "100.64.0.1", provider.Owner{ASN: 64500, Holder: "ACME-NET", Known: true},
			provider.Result{Known: true}},
		{"no owner and no range is unknown", "100.64.0.2", provider.Owner{}, provider.Result{}},
	}
	for _, c := range cases {
		got := db.Classify(ip(c.addr), c.owner, provider.NewRanges(ranges))
		if got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

// The index finds exactly the ranges a linear scan does, in the same order, so
// Classify's first-match result is unchanged.
func TestClassifyIndexMatchesLinearScan(t *testing.T) {
	db := provider.Default()
	ranges := []provider.Range{
		{Prefix: pfx("203.0.112.0/22"), Provider: "aws", Service: "AMAZON"},
		{Prefix: pfx("203.0.113.0/24"), Provider: "aws", Service: "EC2"},
		{Prefix: pfx("203.0.113.128/25"), Provider: "aws", Service: "ROUTE53"},
		{Prefix: pfx("203.0.113.0/24"), Provider: "aws", Service: "CLOUDFRONT"},
		{Prefix: pfx("203.0.113.192/26"), Provider: "gcp"},
		{Prefix: pfx("203.0.113.200/32"), Provider: "aws", Service: "EC2"},
		{Prefix: pfx("2001:db8::/32"), Provider: "aws", Service: "AMAZON"},
		{Prefix: pfx("2001:db8:1::/48"), Provider: "aws", Service: "EC2"},
		{Prefix: pfx("2001:db8:1:2::/64"), Provider: "aws", Service: "S3"},
		{Prefix: pfx("2001:db8:ff::/48"), Provider: "gcp"},
		{Prefix: pfx("0.0.0.0/0"), Provider: "other"},
	}
	// The range half of the original linear Classify (owner is an AWS ASN, so
	// with no covering range the result is the ASN's).
	linear := func(a netip.Addr, owner provider.Owner) provider.Result {
		var ec2, amazon, gcp bool
		for _, r := range ranges {
			if !r.Prefix.Contains(a) {
				continue
			}
			switch r.Provider {
			case "aws":
				switch r.Service {
				case "EC2":
					ec2 = true
				case "AMAZON":
					amazon = true
				default:
					return provider.Result{Known: true, Shared: true, Provider: "aws", Service: r.Service, Evidence: "range"}
				}
			case "gcp":
				gcp = true
			}
		}
		switch {
		case gcp:
			return provider.Result{Known: true, Shared: true, Provider: "gcp", Evidence: "range"}
		case ec2:
			return provider.Result{Known: true, Provider: "aws", Service: "EC2", Evidence: "range"}
		case amazon:
			return provider.Result{Known: true, Shared: true, Provider: "aws", Evidence: "range"}
		}
		return db.Classify(a, owner, nil)
	}
	idx := provider.NewRanges(ranges)
	var addrs []netip.Addr
	for i := 0; i < 1024; i++ {
		addrs = append(addrs, netip.AddrFrom4([4]byte{203, 0, byte(112 + i/256), byte(i)}))
	}
	for _, s := range []string{"2001:db8::1", "2001:db8:1::1", "2001:db8:1:2::1", "2001:db8:ff::9", "2001:db9::1", "::ffff:203.0.113.200", "8.8.8.8"} {
		addrs = append(addrs, ip(s))
	}
	owner := provider.Owner{ASN: 16509, Known: true}
	for _, a := range addrs {
		if got, want := db.Classify(a, owner, idx), linear(a.Unmap(), owner); got != want {
			t.Errorf("%s: indexed %+v, linear %+v", a, got, want)
		}
	}
	if got := db.Classify(ip("203.0.113.5"), provider.Owner{}, nil); got != (provider.Result{}) {
		t.Errorf("nil ranges: got %+v", got)
	}
}
