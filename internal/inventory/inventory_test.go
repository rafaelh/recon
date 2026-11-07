package inventory_test

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/inventory"
	"github.com/rafaelh/recon/internal/provider"
	"github.com/rafaelh/recon/internal/scope"
)

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func ips(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, a := range s {
		out = append(out, ip(a))
	}
	return out
}

// resolve adds A/AAAA resolution rows for a queried name.
func resolve(d *inventory.Data, name string, addrs ...string) {
	for _, a := range addrs {
		typ := "A"
		if ip(a).Is6() {
			typ = "AAAA"
		}
		d.Resolutions = append(d.Resolutions, inventory.Resolution{Name: name, Type: typ, Value: a})
		d.IPs = append(d.IPs, ip(a))
	}
	d.Hosts = append(d.Hosts, inventory.Host{Name: name, Stages: []string{"crtsh"}})
}

func newScope(inv *inventory.Inventory, d inventory.Data, excl ...string) *scope.Scope {
	var xs []input.Exclusion
	for _, e := range excl {
		x, _ := input.ParseExclusion(e)
		xs = append(xs, x)
	}
	return scope.New(scope.Config{
		Roots: []string{"example.com"}, Netblocks: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		Exclusions: xs, Resolutions: inv.Addrs(), WildcardOnly: inv.WildcardOnly(),
	})
}

// Wildcard-only names are computed on read, by CNAME or by overlapping addresses.
func TestWildcardOnly(t *testing.T) {
	var d inventory.Data
	d.Wildcards = []inventory.Wildcard{{Zone: "example.com", Addrs: ips("203.0.113.1", "203.0.113.2")}}
	resolve(&d, "zz.example.com", "203.0.113.1")                                                          // overlaps the probe addresses
	resolve(&d, "real.example.com", "203.0.113.50")                                                       // distinct: a real host
	resolve(&d, "deep.sub.example.com", "203.0.113.1")                                                    // not directly under the zone
	d.Hosts = append(d.Hosts, inventory.Host{Name: "late.example.com", Stages: []string{"permutations"}}) // unresolved
	inv := inventory.New(d, provider.Default())
	wo := inv.WildcardOnly()
	if !wo["zz.example.com"] || wo["real.example.com"] || wo["deep.sub.example.com"] || wo["late.example.com"] || wo["example.com"] {
		t.Errorf("wildcard-only = %v", wo)
	}

	// A name discovered after the zone check is still caught: same Data, new host.
	resolve(&d, "later.example.com", "203.0.113.2")
	if !inventory.New(d, provider.Default()).WildcardOnly()["later.example.com"] {
		t.Error("a name found after the zone's check must be wildcard-only")
	}
}

func TestWildcardOnlyByCNAME(t *testing.T) {
	var d inventory.Data
	d.Wildcards = []inventory.Wildcard{{Zone: "example.com", Addrs: ips("203.0.113.1"), CNAME: "lb.cdn.example.net"}}
	// A rotating CDN: this name's addresses differ from the probes', but the CNAME target is the same.
	d.Resolutions = append(d.Resolutions,
		inventory.Resolution{Name: "a.example.com", Type: "CNAME", Value: "lb.cdn.example.net"},
		inventory.Resolution{Name: "a.example.com", Type: "A", Value: "203.0.113.99"})
	d.Hosts = append(d.Hosts, inventory.Host{Name: "a.example.com", Stages: []string{"crtsh"}})
	d.Resolutions = append(d.Resolutions,
		inventory.Resolution{Name: "b.example.com", Type: "CNAME", Value: "other.example.net"},
		inventory.Resolution{Name: "b.example.com", Type: "A", Value: "203.0.113.98"})
	d.Hosts = append(d.Hosts, inventory.Host{Name: "b.example.com", Stages: []string{"crtsh"}})
	wo := inventory.New(d, provider.Default()).WildcardOnly()
	if !wo["a.example.com"] || wo["b.example.com"] {
		t.Errorf("wildcard-only = %v", wo)
	}
}

// One representative per wildcard reaches ProbeHostnames; wildcard-only names do not.
func TestProbeHostnames(t *testing.T) {
	var d inventory.Data
	d.Wildcards = []inventory.Wildcard{{Zone: "example.com", Addrs: ips("203.0.113.1")}}
	resolve(&d, "zz.example.com", "203.0.113.1")
	resolve(&d, "aa.example.com", "203.0.113.1") // lexicographically smallest wildcard-only name
	resolve(&d, "real.example.com", "203.0.113.50")
	resolve(&d, "gone.example.com")              // no addresses
	resolve(&d, "x.example.org", "203.0.113.60") // candidate
	resolve(&d, "admin.example.com", "203.0.113.70")
	inv := inventory.New(d, provider.Default())
	sc := newScope(inv, d, "admin.example.com")
	got := inv.ProbeHostnames(sc)
	if !slices.Equal(got, []string{"aa.example.com", "real.example.com"}) {
		t.Errorf("ProbeHostnames = %v", got)
	}
	if reps := inv.Representatives(sc); reps["example.com"] != "aa.example.com" {
		t.Errorf("representatives = %v", reps)
	}
}

// The representative is chosen among probeable names, so an excluded or
// address-less wildcard-only name never costs the zone its only probe.
func TestRepresentativeIsProbeable(t *testing.T) {
	var d inventory.Data
	d.Wildcards = []inventory.Wildcard{{Zone: "example.com", Addrs: ips("203.0.113.1"), CNAME: "wild.example.net"}}
	resolve(&d, "admin.example.com", "203.0.113.1") // smallest, but excluded
	d.Resolutions = append(d.Resolutions, inventory.Resolution{Name: "b.example.com", Type: "CNAME", Value: "wild.example.net"})
	d.Hosts = append(d.Hosts, inventory.Host{Name: "b.example.com", Stages: []string{"crtsh"}}) // wildcard-only, no addresses
	resolve(&d, "shop.example.com", "203.0.113.1")
	inv := inventory.New(d, provider.Default())
	sc := newScope(inv, d, "admin.example.com")
	if got := inv.ProbeHostnames(sc); !slices.Equal(got, []string{"shop.example.com"}) {
		t.Errorf("ProbeHostnames = %v, want the in-scope resolving representative", got)
	}
}

// Only names seen by a stage other than permutations are seeds.
func TestSeeds(t *testing.T) {
	var d inventory.Data
	d.Wildcards = []inventory.Wildcard{{Zone: "example.com", Addrs: ips("203.0.113.1")}}
	d.Hosts = []inventory.Host{
		{Name: "api.example.com", Stages: []string{"crtsh"}},
		{Name: "api-dev.example.com", Stages: []string{"permutations"}},
		{Name: "both.example.com", Stages: []string{"permutations", "rdns"}},
		{Name: "wild.example.com", Stages: []string{"crtsh"}},
		{Name: "x.example.org", Stages: []string{"crtsh"}},
		{Name: "example.com", Stages: []string{"crtsh"}}, // the apex: its parent "com" is not in scope
	}
	resolve(&d, "wild.example.com", "203.0.113.1")
	d.Hosts = d.Hosts[:len(d.Hosts)-1] // resolve() appended a duplicate record for wild
	inv := inventory.New(d, provider.Default())
	got := inv.Seeds(newScope(inv, d), "permutations")
	if !slices.Equal(got, []string{"api.example.com", "both.example.com"}) {
		t.Errorf("seeds = %v", got)
	}
}

// CNAME-to-provider rows, with resolves=false for dangling chains.
func TestProviderHosts(t *testing.T) {
	var d inventory.Data
	d.Hosts = []inventory.Host{
		{Name: "cdn.example.com", Stages: []string{"crtsh"}}, {Name: "dangling.example.com", Stages: []string{"crtsh"}},
		{Name: "mail.example.com", Stages: []string{"crtsh"}}, {Name: "apex.example.com", Stages: []string{"crtsh"}},
	}
	d.Resolutions = []inventory.Resolution{
		{Name: "cdn.example.com", Type: "CNAME", Value: "d1.cloudfront.net"},
		{Name: "cdn.example.com", Type: "A", Value: "203.0.113.10"},
		{Name: "dangling.example.com", Type: "CNAME", Value: "gone.azurewebsites.net"},
		{Name: "mail.example.com", Type: "CNAME", Value: "mail.example.net"},
		{Name: "mail.example.com", Type: "A", Value: "203.0.113.11"},
		{Name: "apex.example.com", Type: "A", Value: "203.0.113.12"},
	}
	// An apex ALIAS: an A record with no CNAME, inside a CloudFront range.
	d.Ranges = provider.NewRanges([]provider.Range{
		{Prefix: netip.MustParsePrefix("203.0.113.12/32"), Provider: "aws", Service: "AMAZON"},
		{Prefix: netip.MustParsePrefix("203.0.113.12/32"), Provider: "aws", Service: "CLOUDFRONT"},
	})
	inv := inventory.New(d, provider.Default())
	rows := inv.ProviderHosts(newScope(inv, d))
	byHost := map[string][]inventory.ProviderHost{}
	for _, r := range rows {
		byHost[r.Hostname] = append(byHost[r.Hostname], r)
	}
	if r := byHost["cdn.example.com"]; len(r) != 1 || r[0].Provider != "aws" || r[0].Service != "CloudFront" || r[0].Evidence != "cname" ||
		r[0].CNAME != "d1.cloudfront.net" || !r[0].Resolves {
		t.Errorf("cdn = %+v", r)
	}
	if r := byHost["dangling.example.com"]; len(r) != 1 || r[0].Provider != "azure" || r[0].Resolves {
		t.Errorf("dangling chain: %+v", r)
	}
	if len(byHost["mail.example.com"]) != 0 {
		t.Errorf("unrelated suffix produced a row: %+v", byHost["mail.example.com"])
	}
	if r := byHost["apex.example.com"]; len(r) != 1 || r[0].Evidence != "range" || r[0].Service != "CLOUDFRONT" || r[0].CNAME != "" || !r[0].Resolves {
		t.Errorf("apex ALIAS must be recognised by range: %+v", r)
	}
}

// IP rows, owners, eligibility; unknown owner fails closed.
func TestIPRows(t *testing.T) {
	var d inventory.Data
	resolve(&d, "www.example.com", "203.0.113.5")
	resolve(&d, "cdn.example.com", "104.16.0.1")
	resolve(&d, "edge.example.com", "104.16.0.2") // owner lookup failed: unknown
	d.IPs = append(d.IPs, ip("198.51.100.9"))
	d.Owners = map[netip.Addr]provider.Owner{
		ip("203.0.113.5"): {ASN: 64500, Holder: "ACME-NET", Known: true},
		ip("104.16.0.1"):  {ASN: 13335, Holder: "CLOUDFLARENET", Known: true},
	}
	d.IPHostnames = []inventory.IPHostname{{IP: ip("198.51.100.9"), Hostname: "ptr.other.org", Source: "rdns"}, {IP: ip("198.51.100.9"), Hostname: "shodan.other.org", Source: "shodan"}}
	inv := inventory.New(d, provider.Default())
	sc := newScope(inv, d)

	rows := map[string]inventory.IPRow{}
	for _, r := range inv.IPRows(sc) {
		rows[r.IP.String()] = r
	}
	if r := rows["203.0.113.5"]; !r.PortEligible || r.Owner != "ACME-NET" || r.ASN != 64500 || r.Provider != "" {
		t.Errorf("ordinary host: %+v", r)
	}
	if r := rows["104.16.0.1"]; r.PortEligible || r.Provider != "cloudflare" || r.Owner != "CLOUDFLARENET" {
		t.Errorf("cdn edge: %+v", r)
	}
	if r := rows["104.16.0.2"]; r.PortEligible || r.Owner != "unknown" {
		t.Errorf("unknown owner must fail closed: %+v", r)
	}
	if r := rows["198.51.100.9"]; !r.PortEligible || !r.InScope || !slices.Equal(r.Hostnames, []string{"ptr.other.org", "shodan.other.org"}) {
		t.Errorf("in-scope IP: %+v", r)
	}
}

// The ips.csv port_eligible column equals egress's decision for the same address.
func TestIPRowsMatchEgress(t *testing.T) {
	var d inventory.Data
	resolve(&d, "www.example.com", "203.0.113.5")
	resolve(&d, "cdn.example.com", "104.16.0.1")
	resolve(&d, "edge.example.com", "104.16.0.2")
	resolve(&d, "admin.example.com", "203.0.113.6")
	resolve(&d, "v6.example.com", "2001:db8::5")
	// Only the CNAME shows that this ordinary-ASN address is shared infrastructure.
	resolve(&d, "hk.example.com", "203.0.113.60")
	d.Resolutions = append(d.Resolutions, inventory.Resolution{Name: "hk.example.com", Type: "CNAME", Value: "x.herokudns.com"})
	d.IPs = append(d.IPs, ip("198.51.100.9"), ip("8.8.8.8"))
	d.Owners = map[netip.Addr]provider.Owner{
		ip("203.0.113.5"):  {ASN: 64500, Holder: "ACME-NET", Known: true},
		ip("104.16.0.1"):   {ASN: 13335, Holder: "CLOUDFLARENET", Known: true},
		ip("203.0.113.6"):  {ASN: 64500, Holder: "ACME-NET", Known: true},
		ip("2001:db8::5"):  {ASN: 64500, Holder: "ACME-NET", Known: true},
		ip("8.8.8.8"):      {ASN: 15169, Holder: "GOOGLE", Known: true},
		ip("203.0.113.60"): {ASN: 64500, Holder: "ACME-NET", Known: true},
	}
	inv := inventory.New(d, provider.Default())
	sc := newScope(inv, d, "admin.example.com")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, ps, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(ps)
	dm := map[string]string{}
	res := map[string][]netip.Addr{}
	for _, r := range inv.IPRows(sc) {
		dm[net.JoinHostPort(r.IP.String(), ps)] = ln.Addr().String()
	}
	for _, rr := range d.Resolutions {
		if rr.Type != "CNAME" {
			res[rr.Name] = append(res[rr.Name], ip(rr.Value))
		}
	}
	eg := egress.New(egress.Options{ConnectTimeout: 200 * time.Millisecond, BannerWait: 10 * time.Millisecond, RatePerHost: 1000, DialMap: dm})
	eg.SetPolicy(&egress.Policy{
		Scope: sc, Ack: true, Ports: []int{port}, Resolutions: res,
		Shared:       inv.Shared,
		OwnerUnknown: func(a netip.Addr) bool { return !inv.OwnerKnown(a, sc) },
	})
	rows := inv.IPRows(sc)
	if len(rows) != 8 {
		t.Fatalf("expected 8 IP rows, got %d", len(rows))
	}
	for _, r := range rows {
		res, err := eg.Clients("t", true, nil).TCP.Connect(context.Background(), r.IP, port)
		if err != nil {
			t.Fatal(err)
		}
		_, refused := res.(egress.Refused)
		if r.PortEligible == refused {
			t.Errorf("%s: ips.csv port_eligible=%v but egress refused=%v", r.IP, r.PortEligible, refused)
		}
	}
}

// A hyperscaler address with no range data is shared; EC2-only is not.
func TestSharedFromRanges(t *testing.T) {
	var d inventory.Data
	d.Ranges = provider.NewRanges([]provider.Range{
		{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Provider: "aws", Service: "EC2"},
		{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Provider: "aws", Service: "AMAZON"},
		{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Provider: "aws", Service: "ELB"},
	})
	d.Owners = map[netip.Addr]provider.Owner{
		ip("203.0.113.5"): {ASN: 16509, Known: true}, ip("192.0.2.5"): {ASN: 16509, Known: true}, ip("54.1.1.1"): {ASN: 16509, Known: true},
	}
	inv := inventory.New(d, provider.Default())
	for a, want := range map[string]bool{"203.0.113.5": false, "192.0.2.5": true, "54.1.1.1": true} {
		if got := inv.Shared(ip(a)); got != want {
			t.Errorf("Shared(%s) = %v, want %v", a, got, want)
		}
	}
}

// Outputs are stable: when names CNAMEd to different providers share an
// address, the address's label comes from the first such name, on every run.
func TestCNAMESharedLabelIsStable(t *testing.T) {
	var d inventory.Data
	resolve(&d, "a.example.com", "203.0.113.80")
	resolve(&d, "b.example.com", "203.0.113.80")
	d.Resolutions = append(d.Resolutions,
		inventory.Resolution{Name: "a.example.com", Type: "CNAME", Value: "x.cloudfront.net"},
		inventory.Resolution{Name: "b.example.com", Type: "CNAME", Value: "y.fastly.net"})
	for range 50 {
		inv := inventory.New(d, provider.Default())
		rows := inv.IPRows(newScope(inv, d))
		if len(rows) != 1 || rows[0].Provider != "aws" || rows[0].Service != "CloudFront" {
			t.Fatalf("IPRows = %+v, want the label of a.example.com", rows)
		}
	}
}

// One eligibility function for the sweep, egress and ips.csv.
func TestPortEligibleMatchesIPRows(t *testing.T) {
	var d inventory.Data
	resolve(&d, "www.example.com", "203.0.113.5")
	resolve(&d, "cdn.example.com", "104.16.0.1")
	resolve(&d, "edge.example.com", "104.16.0.2") // owner unknown
	resolve(&d, "admin.example.com", "203.0.113.6")
	d.IPs = append(d.IPs, ip("198.51.100.9"))
	d.Owners = map[netip.Addr]provider.Owner{
		ip("203.0.113.5"): {ASN: 64500, Holder: "ACME-NET", Known: true},
		ip("104.16.0.1"):  {ASN: 13335, Holder: "CLOUDFLARENET", Known: true},
		ip("203.0.113.6"): {ASN: 64500, Holder: "ACME-NET", Known: true},
	}
	inv := inventory.New(d, provider.Default())
	sc := newScope(inv, d, "admin.example.com")

	want := map[string]bool{"203.0.113.5": true, "198.51.100.9": true, "104.16.0.1": false, "104.16.0.2": false, "203.0.113.6": false}
	for _, r := range inv.IPRows(sc) {
		if got := inv.PortEligible(r.IP, sc); got != r.PortEligible || got != want[r.IP.String()] {
			t.Errorf("%s: PortEligible = %v, row = %v, want %v", r.IP, got, r.PortEligible, want[r.IP.String()])
		}
	}
	// An address nothing is known about, an IPv4-mapped form and an in-scope netblock address.
	if inv.PortEligible(ip("192.0.2.77"), sc) {
		t.Error("an address with no hostname, owner or netblock must not be eligible")
	}
	if !inv.PortEligible(ip("::ffff:203.0.113.5"), sc) {
		t.Error("an IPv4-mapped address must be decided as the IPv4 address")
	}
	if !inv.PortEligible(ip("198.51.100.200"), sc) {
		t.Error("an address inside an in-scope netblock is eligible")
	}
}
