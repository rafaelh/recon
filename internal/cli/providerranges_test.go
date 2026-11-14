package cli_test

import (
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"

	"github.com/rafaelh/recon/internal/stages/providerranges"
)

// The seven publishers, as the stage fetches them. The addresses are ones no
// other test uses: 100.67/24 is DigitalOcean's, 100.68/24 Linode's, 100.69.0/24
// Oracle's OCI and 100.69.1/24 its OSN.
const (
	cloudflareV4 = "104.16.0.0/13\n"
	cloudflareV6 = "2606:4700::/32\n"
	fastlyList   = `{"addresses":["151.101.0.0/16"],"ipv6_addresses":["2a04:4e40::/32"]}`
	doList       = "100.67.0.0/24,US,US-NJ,North Bergen,07047\n"
	linodeList   = "# geofeed\n100.68.0.0/24,US,US-TX,Richardson,\n"
	oracleList   = `{"regions":[{"region":"us-phoenix-1","cidrs":[{"cidr":"100.69.0.0/24","tags":["OCI"]},{"cidr":"100.69.1.0/24","tags":["OSN"]}]}]}`
	awsList      = `{"prefixes":[{"ip_prefix":"203.0.113.0/24","region":"eu-west-1","service":"EC2"}],"ipv6_prefixes":[]}`
	gcpList      = `{"prefixes":[{"ipv4Prefix":"100.64.0.0/16","scope":"europe-west1"}]}`
)

var allRangeChecks = []string{"aws", "cloudflare-v4", "cloudflare-v6", "digitalocean", "fastly", "gcp", "linode", "oracle"}

// rangeHosts are the seven publishers; newRangeHosts those added after AWS and GCP.
var (
	rangeHosts    = providerranges.New().Sources()
	newRangeHosts = slices.DeleteFunc(slices.Clone(rangeHosts), func(h string) bool {
		return h == "ip-ranges.amazonaws.com" || h == "www.gstatic.com"
	})
)

// allRangeChecksBut is every list's check key except k.
func allRangeChecksBut(k string) []string {
	return slices.DeleteFunc(slices.Clone(allRangeChecks), func(c string) bool { return c == k })
}

// serveNewRanges answers the six lists added after AWS and GCP.
func serveNewRanges(w *world) {
	w.handle("www.cloudflare.com", func(rw http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ips-v4":
			_, _ = rw.Write([]byte(cloudflareV4))
		case "/ips-v6":
			_, _ = rw.Write([]byte(cloudflareV6))
		default:
			http.NotFound(rw, r)
		}
	})
	w.handle("api.fastly.com", jsonBody(fastlyList))
	w.handle("www.digitalocean.com", jsonBody(doList))
	w.handle("docs.oracle.com", jsonBody(oracleList))
	w.handle("geoip.linode.com", jsonBody(linodeList))
}

func serveOldRanges(w *world) {
	w.handle("ip-ranges.amazonaws.com", jsonBody(awsList))
	w.handle("www.gstatic.com", jsonBody(gcpList))
}

func serveAllRanges(w *world) { serveOldRanges(w); serveNewRanges(w) }

func requestCount(w *world, hosts ...string) int {
	n := 0
	for _, h := range hosts {
		n += len(w.requests(h))
	}
	return n
}

func uris(w *world, host string) []string {
	var out []string
	for _, r := range w.requests(host) {
		out = append(out, r.URI)
	}
	slices.Sort(out)
	return out
}

// Each list is its own check, fetched once and refreshed only by --redo.
func TestProviderRanges_EachListIsItsOwnCheckFetchedOnce(t *testing.T) {
	w := newWorld(t)
	serveAllRanges(w)
	if code := w.run("--passive", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got := sorted(w.h.completed(eng, "providerranges")); !slices.Equal(got, allRangeChecks) {
		t.Errorf("completed = %v, want %v", got, allRangeChecks)
	}
	for host, want := range map[string][]string{
		"ip-ranges.amazonaws.com": {"/ip-ranges.json"},
		"www.gstatic.com":         {"/ipranges/cloud.json"},
		"www.cloudflare.com":      {"/ips-v4", "/ips-v6"},
		"api.fastly.com":          {"/public-ip-list"},
		"www.digitalocean.com":    {"/geo/google.csv"},
		"docs.oracle.com":         {"/en-us/iaas/tools/public_ip_ranges.json"},
		"geoip.linode.com":        {"/"},
	} {
		if got := uris(w, host); !slices.Equal(got, want) {
			t.Errorf("%s was asked for %v, want %v", host, got, want)
		}
	}
	first := requestCount(w, rangeHosts...)
	if first != 8 {
		t.Errorf("%d range requests, want 8 (one per list)", first)
	}

	// Another run fetches nothing.
	w.run("--passive", "example.com")
	if n := requestCount(w, rangeHosts...); n != first {
		t.Errorf("a second run made %d more range requests", n-first)
	}

	// --redo refreshes every list.
	w.run("--passive", "--redo", "providerranges", "example.com")
	if n := requestCount(w, rangeHosts...); n != 2*first {
		t.Errorf("--redo providerranges: %d requests in all, want %d", n, 2*first)
	}
}

// An engagement that already holds AWS and GCP fetches only the six new lists.
func TestProviderRanges_ExistingEngagementFetchesOnlyTheNewLists(t *testing.T) {
	w := newWorld(t)
	serveOldRanges(w) // the new publishers answer 404 until they are served
	w.run("--passive", "example.com")
	if got := sorted(w.h.completed(eng, "providerranges")); !slices.Equal(got, []string{"aws", "gcp"}) {
		t.Fatalf("before the upgrade: completed = %v", got)
	}

	serveNewRanges(w)
	if code := w.run("--passive", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got := sorted(w.h.completed(eng, "providerranges")); !slices.Equal(got, allRangeChecks) {
		t.Errorf("completed = %v, want %v", got, allRangeChecks)
	}
	if n := requestCount(w, "ip-ranges.amazonaws.com", "www.gstatic.com"); n != 2 {
		t.Errorf("AWS and GCP were fetched %d times in all, want once each", n)
	}
	if n := len(w.requests("www.cloudflare.com")); n < 2 {
		t.Errorf("the Cloudflare lists were not fetched: %d requests", n)
	}
}

// A list that cannot be read is a failed check named in the --verbose warning;
// the ranges fetched before still apply and nothing is reported as a finding.
func TestProviderRanges_FailedListKeepsEarlierRanges(t *testing.T) {
	for _, c := range []struct {
		name  string
		serve http.HandlerFunc
	}{
		{"download fails", status(500)},
		{"empty body", jsonBody("")},
		{"no ranges in the body", jsonBody("<html>moved</html>")},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			serveAllRanges(w)
			w.crtsh(map[string][]string{"example.com": {"do.example.com", "cf.example.com"}}, nil)
			w.dns.A("do.example.com", "100.67.0.9")
			w.owner("100.67.0.9", 14061, "DIGITALOCEAN-ASN")
			w.dns.A("cf.example.com", "104.16.0.5")
			w.owner("104.16.0.5", 13335, "CLOUDFLARENET")
			if code := w.run("--passive", "example.com"); code != 0 {
				t.Fatalf("exit %d", code)
			}
			before := find(w.table(eng, "ips.csv"), "ip", "100.67.0.9")
			if before == nil || before["provider"] != "digitalocean" || before["port_eligible"] != "true" {
				t.Fatalf("with the list: %v", before)
			}

			w.handle("www.digitalocean.com", c.serve)
			if code := w.run("--passive", "--verbose", "--redo", "providerranges", "example.com"); code != 0 {
				t.Fatalf("exit %d", code)
			}
			done := sorted(w.h.completed(eng, "providerranges"))
			if want := allRangeChecksBut("digitalocean"); !slices.Equal(done, want) {
				t.Errorf("completed = %v, want every list but digitalocean", done)
			}
			if !slices.ContainsFunc(messages(w, "warning", "providerranges"), func(m string) bool { return strings.Contains(m, "digitalocean") }) {
				t.Errorf("no --verbose warning names digitalocean: %q", messages(w, "warning", ""))
			}
			if s := lastState(w.h.events(), "providerranges"); s.num("failed") != 1 {
				t.Errorf("state = %v, want one failed check", s)
			}
			after := find(w.table(eng, "ips.csv"), "ip", "100.67.0.9")
			if after == nil || after["provider"] != "digitalocean" || after["service"] != before["service"] || after["port_eligible"] != "true" {
				t.Errorf("the earlier ranges must still apply: %v, was %v", after, before)
			}
			for _, f := range []string{"risk-takeover.csv", "risk-storage.csv", "risk-sensitive-paths.csv", "risk-email.csv", "risk-ports.csv", "risk-certificates.csv"} {
				if w.file(eng, f) != "" {
					t.Errorf("%s was written after a list failed", f)
				}
			}
			for _, e := range ofType(w.h.events(), "finding") {
				t.Errorf("a missing list produced a finding: %v", e)
			}
		})
	}
}

// DigitalOcean and Linode addresses are customers' own machines and are
// port-checked; a Cloudflare address is shared and is not.
func TestProviderRanges_DedicatedRangesArePortCheckedAndCDNsAreNot(t *testing.T) {
	p := newPorts(t)
	serveAllRanges(p.world)
	ports := []int{8080}
	p.names("do.example.com", "ln.example.com", "cf.example.com", "fy.example.com")
	p.host("do.example.com", "100.67.0.9") // DigitalOcean's ASN alone says shared hosting
	p.owner("100.67.0.9", 14061, "DIGITALOCEAN-ASN")
	p.host("ln.example.com", "100.68.0.9") // Linode's owner lookup is never answered
	p.host("cf.example.com", "104.16.0.5")
	p.owner("104.16.0.5", 13335, "CLOUDFLARENET")
	p.host("fy.example.com", "151.101.1.1") // Fastly, by its list alone
	p.serve("100.67.0.9", 8080, hello)
	p.serve("100.68.0.9", 8080, hello)
	cf := p.canary("104.16.0.5", ports)
	fy := p.canary("151.101.1.1", ports)

	p.sweep(ports)

	if got, want := p.checked(), portKeys([]string{"100.67.0.9", "100.68.0.9", "203.0.113.250"}, ports); !slices.Equal(got, want) {
		t.Errorf("checked = %v\nwant     %v", got, want)
	}
	if cf.conns.Load() != 0 || fy.conns.Load() != 0 {
		t.Errorf("a CDN address was handshaken: cloudflare %d, fastly %d", cf.conns.Load(), fy.conns.Load())
	}
	if got := p.openPortKeys(); !slices.Contains(got, "100.67.0.9:8080") || !slices.Contains(got, "100.68.0.9:8080") {
		t.Errorf("open ports = %v, want the DigitalOcean and Linode services", got)
	}
	ips := p.table(eng, "ips.csv")
	for ip, eligible := range map[string]string{"100.67.0.9": "true", "100.68.0.9": "true", "104.16.0.5": "false", "151.101.1.1": "false"} {
		if r := find(ips, "ip", ip); r == nil || r["port_eligible"] != eligible {
			t.Errorf("%s: %v, want port_eligible=%s", ip, r, eligible)
		}
	}
}

// With no DigitalOcean list the ASN still applies, as before: the address is
// shared and is not handshaken.
func TestProviderRanges_DigitalOceanWithoutItsListStaysShared(t *testing.T) {
	p := newPorts(t)
	serveOldRanges(p.world)
	p.names("do.example.com")
	p.host("do.example.com", "100.67.0.9")
	p.owner("100.67.0.9", 14061, "DIGITALOCEAN-ASN")
	do := p.canary("100.67.0.9", []int{8080})

	p.sweep([]int{8080})

	if do.conns.Load() != 0 {
		t.Error("a DigitalOcean address was handshaken without the list that makes it dedicated")
	}
	r := find(p.table(eng, "ips.csv"), "ip", "100.67.0.9")
	if r == nil || r["provider"] != "digitalocean" || r["port_eligible"] != "false" {
		t.Errorf("ips.csv: %v, want digitalocean by ASN and not port-eligible", r)
	}
	if st, _ := p.stageState("providerranges"); st != "done" {
		t.Errorf("providerranges = %s: its failed lists must not fail the run", st)
	}
}

// A published range names the provider, and the service or region, in ips.csv
// even when the owner lookup failed.
func TestProviderRanges_IPsCSVNamesProviderAndRegionWithoutAnOwner(t *testing.T) {
	w := newWorld(t)
	serveAllRanges(w)
	hosts := map[string]string{
		"do": "100.67.0.9", "ln": "100.68.0.9", "oci": "100.69.0.9", "osn": "100.69.1.9",
		"cf": "104.16.0.5", "fy": "151.101.1.1",
	}
	var names []string
	for h, a := range hosts {
		names = append(names, h+".example.com")
		w.dns.A(h+".example.com", a)
	}
	w.crtsh(map[string][]string{"example.com": names}, nil)
	w.dns.RcodeSuffix("asn.cymru.com", int(mdns.RcodeServerFailure))
	if code := w.run("--passive", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if st, _ := stateOf(w, "ipowner"); st != "failed" {
		t.Fatalf("ipowner = %s, want failed", st)
	}
	ips := w.table(eng, "ips.csv")
	for _, c := range []struct{ ip, provider, service, owner, eligible string }{
		{"100.67.0.9", "digitalocean", "US-NJ", "digitalocean", "true"},
		{"100.68.0.9", "linode", "US-TX", "linode", "true"},
		{"100.69.0.9", "oracle", "OCI", "oracle", "true"},
		{"100.69.1.9", "oracle", "OSN", "oracle", "false"},
		{"104.16.0.5", "cloudflare", "", "cloudflare", "false"},
		{"151.101.1.1", "fastly", "", "fastly", "false"},
	} {
		r := find(ips, "ip", c.ip)
		if r == nil || r["provider"] != c.provider || r["service"] != c.service || r["owner"] != c.owner || r["port_eligible"] != c.eligible {
			t.Errorf("%s: %v, want provider=%s service=%q owner=%s port_eligible=%s", c.ip, r, c.provider, c.service, c.owner, c.eligible)
		}
	}
}

// A CNAME into a known provider still makes a host shared, even on a range
// that calls the address dedicated.
func TestProviderRanges_CNAMEIntoProviderStillMakesAHostShared(t *testing.T) {
	w := newWorld(t)
	serveAllRanges(w)
	w.crtsh(map[string][]string{"example.com": {"hk.example.com"}}, nil)
	w.dns.CNAME("hk.example.com", "x.herokudns.com")
	w.dns.A("x.herokudns.com", "100.67.0.9")
	w.owner("100.67.0.9", 14061, "DIGITALOCEAN-ASN")
	if code := w.run("--passive", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	r := find(w.table(eng, "ips.csv"), "ip", "100.67.0.9")
	if r == nil || r["provider"] != "heroku" || r["port_eligible"] != "false" {
		t.Errorf("ips.csv: %v, want a shared heroku address", r)
	}
	if ph := find(w.table(eng, "provider-hosts.csv"), "hostname", "hk.example.com"); ph == nil || ph["provider"] != "heroku" {
		t.Errorf("provider-hosts.csv: %v", ph)
	}
}

// --- README ---

func readmeSection(t *testing.T, heading string) (section, whole string) {
	t.Helper()
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	whole = string(b)
	start := strings.Index(whole, heading)
	if start < 0 {
		t.Fatalf("README has no %q section", heading)
	}
	end := strings.Index(whole[start+1:], "\n## ")
	if end < 0 {
		t.Fatalf("README has nothing after %q", heading)
	}
	return strings.ToLower(whole[start : start+1+end]), whole
}

// The passive-boundary section names every range publisher the stage contacts,
// and says why Azure is not one of them.
func TestReadme_NamesEveryRangePublisher(t *testing.T) {
	section, whole := readmeSection(t, "## Passive boundary")
	for _, p := range []string{"aws", "gcp", "cloudflare", "fastly", "digitalocean", "oracle", "linode"} {
		if !strings.Contains(section, p) {
			t.Errorf("the passive-boundary section does not name %q as a range publisher", p)
		}
	}
	if !strings.Contains(section, "azure") || !strings.Contains(section, "asn") {
		t.Error("the passive-boundary section does not say Azure is classified by ASN only")
	}
	if !strings.Contains(strings.ToLower(whole), "digitalocean addresses") {
		t.Error("the README does not note that DigitalOcean addresses may now be port-checked")
	}
}
