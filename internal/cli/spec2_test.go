package cli_test

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

const eng = "example.com"

func stateOf(w *world, stage string) (string, string) {
	s := lastState(w.h.events(), stage)
	if s == nil {
		return "", ""
	}
	return s.str("state"), s.str("reason")
}

// --- B1: sources ---

func TestB1_KeylessSources(t *testing.T) {
	w := newWorld(t)
	w.crtsh(map[string][]string{"example.com": {"a.example.com\n*.example.com", "b.example.com", "off.example.org"}}, nil)
	w.waybackURLs("http://c.example.com/x", "https://c.example.com/y", "http://e.example.com/z")
	w.commonCrawl("CC-MAIN-2026-01", "http://d.example.com/p")
	for _, h := range []string{"a", "b", "c", "d", "e"} {
		w.dns.A(h+".example.com", "203.0.113.5")
	}
	if code := w.run("--passive", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	got := w.lines(eng, "subdomains.txt")
	for _, want := range []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com"} {
		if !slices.Contains(got, want) {
			t.Errorf("subdomains.txt missing %s: %v", want, got)
		}
	}
	if slices.Contains(got, "off.example.org") || slices.Contains(got, "*.example.com") {
		t.Errorf("out-of-root and wildcard names must not be recorded as subdomains: %v", got)
	}
	if got := w.lines(eng, "wildcard-excluded.txt"); len(got) != 0 {
		t.Errorf("no wildcard expected: %v", got)
	}
	crt := w.requests("crt.sh")
	if len(crt) == 0 || !strings.Contains(crt[0].URI, "exclude=expired") || !strings.Contains(crt[0].URI, "deduplicate=Y") {
		t.Errorf("crt.sh request: %+v", crt)
	}
	if len(w.requests("web.archive.org")) < 3 {
		t.Errorf("wayback should be paged (count + 2 pages): %d requests", len(w.requests("web.archive.org")))
	}
	for k, a := range w.obsAttrs(eng, "hostname") {
		if k == "d.example.com" && !strings.Contains(a, "CC-MAIN-2026-01") {
			t.Errorf("Common Crawl index id missing from %s attrs %s", k, a)
		}
	}
	for _, s := range []string{"crtsh", "wayback", "commoncrawl"} {
		if st, _ := stateOf(w, s); st != "done" {
			t.Errorf("%s state = %s", s, st)
		}
	}
	for _, s := range []string{"virustotal", "securitytrails", "shodan", "whoisxml"} {
		if st, reason := stateOf(w, s); st != "not-configured" || reason != "no key" {
			t.Errorf("%s = %s (%s), want not-configured (no key)", s, st, reason)
		}
	}
}

func TestB1_KeyedSources(t *testing.T) {
	w := newWorld(t)
	keys := map[string]string{"VIRUSTOTAL": "vt-SECRET-1", "SECURITYTRAILS": "st-SECRET-2", "SHODAN": "sh-SECRET-3", "WHOISXML": "wx-SECRET-4"}
	for k, v := range keys {
		t.Setenv("RECON_KEYS_"+k, v)
	}
	w.handle("www.virustotal.com", func(rw http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") != "vt-SECRET-1" {
			http.Error(rw, "bad key", http.StatusUnauthorized)
			return
		}
		_, _ = rw.Write([]byte(`{"data":[{"id":"vt.example.com"}],"meta":{}}`))
	})
	w.handle("api.securitytrails.com", func(rw http.ResponseWriter, r *http.Request) {
		if r.Header.Get("APIKEY") != "st-SECRET-2" {
			http.Error(rw, "bad key", http.StatusForbidden)
			return
		}
		_, _ = rw.Write([]byte(`{"subdomains":["st","mail"]}`))
	})
	w.handle("api.shodan.io", func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != "sh-SECRET-3" {
			http.Error(rw, "bad key", http.StatusUnauthorized)
			return
		}
		_, _ = rw.Write([]byte(`{"matches":[],"total":0}`))
	})
	w.handle("reverse-whois.whoisxmlapi.com", func(rw http.ResponseWriter, r *http.Request) {
		_, _ = rw.Write([]byte(`{"domainsCount":0,"domainsList":[]}`))
	})
	for _, n := range []string{"vt", "st", "mail"} {
		w.dns.A(n+".example.com", "203.0.113.5")
	}
	if code := w.run("--passive", "example.com", "--cidr", "198.51.100.0/30", "--org", "Acme Corp"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	got := w.lines(eng, "subdomains.txt")
	for _, want := range []string{"vt.example.com", "st.example.com", "mail.example.com"} {
		if !slices.Contains(got, want) {
			t.Errorf("subdomains.txt missing %s: %v", want, got)
		}
	}
	for _, s := range []string{"virustotal", "securitytrails", "shodan", "whoisxml"} {
		if st, _ := stateOf(w, s); st != "done" {
			t.Errorf("%s = %s, want done", s, st)
		}
	}
	wx := w.requests("reverse-whois.whoisxmlapi.com")
	if len(wx) == 0 || !strings.Contains(wx[0].Body, "wx-SECRET-4") || !strings.Contains(wx[0].Body, "purchase") || wx[0].Method != "POST" {
		t.Errorf("whoisxml request must carry the key in the body: %+v", wx)
	}
	for _, v := range keys {
		if hits := w.anywhere(eng, v); len(hits) > 0 {
			t.Errorf("key %q leaked into %v", v, hits)
		}
	}
}

// D4: a rejected or exhausted key fails the stage, records nothing, and is retried.
func TestB1_KeyFailuresAbortAndRetry(t *testing.T) {
	for _, code := range []int{401, 403, 429} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			w := newWorld(t)
			t.Setenv("RECON_KEYS_VIRUSTOTAL", "vt-key")
			w.handle("www.virustotal.com", status(code))
			if c := w.run("--concurrency", "1", "--passive", "example.com", "example.org"); c != 0 {
				t.Fatalf("exit %d", c)
			}
			if st, _ := stateOf(w, "virustotal"); st != "failed" {
				t.Errorf("state = %s, want failed", st)
			}
			if done := w.h.completed(eng, "virustotal"); len(done) != 0 {
				t.Errorf("a rejected key must not be recorded as done: %v", done)
			}
			if n := len(w.requests("www.virustotal.com")); n != 1 {
				t.Errorf("the stage should abort after the first rejection, saw %d requests", n)
			}
			// Fix the key: the same checks run and complete.
			w.handle("www.virustotal.com", jsonBody(`{"data":[{"id":"fixed.example.com"}],"meta":{}}`))
			t.Setenv("RECON_KEYS_VIRUSTOTAL", "vt-key-fixed")
			if c := w.run("--passive", "example.com"); c != 0 {
				t.Fatalf("exit %d", c)
			}
			if done := w.h.completed(eng, "virustotal"); len(done) != 2 {
				t.Errorf("fixing the key should complete both roots: %v", done)
			}
			if !slices.Contains(w.lines(eng, "subdomains.txt"), "fixed.example.com") {
				t.Errorf("subdomains.txt = %v", w.lines(eng, "subdomains.txt"))
			}
		})
	}
}

// A 404 that means "no data" completes the check: VirusTotal for an unknown
// domain, and a Common Crawl page with no captures (the page count is of index
// blocks, not matches).
func TestB1_NotFoundIsNoData(t *testing.T) {
	w := newWorld(t)
	t.Setenv("RECON_KEYS_VIRUSTOTAL", "vt-key")
	w.handle("www.virustotal.com", status(404))
	w.handle("index.commoncrawl.org", func(rw http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case strings.HasSuffix(r.URL.Path, "collinfo.json"):
			_, _ = rw.Write([]byte(`[{"id":"CC-MAIN-2026-01"}]`))
		case q.Get("showNumPages") == "true":
			_, _ = rw.Write([]byte(`{"pages":2}`))
		case q.Get("page") == "0":
			http.Error(rw, "No Captures found for: *.example.com", 404)
		default:
			_, _ = rw.Write([]byte(`{"url":"https://cc.example.com/"}` + "\n"))
		}
	})
	w.dns.A("cc.example.com", "203.0.113.5")
	if c := w.run("--passive", "example.com"); c != 0 {
		t.Fatalf("exit %d", c)
	}
	for _, s := range []string{"virustotal", "commoncrawl"} {
		if st, _ := stateOf(w, s); st != "done" {
			t.Errorf("%s = %s, want done", s, st)
		}
		if done := w.h.completed(eng, s); len(done) != 1 {
			t.Errorf("%s completed = %v, want the root's check", s, done)
		}
	}
	if !slices.Contains(w.lines(eng, "subdomains.txt"), "cc.example.com") {
		t.Errorf("subdomains.txt = %v, want the name from the page after the empty one", w.lines(eng, "subdomains.txt"))
	}
}

func TestB1_TruncatedBodyIsAnError(t *testing.T) {
	w := newWorld(t)
	w.handle("crt.sh", func(rw http.ResponseWriter, r *http.Request) {
		_, _ = rw.Write([]byte(`[{"name_value":"a.example.com"}`))
		_, _ = rw.Write([]byte(strings.Repeat(" ", 10<<20+1000)))
		_, _ = rw.Write([]byte(`]`))
	})
	w.run("--passive", "example.com")
	if st, _ := stateOf(w, "crtsh"); st != "failed" {
		t.Errorf("crtsh = %s, want failed", st)
	}
	if done := w.h.completed(eng, "crtsh"); len(done) != 0 {
		t.Errorf("a truncated body must not be recorded as complete: %v", done)
	}
	w.crtsh(map[string][]string{"example.com": {"a.example.com"}}, nil)
	w.run("--passive", "example.com")
	if done := w.h.completed(eng, "crtsh"); len(done) != 1 {
		t.Errorf("retry should complete: %v", done)
	}
}

// An unreadable Wayback page count is a failure, not "zero pages, complete".
func TestB1_UnreadableWaybackPageCountIsAnError(t *testing.T) {
	w := newWorld(t)
	w.handle("web.archive.org", func(rw http.ResponseWriter, r *http.Request) {
		_, _ = rw.Write([]byte("<html>Service Unavailable</html>"))
	})
	w.run("--passive", "example.com")
	if st, _ := stateOf(w, "wayback"); st != "failed" {
		t.Errorf("wayback = %s, want failed", st)
	}
	if done := w.h.completed(eng, "wayback"); len(done) != 0 {
		t.Errorf("an unreadable page count must not be recorded as complete: %v", done)
	}
}

func TestB1_CrtshHasALongerTimeout(t *testing.T) {
	w := newWorld(t)
	w.h.eopts.HTTPTimeout = 150 * time.Millisecond
	slow := func(body string) http.HandlerFunc {
		return func(rw http.ResponseWriter, r *http.Request) {
			time.Sleep(450 * time.Millisecond)
			_, _ = rw.Write([]byte(body))
		}
	}
	w.handle("crt.sh", slow(`[{"name_value":"slow.example.com"}]`))
	w.handle("web.archive.org", slow("0\n"))
	w.dns.A("slow.example.com", "203.0.113.5")
	w.run("--passive", "example.com")
	if st, _ := stateOf(w, "crtsh"); st != "done" {
		t.Errorf("crtsh should outlast the default timeout, got %s", st)
	}
	if st, _ := stateOf(w, "wayback"); st != "failed" {
		t.Errorf("wayback uses the default timeout and should fail, got %s", st)
	}
}

// --- B2: permutations ---

func permWorld(t *testing.T, words string) (*world, string) {
	w := newWorld(t)
	wl := writeFile(t, t.TempDir(), "words.txt", words)
	w.crtsh(map[string][]string{"example.com": {"api.example.com", "api-both.example.com"}}, nil)
	w.dns.A("api.example.com", "203.0.113.5")
	w.dns.A("api-dev.example.com", "203.0.113.6") // a permutation that exists
	w.dns.A("dev.example.com", "203.0.113.7")     // a root-level permutation that exists
	w.dns.A("api-both.example.com", "203.0.113.8")
	return w, wl
}

func queriedPrefix(w *world, prefix string) []string {
	var out []string
	for _, n := range w.dns.Queried("A") {
		if strings.HasPrefix(n, prefix) {
			out = append(out, n)
		}
	}
	return out
}

func TestB2_PermutationsAreNeverSeeds(t *testing.T) {
	w, wl := permWorld(t, "dev\nboth\n")
	if code := w.run("--passive", "--wordlist", wl, "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if st, _ := stateOf(w, "permutations"); st != "done" {
		t.Errorf("permutations must run under --passive, state %s", st)
	}
	hosts := w.lines(eng, "subdomains.txt")
	for _, want := range []string{"api-dev.example.com", "dev.example.com"} {
		if !slices.Contains(hosts, want) {
			t.Errorf("existing permutation %s not recorded: %v", want, hosts)
		}
	}
	if bad := queriedPrefix(w, "api-dev-"); len(bad) > 0 {
		t.Errorf("a permutation was used as a seed: %v", bad)
	}
	if bad := append(queriedPrefix(w, "devdev"), queriedPrefix(w, "dev1.")...); len(bad) > 0 {
		t.Errorf("a root-level permutation was used as a seed: %v", bad)
	}
	// api-both was found by crt.sh as well as generated, so it is a seed.
	if len(queriedPrefix(w, "api-both-")) == 0 {
		t.Error("a name also found by a real source must be a seed")
	}
	if len(queriedPrefix(w, "api-")) == 0 {
		t.Error("api must be permuted")
	}
}

// Seeding the apex would split it into the label "example" under "com" and
// query other registrants' domains.
func TestB2_ApexIsNotSeed(t *testing.T) {
	w := newWorld(t)
	wl := writeFile(t, t.TempDir(), "words.txt", "dev\nmail\n")
	w.crtsh(map[string][]string{"example.com": {"example.com", "api.example.com"}}, nil)
	w.dns.A("api.example.com", "203.0.113.5")
	w.dns.A("example1.com", "203.0.113.99")
	w.run("--passive", "--wordlist", wl, "example.com")
	for _, n := range w.dns.Queried("A") {
		if n != "example.com" && !strings.HasSuffix(n, ".example.com") {
			t.Errorf("queried %s, which is not under the root", n)
		}
	}
	for _, r := range w.table(eng, "candidates.csv") {
		if r["type"] == "hostname" {
			t.Errorf("permutations produced a candidate: %v", r)
		}
	}
	if len(queriedPrefix(w, "api-")) == 0 {
		t.Error("api must still be permuted")
	}
}

func TestB2_Disabled(t *testing.T) {
	w, wl := permWorld(t, "dev\n")
	w.run("--passive", "--wordlist", wl, "--no-permutations", "example.com")
	if st, reason := stateOf(w, "permutations"); st != "not-configured" || reason != "disabled" {
		t.Errorf("permutations = %s (%s)", st, reason)
	}
	if got := w.dns.Count("api-dev.example.com", "A") + w.dns.Count("dev.example.com", "A"); got != 0 {
		t.Errorf("no permutation names may be queried when disabled, got %d", got)
	}
}

func TestB2_InvalidCapExits2(t *testing.T) {
	w, _ := permWorld(t, "dev\n")
	if code := w.run("--passive", "--permutations-max", "0", "example.com"); code != 2 {
		t.Errorf("exit %d, want 2", code)
	}
	if w.dns.Total() != 0 {
		t.Error("nothing may be queried after a validation error")
	}
}

func TestB2_CapAndSettingsChangeChecks(t *testing.T) {
	w, wl := permWorld(t, "dev\nboth\nstaging\ntest\nbeta\nold\nnew\nqa\n")
	w.run("--passive", "--wordlist", wl, "--permutations-max", "5", "example.com")
	var fromApi int
	for _, n := range w.dns.Queried("A") {
		label, _, _ := strings.Cut(n, ".")
		if strings.Contains(label, "api") && label != "api" && !strings.HasPrefix(label, "api-both-") {
			fromApi++
		}
	}
	if fromApi > 5+5 { // api and api-both are seeds; each is capped at 5
		t.Errorf("per-seed cap exceeded: %d names derived from api seeds", fromApi)
	}
	before := w.h.completed(eng, "permutations")
	if len(before) == 0 {
		t.Fatal("no permutation checks recorded")
	}
	w.run("--passive", "--wordlist", wl, "--permutations-max", "6", "example.com")
	afterCap := w.h.completed(eng, "permutations")
	if len(afterCap) <= len(before) {
		t.Errorf("changing the cap must create new seed checks: %d -> %d", len(before), len(afterCap))
	}
	if err := os.WriteFile(wl, []byte("dev\nboth\nstaging\nextra\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w.run("--passive", "--wordlist", wl, "--permutations-max", "6", "example.com")
	afterWL := w.h.completed(eng, "permutations")
	if len(afterWL) <= len(afterCap) {
		t.Errorf("changing the wordlist must create new checks: %d -> %d", len(afterCap), len(afterWL))
	}
}

// --- B3: resolution ---

func TestB3_UnresolvedAndCNAME(t *testing.T) {
	w := newWorld(t)
	w.crtsh(map[string][]string{"example.com": {"nx.example.com", "nodata.example.com", "fail.example.com", "www.example.com", "bad.example.com"}}, nil)
	w.dns.TXT("nodata.example.com", "just text") // exists, no A/AAAA
	w.dns.Rcode("fail.example.com", int(mdns.RcodeServerFailure))
	w.dns.CNAME("www.example.com", "lb.example.net")
	w.dns.A("lb.example.net", "203.0.113.10")
	w.owner("203.0.113.10", 64500, "ACME-NET")
	w.dns.CNAME("bad.example.com", "lb2.example.net")
	w.dns.A("lb2.example.net", "192.0.2.50")
	w.owner("192.0.2.50", 64500, "ACME-NET")
	if code := w.run("--passive", "-x", "192.0.2.0/24", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	attrs := w.obsAttrs(eng, "unresolved")
	for name, rcode := range map[string]string{"nx.example.com": "NXDOMAIN", "nodata.example.com": "NODATA", "fail.example.com": "SERVFAIL"} {
		if !strings.Contains(attrs[name], `"rcode":"`+rcode+`"`) {
			t.Errorf("%s unresolved attrs = %q, want rcode %s", name, attrs[name], rcode)
		}
	}
	if got := w.lines(eng, "unresolved.txt"); !slices.Equal(got, []string{"fail.example.com", "nodata.example.com", "nx.example.com"}) {
		t.Errorf("unresolved.txt = %v", got)
	}
	res := w.table(eng, "resolutions.csv")
	if find(res, "name", "www.example.com") == nil {
		t.Fatalf("resolutions.csv = %v", res)
	}
	var wwwA, lbA, wwwCNAME bool
	for _, r := range res {
		wwwA = wwwA || (r["name"] == "www.example.com" && r["type"] == "A" && r["value"] == "203.0.113.10")
		lbA = lbA || (r["name"] == "lb.example.net" && r["type"] == "A")
		wwwCNAME = wwwCNAME || (r["name"] == "www.example.com" && r["type"] == "CNAME" && r["value"] == "lb.example.net")
	}
	if !wwwA || lbA || !wwwCNAME {
		t.Errorf("A record must be keyed to the queried name and the CNAME recorded as a link: wwwA=%v lbA=%v cname=%v", wwwA, lbA, wwwCNAME)
	}
	if ip := find(w.table(eng, "ips.csv"), "ip", "203.0.113.10"); ip == nil || ip["port_eligible"] != "true" || !strings.Contains(ip["hostnames"], "www.example.com") {
		t.Errorf("host behind a CNAME must be port-eligible: %v", ip)
	}
	if ex := find(w.table(eng, "excluded.csv"), "value", "bad.example.com"); ex == nil {
		t.Errorf("a host whose A record is in an excluded CIDR must be excluded: %s", w.file(eng, "excluded.csv"))
	}
}

func TestB3_TimeoutIsTransient(t *testing.T) {
	w := newWorld(t)
	w.crtsh(map[string][]string{"example.com": {"slow.example.com"}}, nil)
	w.dns.A("slow.example.com", "203.0.113.5")
	w.dns.Drop("slow.example.com")
	w.run("--passive", "example.com")
	if slices.Contains(w.h.completed(eng, "resolve"), "slow.example.com") {
		t.Error("a DNS timeout must not complete the check")
	}
	if len(w.obsAttrs(eng, "unresolved")) != 0 {
		t.Error("a timeout is not an unresolved name (and not a takeover signal)")
	}
	w.dns.Undrop("slow.example.com")
	w.run("--passive", "example.com")
	if !slices.Contains(w.h.completed(eng, "resolve"), "slow.example.com") {
		t.Error("the failed check must be retried on the next run")
	}
	if find(w.table(eng, "resolutions.csv"), "name", "slow.example.com") == nil {
		t.Error("the retry should record the resolution")
	}
}

// --- B4: wildcards ---

func TestB4_Wildcards(t *testing.T) {
	w := newWorld(t)
	w.crtsh(map[string][]string{"example.com": {"junk1.example.com", "junk2.example.com", "real.example.com"}}, nil)
	w.dns.Wildcard("example.com", "203.0.113.1", "203.0.113.2")
	w.dns.A("real.example.com", "203.0.113.50")
	w.owner("203.0.113.1", 64500, "ACME-NET")
	w.owner("203.0.113.2", 64500, "ACME-NET")
	w.owner("203.0.113.50", 64500, "ACME-NET")
	w.run("--passive", "--no-permutations", "example.com") // permutations would add many wildcard-only names

	if got := w.lines(eng, "wildcard-excluded.txt"); !slices.Equal(got, []string{"junk1.example.com", "junk2.example.com"}) {
		t.Errorf("wildcard-excluded.txt = %v", got)
	}
	if hosts := w.lines(eng, "subdomains.txt"); slices.Contains(hosts, "junk1.example.com") || !slices.Contains(hosts, "real.example.com") {
		t.Errorf("subdomains.txt = %v", hosts)
	}
	if got := w.probed(); !slices.Equal(got, []string{"example.com", "junk1.example.com", "real.example.com"}) {
		t.Errorf("ProbeHostnames = %v: want real plus one representative", got)
	}
	re := regexp.MustCompile(`^[a-z0-9]{16}\.example\.com$`)
	var random int
	for _, n := range w.dns.Queried("A") {
		if re.MatchString(n) {
			random++
		}
	}
	if random != 2 {
		t.Errorf("wildcard detection should query two random 16-char labels, saw %d", random)
	}
	for _, a := range []string{"203.0.113.1", "203.0.113.2"} {
		if ip := find(w.table(eng, "ips.csv"), "ip", a); ip != nil && ip["port_eligible"] == "true" {
			t.Errorf("a wildcard-only name must not make %s eligible", a)
		}
	}
	if ip := find(w.table(eng, "ips.csv"), "ip", "203.0.113.50"); ip == nil || ip["port_eligible"] != "true" {
		t.Errorf("real host should be eligible: %v", ip)
	}

	// A name discovered after the zone's check is still caught.
	w.crtsh(map[string][]string{"example.com": {"junk1.example.com", "junk2.example.com", "real.example.com", "junk3.example.com"}}, nil)
	w.h.exec("--json", "--redo", "crtsh", "--rate-per-source", "1000", "--rate-dns", "100000", "--passive", "--no-permutations", "example.com")
	if got := w.lines(eng, "wildcard-excluded.txt"); !slices.Contains(got, "junk3.example.com") {
		t.Errorf("late name not excluded: %v", got)
	}
}

// With permutations on (the default) every generated name "exists" under a
// wildcard, yet exactly one representative and the real host are probed.
func TestB4_WildcardWithDefaultPermutations(t *testing.T) {
	w := newWorld(t)
	w.crtsh(map[string][]string{"example.com": {"real.example.com"}}, nil)
	w.dns.Wildcard("example.com", "203.0.113.1", "203.0.113.2")
	w.dns.A("real.example.com", "203.0.113.50")
	w.run("--passive", "example.com")
	excluded := w.lines(eng, "wildcard-excluded.txt")
	if len(excluded) < 100 {
		t.Fatalf("expected the generated names to be wildcard-only, got %d", len(excluded))
	}
	probed := w.probed()
	if len(probed) != 3 || !slices.Contains(probed, "example.com") || !slices.Contains(probed, "real.example.com") {
		t.Fatalf("probed = %v", probed)
	}
	for _, p := range probed {
		if p != "example.com" && p != "real.example.com" && p != excluded[0] {
			t.Errorf("the representative must be the smallest wildcard-only name %s, got %s", excluded[0], p)
		}
	}
}

// A sub-root's parents are not ours to probe.
func TestB4_SubRootDoesNotProbeItsParent(t *testing.T) {
	w := newWorld(t)
	w.crtsh(map[string][]string{"corp.example.com": {"a.corp.example.com"}}, nil)
	w.dns.A("a.corp.example.com", "203.0.113.5")
	w.run("--passive", "--no-permutations", "corp.example.com")
	for _, n := range w.dns.Queried("A") {
		if n != "corp.example.com" && !strings.HasSuffix(n, ".corp.example.com") {
			t.Errorf("queried %s, outside the root corp.example.com", n)
		}
	}
}

func TestB4_WildcardByCNAME(t *testing.T) {
	w := newWorld(t)
	w.crtsh(map[string][]string{"example.com": {"x.example.com", "y.example.com", "z.example.com"}}, nil)
	w.dns.WildcardCNAME("example.com", "lb.example.net")
	w.dns.A("lb.example.net", "203.0.113.9")
	w.dns.CNAME("z.example.com", "other.example.net")
	w.dns.A("other.example.net", "203.0.113.77")
	w.run("--passive", "--no-permutations", "example.com")
	if got := w.lines(eng, "wildcard-excluded.txt"); !slices.Equal(got, []string{"x.example.com", "y.example.com"}) {
		t.Errorf("wildcard-excluded.txt = %v", got)
	}
}

// --- B5, B8, B9: providers and eligibility ---

func TestB5_ProviderHosts(t *testing.T) {
	w := newWorld(t)
	w.crtsh(map[string][]string{"example.com": {"cdn.example.com", "dang.example.com", "plain.example.com"}}, nil)
	w.dns.CNAME("cdn.example.com", "d1.cloudfront.net")
	w.dns.A("d1.cloudfront.net", "203.0.113.20")
	w.dns.CNAME("dang.example.com", "gone.azurewebsites.net")
	w.dns.CNAME("plain.example.com", "mail.example.net")
	w.dns.A("mail.example.net", "203.0.113.21")
	w.owner("203.0.113.20", 64500, "ACME-NET")
	w.owner("203.0.113.21", 64500, "ACME-NET")
	w.run("--passive", "example.com")
	rows := w.table(eng, "provider-hosts.csv")
	if r := find(rows, "hostname", "cdn.example.com"); r == nil || r["provider"] != "aws" || r["service"] != "CloudFront" ||
		r["evidence"] != "cname" || r["cname"] != "d1.cloudfront.net" || r["resolves"] != "true" {
		t.Errorf("cdn row = %v", r)
	}
	if r := find(rows, "hostname", "dang.example.com"); r == nil || r["provider"] != "azure" || r["resolves"] != "false" {
		t.Errorf("dangling chain row = %v", r)
	}
	if find(rows, "hostname", "plain.example.com") != nil {
		t.Error("unrelated suffix produced a row")
	}
	ips := w.table(eng, "ips.csv")
	if r := find(ips, "ip", "203.0.113.20"); r == nil || r["port_eligible"] != "false" || r["provider"] != "aws" || r["service"] != "CloudFront" {
		t.Errorf("an address behind a provider CNAME is shared even if its ASN is ordinary: %v", r)
	}
	if r := find(ips, "ip", "203.0.113.21"); r == nil || r["port_eligible"] != "true" {
		t.Errorf("an unrelated CNAME leaves the address eligible: %v", r)
	}
	if rows := w.table(eng, "provider-hosts.csv"); len(rows) != 2 {
		t.Errorf("one row per CNAME match, no duplicates from the address: %v", rows)
	}
	if got := w.providerHosts(); !slices.Contains(got, "cdn.example.com|aws") || !slices.Contains(got, "dang.example.com|azure") {
		t.Errorf("View.ProviderHosts = %v", got)
	}
}

func TestB8_ProviderLabelsAndSharedInfrastructure(t *testing.T) {
	w := newWorld(t)
	hosts := map[string]struct {
		addr   string
		asn    int
		holder string
	}{
		"ec2":    {"203.0.113.5", 16509, "AMAZON-02"},
		"cf":     {"192.0.2.5", 16509, "AMAZON-02"},
		"gcp":    {"100.64.1.1", 15169, "GOOGLE"},
		"azure":  {"20.1.1.1", 8075, "MICROSOFT-CORP"},
		"cdn":    {"104.16.0.5", 13335, "CLOUDFLARENET"},
		"aws2":   {"54.1.1.1", 16509, "AMAZON-02"},
		"plain":  {"100.65.0.1", 64500, "ACME-NET"},
		"nobody": {"100.66.0.1", 0, ""},
	}
	var names []string
	for h, v := range hosts {
		n := h + ".example.com"
		names = append(names, n)
		w.dns.A(n, v.addr)
		if v.asn != 0 {
			w.owner(v.addr, v.asn, v.holder)
		}
	}
	// Heroku runs on EC2-only ranges: only the CNAME shows the address is shared.
	names = append(names, "hk.example.com")
	w.dns.CNAME("hk.example.com", "x.herokudns.com")
	w.dns.A("x.herokudns.com", "203.0.113.9")
	w.owner("203.0.113.9", 16509, "AMAZON-02")
	w.crtsh(map[string][]string{"example.com": names}, nil)
	w.handle("ip-ranges.amazonaws.com", jsonBody(`{"prefixes":[
		{"ip_prefix":"203.0.113.0/24","region":"eu-west-1","service":"AMAZON"},
		{"ip_prefix":"203.0.113.0/24","region":"eu-west-1","service":"EC2"},
		{"ip_prefix":"192.0.2.0/24","region":"GLOBAL","service":"AMAZON"},
		{"ip_prefix":"192.0.2.0/24","region":"GLOBAL","service":"CLOUDFRONT"}],"ipv6_prefixes":[]}`))
	w.handle("www.gstatic.com", jsonBody(`{"prefixes":[{"ipv4Prefix":"100.64.0.0/16","service":"Google Cloud","scope":"europe-west1"}]}`))
	w.run("--passive", "example.com")
	ips := w.table(eng, "ips.csv")
	for _, c := range []struct{ ip, provider, service, eligible string }{
		{"203.0.113.5", "aws", "EC2", "true"},
		{"192.0.2.5", "aws", "CLOUDFRONT", "false"},
		{"100.64.1.1", "gcp", "", "false"},
		{"20.1.1.1", "azure", "", "false"},
		{"104.16.0.5", "cloudflare", "", "false"},
		{"54.1.1.1", "aws", "", "false"},
		{"100.65.0.1", "", "", "true"},
		{"203.0.113.9", "heroku", "Heroku", "false"},
	} {
		r := find(ips, "ip", c.ip)
		if r == nil || r["provider"] != c.provider || r["service"] != c.service || r["port_eligible"] != c.eligible {
			t.Errorf("%s: %v, want provider=%q service=%q eligible=%s", c.ip, r, c.provider, c.service, c.eligible)
		}
	}
	if r := find(ips, "ip", "100.66.0.1"); r == nil || r["owner"] != "unknown" || r["port_eligible"] != "false" {
		t.Errorf("unknown owner: %v", r)
	}
	ph := w.table(eng, "provider-hosts.csv")
	if r := find(ph, "hostname", "cf.example.com"); r == nil || r["evidence"] != "range" || r["cname"] != "" {
		t.Errorf("an AWS apex ALIAS (A record, no CNAME) must be recognised by range: %v", r)
	}
	if find(ph, "hostname", "ec2.example.com") != nil {
		t.Error("EC2-only is not shared infrastructure")
	}
}

func TestB9_OwnerLookupFailureFailsClosed(t *testing.T) {
	w := newWorld(t)
	w.crtsh(map[string][]string{"example.com": {"cdn.example.com"}}, nil)
	w.dns.A("cdn.example.com", "104.16.0.5")
	w.dns.RcodeSuffix("asn.cymru.com", int(mdns.RcodeServerFailure))
	w.run("--passive", "example.com")
	if st, _ := stateOf(w, "ipowner"); st != "failed" {
		t.Errorf("ipowner = %s, want failed", st)
	}
	r := find(w.table(eng, "ips.csv"), "ip", "104.16.0.5")
	if r == nil || r["owner"] != "unknown" || r["port_eligible"] != "false" {
		t.Errorf("a CDN edge IP must not become a port-check target when the owner source fails: %v", r)
	}
}

// --- B6: organisation pivots ---

func TestB6_OrganisationPivots(t *testing.T) {
	w := newWorld(t)
	t.Setenv("RECON_KEYS_WHOISXML", "wx-key")
	w.crtsh(nil, map[string][]string{"Acme Corp": {"www.acme-global.com", "*.acme-global.net", "someone@acme-global.org"}})
	w.handle("reverse-whois.whoisxmlapi.com", jsonBody(`{"domainsCount":1,"domainsList":["acme-brands.com"]}`))
	var cats []string
	cats = append(cats, `{"value":"AS64500","description":"ACME-NET - Acme Corp"}`, `{"value":"AS64999","description":"UNRELATED - Other Co"}`)
	for i := 0; i < 12; i++ {
		cats = append(cats, fmt.Sprintf(`{"value":"AS%d","description":"ACME-X%d - Acme Corp Ltd"}`, 65000+i, i))
	}
	w.handle("stat.ripe.net", func(rw http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "searchcomplete") {
			fmt.Fprintf(rw, `{"status":"ok","data":{"categories":[{"category":"ASNs","suggestions":[%s]}]}}`, strings.Join(cats, ","))
			return
		}
		res := strings.TrimPrefix(r.URL.Query().Get("resource"), "AS")
		fmt.Fprintf(rw, `{"status":"ok","data":{"prefixes":[{"prefix":"100.%d.%d.0/24"}]}}`, len(res)%200, len(res))
	})
	w.dns.A("www.example.com", "203.0.113.5")
	w.run("--passive", "--org", "Acme Corp", "example.com")
	cand := w.table(eng, "candidates.csv")
	for _, root := range []string{"acme-global.com", "acme-global.net", "acme-brands.com"} {
		if r := find(cand, "value", root); r == nil || r["type"] != "root" {
			t.Errorf("root %s should be a candidate: %v", root, r)
		}
	}
	var nets int
	for _, r := range cand {
		if r["type"] == "netblock" {
			nets++
		}
	}
	if nets == 0 {
		t.Error("org-asn should record netblock candidates")
	}
	var prefixCalls int
	for _, rq := range w.requests("stat.ripe.net") {
		if strings.Contains(rq.URI, "announced-prefixes") {
			prefixCalls++
			if strings.Contains(rq.URI, "AS64999") {
				t.Error("an ASN whose holder does not match the organisation must be ignored")
			}
		}
	}
	if prefixCalls != 10 {
		t.Errorf("org-asn must cap at 10 ASNs, made %d announced-prefixes requests", prefixCalls)
	}
	for _, r := range w.table(eng, "scope.csv") {
		if r["type"] == "netblock" {
			t.Errorf("org-derived netblocks are candidates, never in scope: %v", r)
		}
	}
	for _, typ := range []string{"A", "AAAA", "PTR"} {
		for _, n := range w.dns.Queried(typ) {
			if strings.Contains(n, "acme-") || strings.HasSuffix(n, "in-addr.arpa") && strings.Contains(n, ".100.") {
				t.Errorf("candidates must not be enumerated, but %s %s was queried", typ, n)
			}
		}
	}
}

// --- B7: netblocks and reverse DNS ---

func TestB7_ReverseDNSAndShodan(t *testing.T) {
	w := newWorld(t)
	t.Setenv("RECON_KEYS_SHODAN", "sh-key")
	w.dns.PTR("198.51.100.1", "host1.example.com")
	w.dns.PTR("198.51.100.2", "ptr.other.org")
	w.dns.A("host1.example.com", "198.51.100.1")
	w.dns.A("elsewhere.example.com", "203.0.113.99")
	w.crtsh(map[string][]string{"example.com": {"elsewhere.example.com"}}, nil)
	w.owner("203.0.113.99", 64500, "ACME-NET")
	w.handle("api.shodan.io", func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") != "" && r.URL.Query().Get("page") != "1" {
			_, _ = rw.Write([]byte(`{"matches":[],"total":1}`))
			return
		}
		_, _ = rw.Write([]byte(`{"matches":[{"ip_str":"198.51.100.3","hostnames":["shodan.other.org"]}],"total":1}`))
	})
	if code := w.run("--passive", "--cidr", "198.51.100.0/30", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	ptrs := w.dns.Queried("PTR")
	if len(ptrs) != 4 {
		t.Errorf("a /30 must be PTR-swept in full, queried %v", ptrs)
	}
	for _, p := range ptrs {
		if !strings.HasSuffix(p, ".100.51.198.in-addr.arpa") {
			t.Errorf("rdns must not run for non-scope IPs: %s", p)
		}
	}
	if !slices.Contains(w.lines(eng, "subdomains.txt"), "host1.example.com") {
		t.Errorf("subdomains.txt = %v", w.lines(eng, "subdomains.txt"))
	}
	cand := w.table(eng, "candidates.csv")
	if find(cand, "value", "ptr.other.org") == nil || find(cand, "value", "shodan.other.org") == nil {
		t.Errorf("out-of-scope names should be candidates: %s", w.file(eng, "candidates.csv"))
	}
	ips := w.table(eng, "ips.csv")
	if r := find(ips, "ip", "198.51.100.2"); r == nil || !strings.Contains(r["hostnames"], "ptr.other.org") {
		t.Errorf("PTR name must be recorded against the IP: %v", r)
	}
	if r := find(ips, "ip", "198.51.100.3"); r == nil || !strings.Contains(r["hostnames"], "shodan.other.org") {
		t.Errorf("Shodan hostnames must be recorded against the IP: %v", r)
	}
	sh := w.requests("api.shodan.io")
	if len(sh) == 0 || !strings.Contains(sh[0].URI, "net%3A198.51.100.0%2F30") {
		t.Errorf("shodan query: %+v", sh)
	}
}

func TestB7_IPv6OnlyChecksFoundAddresses(t *testing.T) {
	w := newWorld(t)
	w.crtsh(map[string][]string{"example.com": {"v6.example.com"}}, nil)
	w.dns.A("v6.example.com", "2001:db8:1::5")
	w.dns.PTR("2001:db8:1::5", "v6ptr.example.com")
	w.dns.A("v6ptr.example.com", "2001:db8:1::5")
	if code := w.run("--passive", "--cidr", "2001:db8:1::/64", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if ptrs := w.dns.Queried("PTR"); len(ptrs) != 1 || !strings.HasPrefix(ptrs[0], "5.0.0.0.") {
		t.Errorf("only addresses found by other stages are checked for IPv6: %v", ptrs)
	}
	if !slices.Contains(w.lines(eng, "subdomains.txt"), "v6ptr.example.com") {
		t.Errorf("subdomains.txt = %v", w.lines(eng, "subdomains.txt"))
	}
}

// --- Plumbing ---

func TestPlumbing_FilesAndCounts(t *testing.T) {
	w := newWorld(t)
	w.crtsh(map[string][]string{"example.com": {"b.example.com", "a.example.com", "nx.example.com"}}, nil)
	w.dns.A("a.example.com", "203.0.113.5")
	w.dns.A("b.example.com", "203.0.113.6")
	w.owner("203.0.113.5", 64500, "ACME-NET")
	w.owner("203.0.113.6", 64500, "ACME-NET")
	w.run("--passive", "example.com")
	evs := w.h.events()
	counts := map[string]int{}
	for _, e := range ofType(evs, "count") {
		counts[e.str("category")] = e.num("n")
	}
	if counts["ips"] != 3 || counts["unresolved names"] != 1 {
		t.Errorf("counts = %v", counts)
	}
	snapshot := map[string]string{}
	for _, f := range []string{"subdomains.txt", "resolutions.csv", "unresolved.txt", "wildcard-excluded.txt", "ips.csv", "provider-hosts.csv"} {
		snapshot[f] = w.file(eng, f)
	}
	if !strings.HasPrefix(snapshot["subdomains.txt"], "a.example.com\nb.example.com\n") {
		t.Errorf("subdomains.txt must be sorted: %q", snapshot["subdomains.txt"])
	}
	hdr := strings.SplitN(snapshot["ips.csv"], "\n", 2)[0]
	if hdr != "ip,asn,owner,provider,service,in_scope,port_eligible,hostnames,current,first_seen,last_seen" {
		t.Errorf("ips.csv header = %q", hdr)
	}
	if snapshot["provider-hosts.csv"] != "" || snapshot["wildcard-excluded.txt"] != "" {
		t.Errorf("files with no rows were written: %q %q", snapshot["provider-hosts.csv"], snapshot["wildcard-excluded.txt"])
	}
	if hdr := strings.SplitN(snapshot["resolutions.csv"], "\n", 2)[0]; hdr != "name,type,value,current,first_seen,last_seen" {
		t.Errorf("resolutions.csv header = %q", hdr)
	}
	if r := find(w.table(eng, "ips.csv"), "ip", "203.0.113.5"); r == nil || r["first_seen"] != "2026-11-01" || r["asn"] != "AS64500" {
		t.Errorf("ips row: %v", r)
	}
	// A resumed run changes nothing.
	w.run("--passive", "example.com")
	for f, before := range snapshot {
		if after := w.file(eng, f); after != before {
			t.Errorf("%s changed on an idle re-run", f)
		}
	}
	for _, f := range []string{"subdomains.txt", "ips.csv"} {
		if _, err := os.Stat(filepath.Join(w.h.eng(eng), f)); err != nil {
			t.Error(err)
		}
	}
}
