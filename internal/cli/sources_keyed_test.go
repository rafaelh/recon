package cli_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
)

// The keyed subdomain sources that reuse existing keys: shodan-dns (keys.shodan),
// censys and chaos.

// defaultPagesKey is the key of the one check a run for example.com completes.
const defaultPagesKey = "example.com|pages=10"

const (
	shodanKey = "sh-key-SECRET-0001"
	censysKey = "cs-token-SECRET-0002"
	chaosKey  = "ch-key-SECRET-0003"
)

// keyedSource describes one of the three stages: its key, the host it asks, how
// to tell the request carries the key, and the answers it gets.
type keyedSource struct {
	stage, host, env, key string
	// auth reports whether the request carries the key the way the source wants it.
	auth func(*http.Request) bool
	// ok holds the names in names plus noise that must not be recorded.
	ok    string
	names []string
}

var keyedSources = []keyedSource{
	{
		stage: "shodan-dns", host: "api.shodan.io", env: "RECON_KEYS_SHODAN", key: shodanKey,
		auth: func(r *http.Request) bool { return r.URL.Query().Get("key") == shodanKey && r.Method == "GET" },
		ok: `{"domain":"example.com","tags":[],"subdomains":["sd","only"],"more":false,"data":[
			{"subdomain":"sd","type":"A","value":"198.51.100.7","last_seen":"2026-01-01T00:00:00"},
			{"subdomain":"sd","type":"TXT","value":"v=spf1 -all"}]}`,
		names: []string{"sd.example.com", "only.example.com"},
	},
	{
		stage: "censys", host: "api.platform.censys.io", env: "RECON_KEYS_CENSYS", key: censysKey,
		auth: func(r *http.Request) bool {
			return r.Header.Get("Authorization") == "Bearer "+censysKey && r.Method == "POST"
		},
		ok: `{"result":{"total_hits":2,"next_page_token":"","hits":[
			{"certificate_v1":{"resource":{"names":["cs.example.com","*.wild.example.com","off.example.org","198.51.100.9","https://url.example.com/x"]}}},
			{"host_v1":{"resource":{"ip":"198.51.100.9"}}}]}}`,
		names: []string{"cs.example.com", "wild.example.com"},
	},
	{
		stage: "chaos", host: "dns.projectdiscovery.io", env: "RECON_KEYS_CHAOS", key: chaosKey,
		auth: func(r *http.Request) bool { return r.Header.Get("Authorization") == chaosKey && r.Method == "GET" },
		ok:   `{"domain":"example.com","subdomains":["ch","*.wild","*",""],"count":4}`,
		// "*" is the root itself and "" is nothing: neither is a new name.
		names: []string{"ch.example.com", "wild.example.com"},
	},
}

// serveOK answers with s.ok when the request carries the key, and 401 when not.
func (s keyedSource) serveOK(w *world) { s.serveWith(w, s.ok) }

func (s keyedSource) serveWith(w *world, body string) {
	w.handle(s.host, func(rw http.ResponseWriter, r *http.Request) {
		if !s.auth(r) {
			http.Error(rw, "bad key", 401)
			return
		}
		_, _ = rw.Write([]byte(body))
	})
}

func forEachKeyed(t *testing.T, fn func(t *testing.T, w *world, s keyedSource)) {
	t.Helper()
	for _, s := range keyedSources {
		t.Run(s.stage, func(t *testing.T) { fn(t, newWorld(t), s) })
	}
}

// leaks reports every place any of the keys (or an encoding of one) appears.
func leaks(w *world) []string {
	var hits []string
	for _, k := range []string{shodanKey, censysKey, chaosKey} {
		for _, form := range []string{k, url.QueryEscape(k), base64.StdEncoding.EncodeToString([]byte(k)), "Bearer " + k} {
			hits = append(hits, w.anywhere(eng, form)...)
		}
	}
	return hits
}

func TestKeyed_NotConfiguredWithoutKey(t *testing.T) {
	w := newWorld(t)
	if code := w.run("--passive", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, s := range keyedSources {
		if st, reason := stateOf(w, s.stage); st != "not-configured" || reason != "no key" {
			t.Errorf("%s = %s (%s), want not-configured (no key)", s.stage, st, reason)
		}
		if n := len(w.requests(s.host)); n != 0 {
			t.Errorf("%s sent %d requests without a key", s.stage, n)
		}
	}
}

func TestKeyed_NamesAreRecordedAndKeySent(t *testing.T) {
	forEachKeyed(t, func(t *testing.T, w *world, s keyedSource) {
		t.Setenv(s.env, s.key)
		s.serveOK(w)
		for _, n := range s.names {
			w.dns.A(n, "203.0.113.5")
		}
		if code := w.run("--passive", "--verbose", "example.com"); code != 0 {
			t.Fatalf("exit %d", code)
		}
		if st, _ := stateOf(w, s.stage); st != "done" {
			t.Errorf("%s state = %s, want done", s.stage, st)
		}
		got := w.lines(eng, "subdomains.txt")
		for _, n := range s.names {
			if !slices.Contains(got, n) {
				t.Errorf("subdomains.txt missing %s: %v", n, got)
			}
		}
		recorded := w.obsAttrs(eng, "hostname")
		for _, noise := range []string{"off.example.org", "198.51.100.9", "url.example.com", "https://url.example.com/x"} {
			if _, ok := recorded[noise]; ok {
				t.Errorf("%q must not be recorded as a hostname", noise)
			}
		}
		if done := w.h.completed(eng, s.stage); !slices.Equal(done, []string{defaultPagesKey}) {
			t.Errorf("completed = %v, want %q", done, defaultPagesKey)
		}
		reqs := w.requests(s.host)
		if len(reqs) == 0 || !strings.Contains(reqs[0].URI+reqs[0].Body, "example.com") {
			t.Fatalf("requests = %+v, want one naming the root", reqs)
		}
		if hits := leaks(w); len(hits) > 0 {
			t.Errorf("key leaked into %v", hits)
		}
	})
}

// The three request shapes, as far as the sources document them.
func TestKeyed_RequestShapes(t *testing.T) {
	w := newWorld(t)
	t.Setenv("RECON_KEYS_SHODAN", shodanKey)
	t.Setenv("RECON_KEYS_CENSYS", censysKey)
	t.Setenv("RECON_KEYS_CHAOS", chaosKey)
	for _, s := range keyedSources {
		s.serveOK(w)
	}
	if code := w.run("--passive", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	var sd, cs, ch loggedReq
	for _, r := range w.requests("api.shodan.io") {
		if strings.HasPrefix(r.URI, "/dns/domain/example.com") {
			sd = r
		}
	}
	if sd.URI == "" || !strings.Contains(sd.URI, "page=1") {
		t.Errorf("shodan-dns request = %+v, want /dns/domain/example.com?page=1&key=...", sd)
	}
	if reqs := w.requests("api.platform.censys.io"); len(reqs) > 0 {
		cs = reqs[0]
	}
	var body struct {
		Query    string `json:"query"`
		PageSize int    `json:"page_size"`
	}
	if err := json.Unmarshal([]byte(cs.Body), &body); err != nil || !strings.Contains(body.Query, "example.com") || cs.URI != "/v3/global/search/query" {
		t.Errorf("censys request = %+v (%v)", cs, err)
	}
	if cs.Header.Get("Content-Type") != "application/json" {
		t.Errorf("censys Content-Type = %q", cs.Header.Get("Content-Type"))
	}
	if reqs := w.requests("dns.projectdiscovery.io"); len(reqs) > 0 {
		ch = reqs[0]
	}
	if ch.URI != "/dns/example.com/subdomains" {
		t.Errorf("chaos request = %+v", ch)
	}
}

// A rejected key or a spent quota stops that stage for the run, and only that stage.
func TestKeyed_RejectionStopsOnlyThatStage(t *testing.T) {
	for _, s := range keyedSources {
		for _, code := range []int{401, 403, 429} {
			t.Run(fmt.Sprintf("%s/%d", s.stage, code), func(t *testing.T) {
				w := newWorld(t)
				for _, o := range keyedSources {
					t.Setenv(o.env, o.key)
					if o.host != s.host {
						o.serveOK(w)
					}
				}
				w.handle(s.host, status(code))
				if c := w.run("--passive", "--verbose", "--concurrency", "1", "example.com", "example.org"); c != 0 {
					t.Fatalf("exit %d", c)
				}
				if st, _ := stateOf(w, s.stage); st != "failed" {
					t.Errorf("%s state = %s, want failed", s.stage, st)
				}
				if n := len(w.requests(s.host)); n != 1 {
					t.Errorf("the stage should stop after the rejection, saw %d requests", n)
				}
				for _, o := range keyedSources {
					if o.host == s.host {
						continue
					}
					if st, _ := stateOf(w, o.stage); st != "done" {
						t.Errorf("%s = %s: another stage must not stop", o.stage, st)
					}
				}
				if hits := leaks(w); len(hits) > 0 {
					t.Errorf("key leaked into %v", hits)
				}
			})
		}
	}
}

// Chaos answers 404 or an empty list for a root it knows nothing about.
func TestKeyed_ChaosNothingForTheRoot(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"404":   status(404),
		"empty": jsonBody(`{"domain":"example.com","subdomains":[],"count":0}`),
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			t.Setenv("RECON_KEYS_CHAOS", chaosKey)
			w.handle("dns.projectdiscovery.io", h)
			if code := w.run("--passive", "--verbose", "example.com"); code != 0 {
				t.Fatalf("exit %d", code)
			}
			if st, _ := stateOf(w, "chaos"); st != "done" {
				t.Errorf("chaos = %s, want done", st)
			}
			if done := w.h.completed(eng, "chaos"); !slices.Equal(done, []string{"example.com|pages=10"}) {
				t.Errorf("completed = %v", done)
			}
			if warns := messages(w, "warning", "chaos"); len(warns) != 0 {
				t.Errorf("warnings = %q, want none", warns)
			}
		})
	}
}

// A body of the wrong shape is a failed check (retried), never "no names".
func TestKeyed_WrongShapeIsAnError(t *testing.T) {
	forEachKeyed(t, func(t *testing.T, w *world, s keyedSource) {
		t.Setenv(s.env, s.key)
		s.serveWith(w, `{"error":"nope"}`)
		if code := w.run("--passive", "example.com"); code != 0 {
			t.Fatalf("exit %d", code)
		}
		if st, _ := stateOf(w, s.stage); st != "failed" {
			t.Errorf("%s = %s, want failed", s.stage, st)
		}
		if done := w.h.completed(eng, s.stage); len(done) != 0 {
			t.Errorf("completed = %v: an unreadable answer must be retried", done)
		}
	})
}

// --- page caps ---

// pagedSource serves three pages of names p1..p3 for the root.
type pagedSource struct {
	stage, host, env, key, flag string
	serve                       func(w *world)
}

func pagedSources() []pagedSource {
	return []pagedSource{
		{stage: "shodan-dns", host: "api.shodan.io", env: "RECON_KEYS_SHODAN", key: shodanKey, flag: "--shodan-dns-max-pages",
			serve: func(w *world) {
				w.handle("api.shodan.io", func(rw http.ResponseWriter, r *http.Request) {
					var n int
					_, _ = fmt.Sscan(r.URL.Query().Get("page"), &n)
					fmt.Fprintf(rw, `{"domain":"example.com","subdomains":["p%d"],"data":[{"subdomain":"p%d","type":"A","value":"203.0.113.5"}],"more":%v}`, n, n, n < 3)
				})
			}},
		{stage: "censys", host: "api.platform.censys.io", env: "RECON_KEYS_CENSYS", key: censysKey, flag: "--censys-max-pages",
			serve: func(w *world) {
				w.handle("api.platform.censys.io", func(rw http.ResponseWriter, r *http.Request) {
					var req struct {
						PageToken string `json:"page_token"`
					}
					_ = json.NewDecoder(r.Body).Decode(&req)
					n := 1
					if req.PageToken != "" {
						_, _ = fmt.Sscanf(req.PageToken, "t%d", &n)
					}
					next := ""
					if n < 3 {
						next = fmt.Sprintf("t%d", n+1)
					}
					fmt.Fprintf(rw, `{"result":{"next_page_token":%q,"hits":[{"certificate_v1":{"resource":{"names":["p%d.example.com"]}}}]}}`, next, n)
				})
			}},
	}
}

// Paging stops at <stage>.max_pages with a warning when the source has more;
// the cap is part of the check, so raising it repeats the check.
func TestKeyed_PageCap(t *testing.T) {
	for _, s := range pagedSources() {
		t.Run(s.stage, func(t *testing.T) {
			w := newWorld(t)
			t.Setenv(s.env, s.key)
			s.serve(w)
			resolveAll(w, "p1", "p2", "p3")
			if code := w.run("--passive", "--no-permutations", "--verbose", s.flag, "2", "example.com"); code != 0 {
				t.Fatalf("exit %d", code)
			}
			if st, _ := stateOf(w, s.stage); st != "done" {
				t.Errorf("reaching the cap completes the check: state = %s", st)
			}
			if done := w.h.completed(eng, s.stage); !slices.Equal(done, []string{"example.com|pages=2"}) {
				t.Errorf("completed = %v", done)
			}
			var asked int
			for _, r := range w.requests(s.host) {
				if strings.Contains(r.URI, "/dns/domain/") || strings.Contains(r.URI, "/v3/global/") {
					asked++
				}
			}
			if asked != 2 {
				t.Errorf("want exactly 2 pages requested, got %d", asked)
			}
			got := w.lines(eng, "subdomains.txt")
			if !slices.Contains(got, "p2.example.com") || slices.Contains(got, "p3.example.com") {
				t.Errorf("subdomains.txt = %v, want the first two pages only", got)
			}
			if warns := messages(w, "warning", s.stage); len(warns) != 1 || !strings.Contains(warns[0], "truncated") {
				t.Errorf("want one truncation warning, got %q", warns)
			}

			if code := w.run("--passive", "--no-permutations", "--verbose", "-e", eng); code != 0 {
				t.Fatalf("exit %d", code)
			}
			if done := w.h.completed(eng, s.stage); !slices.Equal(done, []string{"example.com|pages=10", "example.com|pages=2"}) {
				t.Errorf("completed = %v, want a new check for the new cap", done)
			}
			if !slices.Contains(w.lines(eng, "subdomains.txt"), "p3.example.com") {
				t.Errorf("subdomains.txt = %v", w.lines(eng, "subdomains.txt"))
			}
			if warns := messages(w, "warning", "truncated"); len(warns) != 0 {
				t.Errorf("an untruncated result must not warn: %q", warns)
			}
		})
	}
}

// A result that ends exactly at the cap is not truncated.
func TestKeyed_PageCapNotReached(t *testing.T) {
	for _, s := range pagedSources() {
		t.Run(s.stage, func(t *testing.T) {
			w := newWorld(t)
			t.Setenv(s.env, s.key)
			s.serve(w)
			if code := w.run("--passive", "--verbose", s.flag, "3", "example.com"); code != 0 {
				t.Fatalf("exit %d", code)
			}
			if warns := messages(w, "warning", "truncated"); len(warns) != 0 {
				t.Errorf("the last page was read: %q", warns)
			}
		})
	}
}

// Chaos answers with the whole list at once, so its cap never bites, but it is
// still part of the check.
func TestKeyed_ChaosCapIsInTheCheck(t *testing.T) {
	w := newWorld(t)
	t.Setenv("RECON_KEYS_CHAOS", chaosKey)
	w.handle("dns.projectdiscovery.io", jsonBody(`{"domain":"example.com","subdomains":["a"],"count":1}`))
	if code := w.run("--passive", "--verbose", "--chaos-max-pages", "3", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if done := w.h.completed(eng, "chaos"); !slices.Equal(done, []string{"example.com|pages=3"}) {
		t.Errorf("completed = %v", done)
	}
	if warns := messages(w, "warning", "chaos"); len(warns) != 0 {
		t.Errorf("warnings = %q", warns)
	}
}

func TestKeyed_MaxPagesMustBePositive(t *testing.T) {
	for _, flag := range []string{"--shodan-dns-max-pages", "--censys-max-pages", "--chaos-max-pages"} {
		t.Run(flag, func(t *testing.T) {
			w := newWorld(t)
			if code := w.run("--passive", flag, "0", "example.com"); code != 2 {
				t.Errorf("exit %d, want 2", code)
			}
		})
	}
}

// --- Shodan's DNS records ---

const claimsBody = `{"domain":"example.com","tags":[],"subdomains":["www","dead","cdn","ghost"],"more":false,"data":[
	{"subdomain":"www","type":"A","value":"198.51.100.77"},
	{"subdomain":"www","type":"A","value":"203.0.113.6"},
	{"subdomain":"www","type":"AAAA","value":"2001:db8::1"},
	{"subdomain":"dead","type":"A","value":"198.51.100.88"},
	{"subdomain":"cdn","type":"CNAME","value":"edge.example.com."},
	{"subdomain":"ghost","type":"CNAME","value":"x.other.org"},
	{"subdomain":"","type":"MX","value":"mail.other.net"},
	{"subdomain":"","type":"NS","value":"ns1.example.net"},
	{"subdomain":"www","type":"TXT","value":"v=spf1 -all"}]}`

func resolutionSource(w *world, name, typ, value string) string {
	for _, r := range w.table(eng, "resolutions.csv") {
		if r["name"] == name && r["type"] == typ && r["value"] == value {
			return r["source"]
		}
	}
	return "<no row>"
}

func TestShodanDNS_RecordsAreShownWithTheirSource(t *testing.T) {
	w := newWorld(t)
	t.Setenv("RECON_KEYS_SHODAN", shodanKey)
	w.handle("api.shodan.io", func(rw http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/dns/domain/example.com") {
			_, _ = rw.Write([]byte(claimsBody))
			return
		}
		http.NotFound(rw, r)
	})
	w.dns.A("www.example.com", "203.0.113.6")
	w.dns.CNAME("cdn.example.com", "edge.example.com")
	w.dns.A("edge.example.com", "203.0.113.9")
	w.dns.Rcode("dead.example.com", 3) // NXDOMAIN
	for _, a := range []string{"203.0.113.6", "203.0.113.9"} {
		w.owner(a, 64500, "ACME-NET")
	}
	if code := w.run("--passive", "--no-permutations", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	want := map[[3]string]string{
		{"www.example.com", "A", "198.51.100.77"}:        "shodan",
		{"www.example.com", "A", "203.0.113.6"}:          "resolve;shodan",
		{"www.example.com", "AAAA", "2001:db8::1"}:       "shodan",
		{"dead.example.com", "A", "198.51.100.88"}:       "shodan",
		{"cdn.example.com", "CNAME", "edge.example.com"}: "resolve;shodan",
		{"example.com", "A", "203.0.113.250"}:            "resolve",
		{"edge.example.com", "A", "203.0.113.9"}:         "resolve",
		{"ghost.example.com", "CNAME", "x.other.org"}:    "shodan",
		{"example.com", "MX", "mail.other.net"}:          "shodan",
		{"example.com", "NS", "ns1.example.net"}:         "shodan",
	}
	for k, src := range want {
		if got := resolutionSource(w, k[0], k[1], k[2]); got != src {
			t.Errorf("%v: source = %q, want %q", k, got, src)
		}
	}
	for _, r := range w.table(eng, "resolutions.csv") {
		if r["type"] == "TXT" {
			t.Errorf("only A, AAAA, CNAME, MX and NS are recorded: %v", r)
		}
		if r["name"] == "www.example.com" && r["value"] == "198.51.100.77" && r["current"] != "true" {
			t.Errorf("a claim is current when seen: %v", r)
		}
	}
	// dead.example.com does not resolve, whatever Shodan says.
	if !slices.Contains(w.lines(eng, "unresolved.txt"), "dead.example.com") {
		t.Errorf("unresolved.txt = %v, want dead.example.com", w.lines(eng, "unresolved.txt"))
	}
	if !slices.Contains(w.lines(eng, "subdomains.txt"), "dead.example.com") {
		t.Errorf("subdomains.txt = %v, want the name Shodan lists", w.lines(eng, "subdomains.txt"))
	}
	// Shodan's addresses are not addresses recon found.
	for _, r := range w.table(eng, "ips.csv") {
		if r["ip"] == "198.51.100.77" || r["ip"] == "198.51.100.88" || r["ip"] == "2001:db8::1" {
			t.Errorf("ips.csv lists a Shodan-only address: %v", r)
		}
	}
	if hits := leaks(w); len(hits) > 0 {
		t.Errorf("key leaked into %v", hits)
	}
}

// In-scope targets of CNAME, MX and NS records become hostnames; the others are not
// recorded, so they are not even candidates.
func TestShodanDNS_TargetsBecomeHostnamesOnlyInScope(t *testing.T) {
	w := newWorld(t)
	t.Setenv("RECON_KEYS_SHODAN", shodanKey)
	w.handle("api.shodan.io", func(rw http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/dns/domain/example.com") {
			_, _ = rw.Write([]byte(`{"domain":"example.com","subdomains":["www"],"more":false,"data":[
				{"subdomain":"www","type":"CNAME","value":"edge.example.net"},
				{"subdomain":"www","type":"CNAME","value":"lb.other.org"},
				{"subdomain":"","type":"MX","value":"mx.example.net"},
				{"subdomain":"","type":"MX","value":"mx.other.org"},
				{"subdomain":"","type":"NS","value":"ns1.example.net"},
				{"subdomain":"","type":"NS","value":"ns1.other.org"}]}`))
			return
		}
		_, _ = rw.Write([]byte(`{"domain":"example.net","subdomains":[],"data":[],"more":false}`))
	})
	for _, n := range []string{"www.example.com", "edge.example.net", "mx.example.net", "ns1.example.net"} {
		w.dns.A(n, "203.0.113.5")
	}
	w.dns.A("example.net", "203.0.113.5")
	if code := w.run("--passive", "--no-permutations", "example.com", "example.net"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	subs := w.lines(eng, "subdomains.txt")
	for _, n := range []string{"edge.example.net", "mx.example.net", "ns1.example.net"} {
		if !slices.Contains(subs, n) {
			t.Errorf("subdomains.txt missing the in-scope target %s: %v", n, subs)
		}
	}
	recorded := w.obsAttrs(eng, "hostname")
	for _, n := range []string{"lb.other.org", "mx.other.org", "ns1.other.org"} {
		if _, ok := recorded[n]; ok {
			t.Errorf("%s is out of scope and must not be recorded as a hostname", n)
		}
	}
	if cands := w.table(eng, "candidates.csv"); find(cands, "value", "lb.other.org") != nil || find(cands, "value", "mx.other.org") != nil {
		t.Errorf("candidates.csv = %s", w.file(eng, "candidates.csv"))
	}
	// The record itself is still shown.
	if got := resolutionSource(w, "www.example.com", "CNAME", "lb.other.org"); got != "shodan" {
		t.Errorf("the out-of-scope CNAME claim: source = %q, want shodan", got)
	}
}

// A Shodan-only address decides nothing: it is never contacted, never in ips.csv,
// and its name is neither resolved nor probed because of it.
func TestShodanDNS_ClaimedAddressIsNeverContacted(t *testing.T) {
	p := newPorts(t)
	t.Setenv("RECON_KEYS_SHODAN", shodanKey)
	const ghost = "198.51.100.77"
	p.handle("api.shodan.io", func(rw http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/dns/domain/example.com") {
			_, _ = rw.Write([]byte(`{"domain":"example.com","subdomains":["live","gone"],"more":false,"data":[
				{"subdomain":"live","type":"A","value":"` + ghost + `"},
				{"subdomain":"live","type":"A","value":"203.0.113.6"},
				{"subdomain":"gone","type":"A","value":"` + ghost + `"}]}`))
			return
		}
		http.NotFound(rw, r)
	})
	p.host("live.example.com", "203.0.113.6")
	p.owner("203.0.113.6", 64500, "ACME-NET")
	p.owner(ghost, 64500, "ACME-NET")
	live := p.plain("203.0.113.6", 80, page("<title>Live</title>"))
	ports := []int{80, 443, 8080}
	canary := p.canary(ghost, ports)
	p.sweep(ports[2:])

	if n := canary.conns.Load(); n != 0 {
		t.Errorf("the Shodan-only address was dialled %d times", n)
	}
	if live.hits() == 0 {
		t.Error("the name's own address was never probed: the test proves nothing")
	}
	if got := resolutionSource(p.world, "live.example.com", "A", ghost); got != "shodan" {
		t.Errorf("the claim is not shown: source = %q", got)
	}
	for _, r := range p.table(eng, "ips.csv") {
		if r["ip"] == ghost {
			t.Errorf("ips.csv lists the Shodan-only address: %v", r)
		}
	}
	for _, k := range p.checked() {
		if strings.HasPrefix(k, ghost+":") {
			t.Errorf("port check %s was made for the Shodan-only address", k)
		}
	}
	if !slices.Contains(p.lines(eng, "unresolved.txt"), "gone.example.com") {
		t.Errorf("a name only Shodan resolves stays unresolved: %v", p.lines(eng, "unresolved.txt"))
	}
	probed := p.probed()
	if slices.Contains(probed, "gone.example.com") || !slices.Contains(probed, "live.example.com") {
		t.Errorf("probe hostnames = %v", probed)
	}
	for _, typ := range []string{"A", "AAAA", "PTR", "TXT"} {
		for _, q := range p.dns.Queried(typ) {
			if strings.Contains(q, "77.100.51.198") {
				t.Errorf("DNS asked about the Shodan-only address: %s %s", typ, q)
			}
		}
	}
}

// --- registry, help and README ---

func TestKeyed_RegistryOrderAndHelp(t *testing.T) {
	var names []string
	for _, s := range defaultStageList() {
		names = append(names, s.Name())
	}
	idx := func(n string) int { return slices.Index(names, n) }
	if !(idx("certspotter") < idx("censys") && idx("censys") < idx("chaos") && idx("chaos") < idx("shodan") &&
		idx("shodan") < idx("shodan-dns") && idx("shodan-dns") < idx("resolve")) || idx("censys") < 0 {
		t.Errorf("stage order = %v", names)
	}
	h := newHarness(t, defaultStageList()...)
	if code := h.exec("--help"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	out := h.stdout.String()
	for _, want := range []string{"shodan-dns", "censys", "chaos", "--shodan-dns-max-pages", "--censys-max-pages", "--chaos-max-pages"} {
		if !strings.Contains(out, want) {
			t.Errorf("help missing %q", want)
		}
	}
}

func TestKeyed_ReadmeNamesTheSources(t *testing.T) {
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(b)
	keyed := keyedSourcesBullet(readme)
	for _, want := range []string{"censys", "chaos", "shodan-dns", "query credit"} {
		if !strings.Contains(keyed, want) {
			t.Errorf("the keyed-sources entry does not mention %q: %q", want, keyed)
		}
	}
	if !strings.Contains(readme, "source") || !strings.Contains(readme, "resolve;shodan") {
		t.Error("README does not describe the source column of resolutions.csv")
	}
}
