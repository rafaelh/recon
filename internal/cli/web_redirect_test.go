package cli_test

import (
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// --- B4: redirects ---

func TestWebB4_InScopeRedirectChain(t *testing.T) {
	x := newWeb(t)
	x.names("a.example.com")
	x.host("a.example.com", "203.0.113.5")
	s80 := x.plain("203.0.113.5", 80, redirectTo(301, "https://a.example.com/login"))
	s443 := x.secure("203.0.113.5", 443, selfSigned(t, leafSpec{cn: "a.example.com", dns: []string{"a.example.com"}}),
		routes(map[string]http.HandlerFunc{
			"/": page("<title>Home</title>"),
			"/login": func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Server", "Caddy")
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte("<title>Login</title>"))
			},
		}))
	x.mustRun("--crawl-pages", "0")

	r := x.service("http://a.example.com")
	for k, v := range map[string]string{
		"status": "301", "redirect": "https://a.example.com/login",
		"title": "Login", "server": "Caddy", "final_url": "https://a.example.com/login",
		"tls_subject": "", "tls_sans": "", "tls_issuer": "", "tls_expiry": "", "tls_error": "", "tls_self_signed": "",
	} {
		if r[k] != v {
			t.Errorf("http service %s = %q, want %q (status and redirect come from hop 1; title, server and final_url from the last page)", k, r[k], v)
		}
	}
	if https := x.service("https://a.example.com"); https["title"] != "Home" || https["tls_subject"] == "" {
		t.Errorf("https service: %v", https)
	}
	if s80.hits() != 1 || s443.count("/login") < 1 {
		t.Errorf("hits: :80=%d /login=%d", s80.hits(), s443.count("/login"))
	}
	if u := find(x.urls(), "url", "https://a.example.com/login"); u == nil || !strings.Contains(u["found_by"], "httpprobe") || u["status"] != "200" {
		t.Errorf("the redirect target must be recorded as a url with the status it returned (D15): %v", x.urls())
	}
	if got := x.observedBy("hostname", "httpprobe"); len(got) != 0 {
		t.Errorf("a redirect to the probed host itself recorded hostnames %v", got)
	}
}

func TestWebB4_OutOfScopeRedirectIsACandidateAndNotRequested(t *testing.T) {
	x := newWeb(t)
	x.names("a.example.com")
	x.host("a.example.com", "203.0.113.5")
	x.plain("203.0.113.5", 80, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Location", "http://evil.example.net/x")
		w.WriteHeader(302)
		_, _ = w.Write([]byte("<title>Moved</title>"))
	})
	evil := x.plain("203.0.113.99", 80, page("<title>evil</title>"))
	x.dns.A("evil.example.net", "203.0.113.99")
	x.mustRun("--crawl-pages", "0")

	if evil.hits() != 0 {
		t.Errorf("an out-of-scope redirect target was requested %d times", evil.hits())
	}
	c := find(x.table(eng, "candidates.csv"), "value", "evil.example.net")
	if c == nil || c["type"] != "hostname" || !strings.Contains(c["found_by"], "httpprobe") {
		t.Errorf("candidates.csv = %s", x.file(eng, "candidates.csv"))
	}
	r := x.service("http://a.example.com")
	if r["status"] != "302" || r["redirect"] != "http://evil.example.net/x" || r["title"] != "Moved" || r["final_url"] != "http://a.example.com/" {
		t.Errorf("a stopped chain keeps the last page reached: %v", r)
	}
	for _, u := range x.urlSet() {
		if strings.Contains(u, "evil.example.net") {
			t.Errorf("urls.csv lists an out-of-scope url %s", u)
		}
	}
}

func TestWebB4_ExcludedRedirectTargetIsNotRequested(t *testing.T) {
	x := newWeb(t)
	x.names("a.example.com", "blocked.example.com")
	x.host("a.example.com", "203.0.113.5")
	x.host("blocked.example.com", "203.0.113.31")
	x.plain("203.0.113.5", 80, redirectTo(302, "http://blocked.example.com/"))
	blocked := x.plain("203.0.113.31", 80, page("blocked"))
	x.mustRun("--crawl-pages", "0", "-x", "blocked.example.com")

	if blocked.hits() != 0 {
		t.Errorf("an excluded host was requested %d times", blocked.hits())
	}
	if find(x.table(eng, "candidates.csv"), "value", "blocked.example.com") != nil {
		t.Error("an excluded host is not a candidate")
	}
	if find(x.table(eng, "excluded.csv"), "value", "blocked.example.com") == nil {
		t.Errorf("excluded.csv = %s", x.file(eng, "excluded.csv"))
	}
}

func TestWebB4_LoopAndHopCapTerminate(t *testing.T) {
	x := newWeb(t)
	x.names("loop.example.com", "deep.example.com")
	x.host("loop.example.com", "203.0.113.5")
	x.host("deep.example.com", "203.0.113.6")
	loop := x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/": redirectTo(302, "/a"), "/a": redirectTo(302, "/b"), "/b": redirectTo(302, "/a"),
	}))
	deep := x.plain("203.0.113.6", 80, func(w http.ResponseWriter, r *http.Request) {
		var n int
		if _, err := fmt.Sscanf(r.URL.Path, "/n/%d", &n); err != nil {
			n = 0
		}
		w.Header().Set("Location", fmt.Sprintf("/n/%d", n+1))
		w.WriteHeader(302)
	})
	x.mustRun("--crawl-pages", "0")

	if loop.hits() != 3 || loop.count("/a") != 1 || loop.count("/b") != 1 {
		t.Errorf("a loop must stop at the first revisit: %+v", loop.requests())
	}
	if deep.hits() != 11 {
		t.Errorf("the hop cap is 10: the first request plus 10 hops = 11 requests, got %d", deep.hits())
	}
	if r := x.service("http://deep.example.com"); r["final_url"] != "http://deep.example.com/n/10" || r["status"] != "302" {
		t.Errorf("deep: %v", r)
	}
	if st, _ := stateOf(x.world, "httpprobe"); st != "done" {
		t.Errorf("httpprobe = %s", st)
	}
	if u := find(x.urls(), "url", "http://loop.example.com/a"); u == nil || u["status"] != "302" {
		t.Errorf("a followed hop records its status: %v", u)
	}
	for _, k := range []string{"loop.example.com:80", "deep.example.com:80"} {
		if !contains(x.completedKeys("httpprobe"), k) {
			t.Errorf("check %s did not complete", k)
		}
	}
}

func TestWebB4_RedirectToSelfOrAnIPAddsNoHostname(t *testing.T) {
	x := newWeb(t)
	x.names("a.example.com", "b.example.com")
	x.host("a.example.com", "203.0.113.5")
	x.host("b.example.com", "203.0.113.6")
	x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{"/": redirectTo(302, "http://a.example.com/home"), "/home": page("home")}))
	ipTarget := x.plain("203.0.113.9", 80, page("ip"))
	x.plain("203.0.113.6", 80, redirectTo(302, "http://203.0.113.9/"))
	x.mustRun("--crawl-pages", "0")

	if got := x.observedBy("hostname", "httpprobe"); len(got) != 0 {
		t.Errorf("httpprobe observed hostnames %v for self and IP redirects", got)
	}
	for _, r := range x.table(eng, "candidates.csv") {
		if _, err := netip.ParseAddr(r["value"]); err == nil {
			t.Errorf("an IP literal became a candidate: %v", r)
		}
	}
	if ipTarget.hits() != 0 {
		t.Error("an out-of-scope IP redirect target was requested")
	}
}

// A name that only the permutation stage found must never become a seed
// because its own service redirects to itself or lists itself in a SAN
// (Spec 2 D14 via the stages that observed it; Spec 3 D11, D12).
func TestWebB4B5_PermutationOnlyNameIsNeverSeededByItsOwnService(t *testing.T) {
	x := newWeb(t)
	x.perms = true
	wl := writeFile(t, t.TempDir(), "words.txt", "dev\n")
	x.names("api.example.com")
	x.host("api.example.com", "203.0.113.5")
	x.host("api-dev.example.com", "203.0.113.6") // a permutation that exists
	s := x.secure("203.0.113.6", 443,
		selfSigned(t, leafSpec{cn: "api-dev.example.com", dns: []string{"api-dev.example.com", "*.api-dev.example.com"}}),
		redirectTo(302, "https://api-dev.example.com/home"))
	x.mustRun("--wordlist", wl)

	if s.hits() == 0 {
		t.Fatal("the permutation-only name was never probed")
	}
	if len(queriedPrefix(x.world, "api-")) == 0 {
		t.Fatal("precondition: api must be permuted")
	}
	if bad := queriedPrefix(x.world, "api-dev-"); len(bad) > 0 {
		t.Errorf("api-dev became a seed through its own redirect or SAN: %v", bad)
	}
	if got := x.observedBy("hostname", "httpprobe"); slices.Contains(got, "api-dev.example.com") {
		t.Errorf("httpprobe re-observed the probed host: %v", got)
	}
}

// --- B5: certificate SANs ---

func TestWebB5_SANsFlowThroughOrBecomeCandidates(t *testing.T) {
	x := newWeb(t)
	x.names("a.example.com")
	x.host("a.example.com", "203.0.113.5")
	x.host("new.example.com", "203.0.113.6")
	cert := selfSigned(t, leafSpec{
		cn:  "a.example.com",
		dns: []string{"a.example.com", "new.example.com", "*.x.example.com", "other.example.org", "*.sub.example.org"},
		ips: []string{"192.0.2.1"},
	})
	x.secure("203.0.113.5", 443, cert, page("<title>A</title>"))
	x.plain("203.0.113.6", 80, page("<title>New</title>"))
	x.mustRun("--crawl-pages", "0")

	// An in-scope SAN is resolved and probed in the same run.
	if r := x.service("http://new.example.com"); r["title"] != "New" {
		t.Errorf("new.example.com was not probed: %v", x.serviceURLs())
	}
	if hosts := x.lines(eng, "subdomains.txt"); !slices.Contains(hosts, "new.example.com") || !slices.Contains(hosts, "x.example.com") {
		t.Errorf("subdomains.txt = %v: want new.example.com and the base of *.x.example.com", hosts)
	}
	cands := x.table(eng, "candidates.csv")
	for _, n := range []string{"other.example.org", "sub.example.org"} {
		if r := find(cands, "value", n); r == nil || !strings.Contains(r["found_by"], "httpprobe") {
			t.Errorf("%s should be a candidate found by httpprobe: %s", n, x.file(eng, "candidates.csv"))
		}
	}
	for _, r := range cands {
		if strings.Contains(r["value"], "*") {
			t.Errorf("a wildcard SAN was recorded as is: %v", r)
		}
		if _, err := netip.ParseAddr(r["value"]); err == nil {
			t.Errorf("an IP SAN became a candidate: %v", r)
		}
	}
	// The probed host's own SAN adds nothing; IP SANs stay in tls_sans.
	want := []string{"new.example.com", "other.example.org", "sub.example.org", "x.example.com"}
	got := x.observedBy("hostname", "httpprobe")
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("httpprobe hostnames = %v, want %v", got, want)
	}
	if r := x.service("https://a.example.com"); !strings.HasSuffix(r["tls_sans"], ";192.0.2.1") {
		t.Errorf("tls_sans = %q", r["tls_sans"])
	}
}
