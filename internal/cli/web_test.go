package cli_test

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"
)

// Spec 3: web services and URLs. The tests drive cli.Execute with the real
// stage list and fake servers behind egress's DialMap; request counters on every
// server assert what was and was not contacted.

func (x *web) wantServices(want ...string) {
	x.t.Helper()
	slices.Sort(want)
	if got := x.serviceURLs(); !slices.Equal(got, want) {
		x.t.Errorf("web services = %v, want %v", got, want)
	}
}

func (x *web) mustRun(args ...string) {
	x.t.Helper()
	if code := x.run(args...); code != 0 {
		x.t.Fatalf("exit %d\n%s", code, x.h.stdout.String())
	}
}

func (x *web) completedKeys(stage string) []string { return x.h.completed(eng, stage) }

// --- B1: which hostnames and ports are probed ---

func TestWebB1_HostnamesProbedOn80And443(t *testing.T) {
	x := newWeb(t)
	x.names("a.example.com", "b.example.com", "c.example.com")
	x.host("a.example.com", "203.0.113.5")
	x.host("b.example.com", "203.0.113.6")
	x.host("c.example.com", "203.0.113.7") // nothing listens on c
	a80 := x.plain("203.0.113.5", 80, page("<title>A</title>"))
	b443 := x.secure("203.0.113.6", 443, selfSigned(t, leafSpec{cn: "b.example.com", dns: []string{"b.example.com"}}), page("<title>B</title>"))
	x.mustRun("--crawl-pages", "0") // the crawl would add a GET of its own

	x.wantServices("http://a.example.com", "https://b.example.com")
	if r := a80.requests(); len(r) == 0 || r[0].Method != "GET" || r[0].URI != "/" || r[0].Host != "a.example.com" {
		t.Errorf("a:80 requests = %+v", r)
	}
	if !b443.requests()[0].TLS {
		t.Error("b:443 was not probed over TLS")
	}
	// A closed port is a completed check with no record.
	keys := x.completedKeys("httpprobe")
	for _, k := range []string{"a.example.com:80", "a.example.com:443", "c.example.com:80", "c.example.com:443", "b.example.com:80"} {
		if !contains(keys, k) {
			t.Errorf("check %s not completed: %v", k, keys)
		}
	}
	if st, _ := stateOf(x.world, "httpprobe"); st != "done" {
		t.Errorf("httpprobe = %s, want done (closed ports are not failures)", st)
	}
	// Only the conventional scheme per standard port.
	if a80.hits() != 1 {
		t.Errorf("a:80 saw %d requests, want 1 (http only on port 80)", a80.hits())
	}
}

func TestWebB1_WildcardSharedAndExcluded(t *testing.T) {
	x := newWeb(t)
	x.names("wild1.w.example.com", "wild2.w.example.com", "hk.example.com", "ex.example.com")
	x.dns.Wildcard("w.example.com", "203.0.113.20")
	x.ips["203.0.113.20"] = true
	x.dns.CNAME("hk.example.com", "x.herokudns.com") // shared provider infrastructure
	x.dns.A("x.herokudns.com", "203.0.113.9")
	x.ips["203.0.113.9"] = true
	x.host("ex.example.com", "203.0.113.30")
	wild := x.plain("203.0.113.20", 80, page("wild"))
	hk := x.plain("203.0.113.9", 80, page("heroku"))
	ex := x.plain("203.0.113.30", 80, page("excluded"))
	x.mustRun("-x", "ex.example.com")

	if got := x.providerHosts(); !slices.Contains(got, "hk.example.com|heroku") {
		t.Fatalf("precondition: hk must be on shared infrastructure: %v", got)
	}
	if got := wild.hostHeaders(); !slices.Equal(got, []string{"wild1.w.example.com"}) {
		t.Errorf("wildcard zone probed as %v, want only its representative", got)
	}
	if got := hk.hostHeaders(); !slices.Equal(got, []string{"hk.example.com"}) {
		t.Errorf("shared-infrastructure host probed as %v, want hk.example.com", got)
	}
	if ex.hits() != 0 {
		t.Errorf("an excluded host was requested %d times", ex.hits())
	}
	x.wantServices("http://hk.example.com", "http://wild1.w.example.com")
}

func TestWebB1_NonStandardPortDetectedOnce(t *testing.T) {
	x := newWeb(t)
	x.names("a.example.com", "b.example.com", "c.example.com")
	for _, n := range []string{"a", "b", "c"} {
		x.host(n+".example.com", "203.0.113.5")
	}
	s := x.plain("203.0.113.5", 8080, page("<title>app</title>"))
	x.open("203.0.113.5:8080", "")
	x.mustRun("--crawl-pages", "0")

	x.wantServices("http://a.example.com:8080", "http://b.example.com:8080", "http://c.example.com:8080")
	if got := s.hostHeaders(); !slices.Equal(got, []string{"a.example.com:8080", "b.example.com:8080", "c.example.com:8080"}) {
		t.Errorf("Host headers = %v", got)
	}
	if s.hits() != 3 {
		t.Errorf("port 8080 saw %d requests, want 3: detection once via a, then b and c (no duplicates)", s.hits())
	}
	keys := x.completedKeys("httpprobe")
	if !contains(keys, "port|203.0.113.5:8080") {
		t.Errorf("detection check missing: %v", keys)
	}
	// Ports 80 and 443 are D2's, never the detection check's.
	for _, k := range keys {
		if strings.HasPrefix(k, "port|") && (strings.HasSuffix(k, ":80") || strings.HasSuffix(k, ":443")) {
			t.Errorf("detection check %s on a standard port", k)
		}
	}
	x.wantRecordCount("http_port", 1)
}

func TestWebB1_DetectionTestsItsOwnAddress(t *testing.T) {
	x := newWeb(t)
	x.names("a.example.com", "b.example.com", "c.example.com")
	x.host("a.example.com", "203.0.113.5")
	x.host("b.example.com", "203.0.113.5", "203.0.113.6") // b is dialled at .5 first
	x.host("c.example.com", "203.0.113.6")
	s5 := x.plain("203.0.113.5", 8080, page("app"))
	s6 := x.silent("203.0.113.6", 8080) // open, but not HTTP
	x.open("203.0.113.5:8080", "")
	x.open("203.0.113.6:8080", "")
	x.mustRun("--crawl-pages", "0")

	// port|203.0.113.6:8080 has representative b; it must test .6, not b's first address.
	if got := x.obsAttrs(eng, "http_port"); len(got) != 1 || got["203.0.113.5:8080"] == "" {
		t.Errorf("http_port = %v, want only 203.0.113.5:8080", got)
	}
	if s6.conns.Load() == 0 {
		t.Error("the detection check of 203.0.113.6:8080 never reached that address")
	}
	// a detects .5; b is .5's vhost (D5); c, only on .6, is never probed.
	x.wantServices("http://a.example.com:8080", "http://b.example.com:8080")
	if got := s5.hostHeaders(); !slices.Equal(got, []string{"a.example.com:8080", "b.example.com:8080"}) {
		t.Errorf("Host headers at .5 = %v", got)
	}
}

func TestWebB1_NameOnTwoAddressesIsDetectedOnce(t *testing.T) {
	x := newWeb(t)
	x.names("a.example.com")
	x.host("a.example.com", "203.0.113.5", "203.0.113.6")
	s5 := x.plain("203.0.113.5", 8080, page("app"))
	s6 := x.plain("203.0.113.6", 8080, page("app"))
	x.open("203.0.113.5:8080", "")
	x.open("203.0.113.6:8080", "")
	x.mustRun("--crawl-pages", "0")

	keys := x.completedKeys("httpprobe")
	if !contains(keys, "port|203.0.113.5:8080") || contains(keys, "port|203.0.113.6:8080") {
		t.Errorf("detection checks = %v, want one, on the first address", keys)
	}
	if n := s5.hits() + s6.hits(); n != 1 {
		t.Errorf("a.example.com:8080 was requested %d times, want 1", n)
	}
	x.wantServices("http://a.example.com:8080")
}

func (x *web) wantRecordCount(kind string, n int) {
	x.t.Helper()
	if got := x.obsAttrs(eng, kind); len(got) != n {
		x.t.Errorf("%d %s records, want %d: %v", len(got), kind, n, got)
	}
}

func TestWebB1_SchemeDetectionAndFallback(t *testing.T) {
	for _, mode := range []string{"reset", "hang"} {
		t.Run("plain server that "+mode+"s a ClientHello", func(t *testing.T) {
			x := newWeb(t)
			x.names("a.example.com")
			x.host("a.example.com", "203.0.113.5")
			s := x.fussy("203.0.113.5", 8080, mode, page("<title>plain</title>"))
			x.open("203.0.113.5:8080", "")
			x.mustRun()
			x.wantServices("http://a.example.com:8080")
			if s.hellos.Load() == 0 {
				t.Error("https must be tried first on a non-standard port")
			}
			if row := x.service("http://a.example.com:8080"); row["title"] != "plain" || row["status"] != "200" {
				t.Errorf("row = %v", row)
			}
		})
	}
	t.Run("https wins when the port speaks TLS", func(t *testing.T) {
		x := newWeb(t)
		x.names("a.example.com")
		x.host("a.example.com", "203.0.113.5")
		s := x.secure("203.0.113.5", 8443, selfSigned(t, leafSpec{cn: "a.example.com", dns: []string{"a.example.com"}}), page("<title>tls</title>"))
		x.open("203.0.113.5:8443", "")
		x.mustRun("--crawl-pages", "0")
		x.wantServices("https://a.example.com:8443")
		if s.hits() != 1 || !s.requests()[0].TLS {
			t.Errorf("requests = %+v", s.requests())
		}
	})
	t.Run("a closed open_port records nothing", func(t *testing.T) {
		x := newWeb(t)
		x.names("a.example.com")
		x.host("a.example.com", "203.0.113.5")
		x.open("203.0.113.5:8080", "") // nothing serves 8080
		x.mustRun()
		x.wantServices()
		if !contains(x.completedKeys("httpprobe"), "port|203.0.113.5:8080") {
			t.Error("the detection check must complete")
		}
	})
}

func TestWebB1_BannerAndNonHTTPPortsGetNoVhostRequests(t *testing.T) {
	x := newWeb(t)
	x.names("a.example.com", "b.example.com", "c.example.com")
	for _, n := range []string{"a", "b", "c"} {
		x.host(n+".example.com", "203.0.113.5")
	}
	withBanner := x.plain("203.0.113.5", 9999, page("would answer HTTP"))
	x.open("203.0.113.5:9999", "SSH-2.0-OpenSSH_9.6")
	notHTTP := x.silent("203.0.113.5", 9100)
	x.open("203.0.113.5:9100", "")
	x.mustRun()

	x.wantServices()
	if withBanner.hits() != 0 {
		t.Errorf("a port with a banner was probed %d times", withBanner.hits())
	}
	if contains(x.completedKeys("httpprobe"), "port|203.0.113.5:9999") {
		t.Error("a port with a banner must not get a detection check")
	}
	if n := notHTTP.conns.Load(); n < 1 || n > 2 {
		t.Errorf("non-HTTP port saw %d connections, want only the representative's https and http tries", n)
	}
	for _, k := range x.completedKeys("httpprobe") {
		if k == "b.example.com:9100" || k == "c.example.com:9100" {
			t.Errorf("vhost check %s on a port that does not speak HTTP", k)
		}
	}
	x.wantRecordCount("http_port", 0)
}

// --- B2: services by IP ---

func TestWebB2_IPLiteralService(t *testing.T) {
	x := newWeb(t)
	v4 := x.plain("198.51.100.7", 8080, page("<title>v4</title>"))
	v6 := x.plain("2001:db8:1::5", 80, page("<title>v6</title>"))
	tlsIP := x.secure("198.51.100.7", 8443, selfSigned(t, leafSpec{cn: "198.51.100.7", ips: []string{"198.51.100.7"}}), page("<title>tls</title>"))
	x.open("198.51.100.7:8080", "")
	x.open("[2001:db8:1::5]:80", "")
	x.open("198.51.100.7:8443", "")
	x.mustRun("--crawl-pages", "0", "--cidr", "198.51.100.0/24", "--cidr", "2001:db8:1::/64")

	x.wantServices("http://198.51.100.7:8080", "http://[2001:db8:1::5]", "https://198.51.100.7:8443")
	if got := v4.hostHeaders(); !slices.Equal(got, []string{"198.51.100.7:8080"}) {
		t.Errorf("v4 Host header = %v", got)
	}
	if got := v6.hostHeaders(); !slices.Equal(got, []string{"[2001:db8:1::5]"}) {
		t.Errorf("v6 Host header = %v, want the bracketed literal without a port", got)
	}
	if got := tlsIP.sniSeen(); !slices.Equal(got, []string{""}) {
		t.Errorf("SNI sent to an IP literal: %q, want none", got)
	}
	if r := x.service("http://[2001:db8:1::5]"); r["host"] != "2001:db8:1::5" || r["port"] != "80" || r["scheme"] != "http" || r["title"] != "v6" {
		t.Errorf("v6 row = %v", r)
	}
	if r := x.service("https://198.51.100.7:8443"); r["host"] != "198.51.100.7" || r["tls_sans"] != "198.51.100.7" {
		t.Errorf("tls row = %v", r)
	}
	keys := x.completedKeys("httpprobe")
	for _, k := range []string{"port|198.51.100.7:8080", "port|[2001:db8:1::5]:80"} {
		if !contains(keys, k) {
			t.Errorf("check %s missing: %v", k, keys)
		}
	}
}

func TestWebB2_ANameWinsOverTheIP(t *testing.T) {
	x := newWeb(t)
	x.names("a.example.com")
	x.host("a.example.com", "198.51.100.7")
	s := x.plain("198.51.100.7", 8080, page("<title>named</title>"))
	x.open("198.51.100.7:8080", "")
	x.mustRun("--cidr", "198.51.100.0/24")

	x.wantServices("http://a.example.com:8080")
	if got := s.hostHeaders(); !slices.Equal(got, []string{"a.example.com:8080"}) {
		t.Errorf("an in-scope IP with a hostname must be probed by name only: %v", got)
	}
}

func TestWebB2_OutOfScopeAndExcludedIPsAreNotProbed(t *testing.T) {
	x := newWeb(t)
	outside := x.plain("192.0.2.9", 8080, page("outside"))
	excluded := x.plain("198.51.100.200", 8080, page("excluded"))
	x.open("192.0.2.9:8080", "")
	x.open("198.51.100.200:8080", "")
	x.mustRun("--cidr", "198.51.100.0/24", "-x", "198.51.100.128/25")

	x.wantServices()
	if outside.hits() != 0 || excluded.hits() != 0 {
		t.Errorf("out-of-scope IP got %d requests, excluded IP got %d", outside.hits(), excluded.hits())
	}
}

// --- B3: what is recorded for a live service ---

func TestWebB3_AllAttributes(t *testing.T) {
	x := newWeb(t)
	x.names("a.example.com")
	x.host("a.example.com", "203.0.113.5")
	ca := newCA(t, "Test Root CA")
	cert := ca.issue(t, leafSpec{cn: "a.example.com", dns: []string{"a.example.com"}, ips: []string{"192.0.2.1"}})
	x.secure("203.0.113.5", 443, cert, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "abc"})
		fmt.Fprint(w, `<html><head><title>  Welcome </title><meta name="generator" content="WordPress 6.4"></head><body>hi</body></html>`)
	})
	x.mustRun()

	r := x.service("https://a.example.com")
	want := map[string]string{
		"host": "a.example.com", "port": "443", "scheme": "https", "status": "200", "title": "Welcome",
		"server": "nginx/1.25.3", "redirect": "", "final_url": "https://a.example.com/",
		"tls_sans": "a.example.com;192.0.2.1", "tls_expiry": "2037-06-01", "tls_self_signed": "false", "current": "true",
		"first_seen": "2026-11-01", "last_seen": "2026-11-01",
	}
	for k, v := range want {
		if r[k] != v {
			t.Errorf("%s = %q, want %q", k, r[k], v)
		}
	}
	if !strings.Contains(r["tls_subject"], "a.example.com") || !strings.Contains(r["tls_issuer"], "Test Root CA") {
		t.Errorf("subject %q, issuer %q", r["tls_subject"], r["tls_issuer"])
	}
	if !strings.Contains(r["tls_error"], "unknown authority") {
		t.Errorf("tls_error = %q: an untrusted issuer must be recorded, not hidden", r["tls_error"])
	}
	tech := strings.Split(r["technologies"], ";")
	if !slices.IsSorted(tech) {
		t.Errorf("technologies must be sorted: %v", tech)
	}
	for _, want := range []string{"Nginx", "PHP", "WordPress"} { // a header, a cookie and a meta generator
		if !slices.ContainsFunc(tech, func(s string) bool { return strings.HasPrefix(s, want) }) {
			t.Errorf("technologies %v missing %s", tech, want)
		}
	}
}

func TestWebB3_ExpiredAndSelfSignedCertificatesAreRecorded(t *testing.T) {
	x := newWeb(t)
	x.names("exp.example.com", "self.example.com", "selfca.example.com")
	ca := newCA(t, "Test Root CA")
	for i, c := range []struct {
		name string
		cert func() (c leafSpec, self bool)
	}{
		{"exp", func() (leafSpec, bool) {
			return leafSpec{cn: "exp.example.com", dns: []string{"exp.example.com"}, notAfter: longAgo}, false
		}},
		{"self", func() (leafSpec, bool) {
			return leafSpec{cn: "self.example.com", dns: []string{"self.example.com"}}, true
		}},
		{"selfca", func() (leafSpec, bool) {
			return leafSpec{cn: "selfca.example.com", dns: []string{"selfca.example.com"}, isCA: true}, true
		}},
	} {
		ip := fmt.Sprintf("203.0.113.%d", 10+i)
		x.host(c.name+".example.com", ip)
		spec, self := c.cert()
		cert := ca.issue(t, spec)
		if self {
			cert = selfSigned(t, spec)
		}
		x.secure(ip, 443, cert, page("<title>"+c.name+"</title>"))
	}
	x.mustRun()

	exp := x.service("https://exp.example.com")
	if exp["status"] != "200" || !strings.Contains(exp["tls_error"], "expired") || exp["tls_self_signed"] != "false" || exp["tls_expiry"] != "2021-01-01" {
		t.Errorf("expired: %v", exp)
	}
	for _, n := range []string{"self", "selfca"} {
		r := x.service("https://" + n + ".example.com")
		if r["status"] != "200" || r["tls_error"] == "" || r["tls_self_signed"] != "true" || r["title"] != n {
			t.Errorf("%s: %v", n, r)
		}
	}
	if st, _ := stateOf(x.world, "httpprobe"); st != "done" {
		t.Errorf("httpprobe = %s: a bad certificate must not stop the probe", st)
	}
}

func TestWebB3_TitleIsTrimmedAndCapped(t *testing.T) {
	x := newWeb(t)
	cases := map[string]struct{ ctype, body string }{
		"t1": {"text/html", "<html><head><title>\n  Hello \t World  </title><title>second</title></head></html>"},
		"t2": {"text/html", "<title>" + strings.Repeat("é", 300) + "</title>"},
		"t3": {"text/html", "<title>bad\xff\xfename</title>"},
		"t4": {"text/plain", "<title>not html</title>"},
		"t5": {"application/json", `{"title":"<title>no</title>"}`},
	}
	var names []string
	i := 0
	for n, c := range cases {
		host := n + ".example.com"
		names = append(names, host)
		ip := fmt.Sprintf("203.0.113.%d", 40+i)
		i++
		x.host(host, ip)
		c := c
		x.plain(ip, 80, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", c.ctype)
			w.Write([]byte(c.body))
		})
	}
	x.names(names...)
	x.mustRun()

	title := func(n string) string { return x.service("http://" + n + ".example.com")["title"] }
	if got := title("t1"); got != "Hello World" {
		t.Errorf("whitespace: %q", got)
	}
	if got := title("t2"); utf8.RuneCountInString(got) != 200 {
		t.Errorf("cap: %d runes, want 200", utf8.RuneCountInString(got))
	}
	if got := title("t3"); !utf8.ValidString(got) || !strings.Contains(got, "bad") || !strings.Contains(got, "name") {
		t.Errorf("invalid UTF-8: %q", got)
	}
	for _, n := range []string{"t4", "t5"} {
		if got := title(n); got != "" {
			t.Errorf("%s: a non-HTML body has no title, got %q", n, got)
		}
	}
}

func TestWebB3_AnyStatusIsALiveService(t *testing.T) {
	x := newWeb(t)
	x.names("gone.example.com", "broken.example.com")
	x.host("gone.example.com", "203.0.113.5")
	x.host("broken.example.com", "203.0.113.6")
	x.plain("203.0.113.5", 80, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(404)
		w.Write([]byte("<title>Not Found</title>"))
	})
	x.plain("203.0.113.6", 80, func(w http.ResponseWriter, r *http.Request) { http.Error(w, "boom", 500) })
	x.mustRun()
	if r := x.service("http://gone.example.com"); r["status"] != "404" || r["title"] != "Not Found" {
		t.Errorf("404: %v", r)
	}
	if r := x.service("http://broken.example.com"); r["status"] != "500" {
		t.Errorf("500: %v", r)
	}
}

func TestWebB3_RedoHTTPProbeRefreshesTheService(t *testing.T) {
	x := newWeb(t)
	x.names("a.example.com")
	x.host("a.example.com", "203.0.113.5")
	var title atomic.Value
	title.Store("Old")
	s := x.plain("203.0.113.5", 80, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<title>%s</title>", title.Load())
	})
	x.mustRun("--crawl-pages", "0")
	if got := x.service("http://a.example.com")["title"]; got != "Old" {
		t.Fatalf("title = %q", got)
	}
	title.Store("New")
	before := s.hits()
	x.mustRun("--crawl-pages", "0")
	if s.hits() != before || x.service("http://a.example.com")["title"] != "Old" {
		t.Error("a service is not re-probed without --redo")
	}
	x.mustRun("--crawl-pages", "0", "--redo", "httpprobe")
	if s.hits() == before {
		t.Error("--redo httpprobe sent no requests")
	}
	if got := x.service("http://a.example.com")["title"]; got != "New" {
		t.Errorf("title after redo = %q", got)
	}
}
