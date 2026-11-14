package cli_test

import (
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

// Web posture: what the probe's own responses say about HSTS, cookie flags,
// directory listings and version banners. Nothing is requested beyond the probe.

const listingPage = `<html><head><title>Index of /</title></head><body><h1>Index of /</h1><pre></pre></body></html>`

// posturePage serves a page after setting each header; a "Set-Cookie" value
// may repeat by separating the cookies with a newline.
func posturePage(body string, header map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for k, v := range header {
			for _, line := range strings.Split(v, "\n") {
				w.Header().Add(k, line)
			}
		}
		page(body)(w, r)
	}
}

func (x *web) postureRows() []map[string]string { return x.table(eng, "risk-web-posture.csv") }

// postureTypes are the "type=url" of the current posture findings, sorted.
func (x *web) postureTypes() []string {
	var out []string
	for _, r := range x.postureRows() {
		if r["current"] == "true" {
			out = append(out, r["type"]+"="+r["url"])
		}
	}
	slices.Sort(out)
	return out
}

func TestWebPosture_ColumnsAndFindingsFromLoopbackServices(t *testing.T) {
	x := newWeb(t)
	x.names("bad.example.com", "plain.example.com", "good.example.com")
	x.host("bad.example.com", "203.0.113.5")
	x.host("plain.example.com", "203.0.113.6")
	x.host("good.example.com", "203.0.113.7")
	cert := func(h string) leafSpec { return leafSpec{cn: h, dns: []string{h}} }
	bad := x.secure("203.0.113.5", 443, selfSigned(t, cert("bad.example.com")), posturePage(listingPage, map[string]string{
		"Server":       "Apache/2.4.41 (Ubuntu)",
		"X-Powered-By": "PHP/8.2.1",
		"Set-Cookie":   "sid=TOPSECRET\ngood=1; Secure; HttpOnly\njsonly=2; Secure",
	}))
	plain := x.plain("203.0.113.6", 80, posturePage("<title>Plain</title>", map[string]string{
		"Server": "nginx", "X-Powered-By": "ASP.NET",
		"Set-Cookie": "c=1\nd=2; HttpOnly",
	}))
	good := x.secure("203.0.113.7", 443, selfSigned(t, cert("good.example.com")), posturePage("<title>Good</title>", map[string]string{
		"Strict-Transport-Security": "max-age=31536000", "Server": "nginx",
		"Set-Cookie": "sid=1; Secure; HttpOnly",
	}))
	x.mustRun("--crawl-pages", "0")

	// web-services.csv gains the posture columns.
	b := x.service("https://bad.example.com")
	if b["hsts"] != "no" || b["directory_listing"] != "yes" || b["version_disclosure"] != "Apache/2.4.41 (Ubuntu);PHP/8.2.1" ||
		b["insecure_cookies"] != "jsonly(httponly);sid(secure)(httponly)" {
		t.Errorf("bad = %v", b)
	}
	if p := x.service("http://plain.example.com"); p["hsts"] != "" || p["directory_listing"] != "no" || p["version_disclosure"] != "" ||
		p["insecure_cookies"] != "c(httponly)" { // over HTTP only HttpOnly is judged
		t.Errorf("plain = %v", p)
	}
	if g := x.service("https://good.example.com"); g["hsts"] != "yes" || g["directory_listing"] != "no" || g["version_disclosure"] != "" || g["insecure_cookies"] != "" {
		t.Errorf("good = %v", g)
	}
	if strings.Contains(x.file(eng, "web-services.csv"), "TOPSECRET") {
		t.Error("a cookie value reached web-services.csv")
	}

	// risk-web-posture.csv: one low row per service and condition.
	want := []string{
		"directory-listing=https://bad.example.com", "insecure-cookie=https://bad.example.com",
		"missing-hsts=https://bad.example.com", "version-disclosure=https://bad.example.com",
	}
	if got := x.postureTypes(); !slices.Equal(got, want) {
		t.Fatalf("posture findings = %v, want %v\n%s", got, want, x.file(eng, "risk-web-posture.csv"))
	}
	for _, r := range x.postureRows() {
		if r["severity"] != "low" || r["detail"] == "" {
			t.Errorf("row = %v", r)
		}
		if r["type"] == "insecure-cookie" && (!strings.Contains(r["detail"], "sid") || strings.Contains(r["detail"], "good") ||
			strings.Contains(r["detail"], "jsonly") || strings.Contains(r["detail"], "TOPSECRET")) {
			t.Errorf("insecure-cookie detail = %q: want sid, the one cookie missing Secure, and no value", r["detail"])
		}
	}
	// Low findings are not headlines, and the file's cookie row is one row.
	if got := ofType(x.h.events(), "summary"); len(got) != 1 || len(got[0]["findings"].([]any)) != 0 {
		t.Errorf("a low finding reached the summary: %v", got)
	}

	// Nothing beyond the probe's own GET of /.
	for name, s := range map[string]*site{"bad": bad, "plain": plain, "good": good} {
		if !s.onlyGET() || !slices.Equal(s.uris(), []string{"/"}) {
			t.Errorf("%s was sent %v, want only GET /", name, s.requests())
		}
	}
}

// The listing that counts is the last page of the service's own origin: a
// listing a redirect leads to on another host is that host's, not this one's.
func TestWebPosture_RedirectChainDecidesWhatIsRead(t *testing.T) {
	x := newWeb(t)
	x.names("www.example.com", "files.example.com", "cookie.example.com")
	x.host("www.example.com", "203.0.113.5")
	x.host("files.example.com", "203.0.113.6")
	x.host("cookie.example.com", "203.0.113.7")
	x.plain("203.0.113.5", 80, redirectTo(302, "http://files.example.com/"))
	x.plain("203.0.113.6", 80, posturePage(listingPage, nil))
	x.plain("203.0.113.7", 80, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Add("Set-Cookie", "hop=1")
			http.Redirect(w, r, "/home", http.StatusFound)
			return
		}
		w.Header().Add("Set-Cookie", "end=1; HttpOnly")
		_, _ = w.Write([]byte("<title>Home</title>"))
	})
	x.mustRun("--crawl-pages", "0")

	if w := x.service("http://www.example.com"); w["directory_listing"] != "no" {
		t.Errorf("www redirects to a listing on another host, and is not one itself: %v", w)
	}
	if f := x.service("http://files.example.com"); f["directory_listing"] != "yes" {
		t.Errorf("files = %v", f)
	}
	// The cookie set by the redirect response counts, though it is not on the final page.
	if c := x.service("http://cookie.example.com"); c["insecure_cookies"] != "hop(httponly)" {
		t.Errorf("cookie = %v, want hop(httponly): a cookie of a redirect response counts, one with HttpOnly does not", c)
	}
	// Every service is HTTP, so the cookies make no finding; only the listing does.
	if got := x.postureTypes(); !slices.Equal(got, []string{"directory-listing=http://files.example.com"}) {
		t.Errorf("posture findings = %v", got)
	}
}

// An IP-literal service and a SaaS-served service have the evidence but no finding.
func TestWebPosture_NoFindingForIPLiteralOrSaaS(t *testing.T) {
	x := newWeb(t)
	x.names("help.example.com", "www.example.com")
	x.host("help.example.com", "203.0.113.20")
	x.dns.CNAME("help.example.com", "acme.zendesk.com")
	x.dns.A("acme.zendesk.com", "203.0.113.20")
	x.host("www.example.com", "203.0.113.21")
	conds := map[string]string{"Server": "Apache/2.4.41"}
	x.plain("203.0.113.20", 80, posturePage(listingPage, conds))
	x.plain("203.0.113.21", 80, posturePage(listingPage, conds))
	x.mustRun("--crawl-pages", "0")

	if s := x.service("http://help.example.com"); s["directory_listing"] != "yes" || s["version_disclosure"] != "Apache/2.4.41" {
		t.Errorf("a SaaS-served service keeps its evidence: %v", s)
	}
	for _, f := range x.postureRows() {
		if strings.Contains(f["url"], "help.example.com") {
			t.Errorf("a SaaS-served service has a posture finding: %v", f)
		}
	}
	if got := x.postureTypes(); !slices.Equal(got, []string{"directory-listing=http://www.example.com", "version-disclosure=http://www.example.com"}) {
		t.Errorf("posture findings = %v", got)
	}
}

// A switchable service: its headers and page change between runs.
type postureSite struct {
	bad atomic.Bool
}

func (p *postureSite) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if p.bad.Load() {
			w.Header().Set("Server", "Apache/2.4.41")
			w.Header().Add("Set-Cookie", "sid=1; HttpOnly")
			_, _ = w.Write([]byte(listingPage))
			return
		}
		w.Header().Set("Strict-Transport-Security", "max-age=1")
		w.Header().Set("Server", "Apache")
		w.Header().Add("Set-Cookie", "sid=1; Secure; HttpOnly")
		_, _ = w.Write([]byte("<title>Home</title>"))
	}
}

func (x *web) switchable(t *testing.T) (*postureSite, *site) {
	t.Helper()
	x.names("www.example.com")
	x.host("www.example.com", "203.0.113.5")
	p := &postureSite{}
	s := x.secure("203.0.113.5", 443, selfSigned(t, leafSpec{cn: "www.example.com", dns: []string{"www.example.com"}}), p.handler())
	return p, s
}

// An engagement probed before posture was recorded has none of it: the columns
// are blank and there are no findings until httpprobe is redone.
func TestWebPosture_ExistingEngagementGainsPostureOnlyAfterRedo(t *testing.T) {
	x := newWeb(t)
	p, s := x.switchable(t)
	p.bad.Store(true)
	x.mustRun("--crawl-pages", "0")
	if len(x.postureTypes()) == 0 {
		t.Fatal("precondition: the first run records the posture")
	}

	// Make the engagement look as it did before posture was recorded.
	db := x.h.openDB(eng)
	for _, q := range []string{"DELETE FROM observations WHERE kind IN ('web_posture','finding')", "DELETE FROM records WHERE kind IN ('web_posture','finding')"} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	before := s.hits()
	x.mustRun("--crawl-pages", "0")
	if s.hits() != before {
		t.Errorf("a plain re-run sent %d requests to a probed service", s.hits()-before)
	}
	if r := x.service("https://www.example.com"); r["hsts"] != "" || r["insecure_cookies"] != "" || r["directory_listing"] != "" || r["version_disclosure"] != "" {
		t.Errorf("posture columns without a redo = %v, want blank", r)
	}
	if got := x.postureTypes(); len(got) != 0 {
		t.Errorf("posture findings without a redo = %v", got)
	}

	x.mustRun("--crawl-pages", "0", "--redo", "httpprobe")
	if s.hits() == before {
		t.Fatal("--redo httpprobe did not probe again")
	}
	if r := x.service("https://www.example.com"); r["hsts"] != "no" || r["directory_listing"] != "yes" || r["version_disclosure"] != "Apache/2.4.41" ||
		r["insecure_cookies"] != "sid(secure)" { // the cookie has HttpOnly but not Secure
		t.Errorf("posture columns after the redo = %v", r)
	}
	want := []string{
		"directory-listing=https://www.example.com", "insecure-cookie=https://www.example.com",
		"missing-hsts=https://www.example.com", "version-disclosure=https://www.example.com",
	}
	if got := x.postureTypes(); !slices.Equal(got, want) {
		t.Errorf("posture findings after the redo = %v, want %v", got, want)
	}
}

// A condition that is gone after a redo leaves its finding on record, not current.
func TestWebPosture_FixedConditionGoesNotCurrentAfterRedo(t *testing.T) {
	x := newWeb(t)
	p, _ := x.switchable(t)
	p.bad.Store(true)
	x.mustRun("--crawl-pages", "0")
	if got := len(x.postureTypes()); got != 4 {
		t.Fatalf("precondition: %d current findings, want 4\n%s", got, x.file(eng, "risk-web-posture.csv"))
	}

	// Without a redo the probe does not look again, so nothing changes.
	p.bad.Store(false)
	x.mustRun("--crawl-pages", "0")
	if got := len(x.postureTypes()); got != 4 {
		t.Errorf("a plain re-run changed the findings: %d current", got)
	}

	x.mustRun("--crawl-pages", "0", "--redo", "httpprobe")
	if got := x.postureTypes(); len(got) != 0 {
		t.Errorf("fixed conditions are still current: %v", got)
	}
	rows := x.postureRows()
	if len(rows) != 4 {
		t.Fatalf("the findings stay on record:\n%s", x.file(eng, "risk-web-posture.csv"))
	}
	for _, r := range rows {
		// As for every category, a finding no longer derived keeps only what its key identifies.
		if r["current"] != "false" || r["url"] != "https://www.example.com" || r["first_seen"] == "" || r["type"] == "" {
			t.Errorf("row = %v", r)
		}
	}
	svc := x.service("https://www.example.com")
	if svc["hsts"] != "yes" || svc["directory_listing"] != "no" || svc["version_disclosure"] != "" || svc["insecure_cookies"] != "" {
		t.Errorf("columns after the fix = %v", svc)
	}

	// The conditions come back: their findings are current again.
	p.bad.Store(true)
	x.mustRun("--crawl-pages", "0", "--redo", "httpprobe")
	if got := len(x.postureTypes()); got != 4 {
		t.Errorf("after the conditions return: %d current, want 4", got)
	}
}
