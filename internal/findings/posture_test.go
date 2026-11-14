package findings_test

import (
	"strings"
	"testing"

	"github.com/rafaelh/recon/internal/findings"
)

// posture adds a web_posture record, as the probe stores it, for a service.
func (f *fixture) posture(service, host string, kv ...any) {
	f.add(rec("web_posture", service, append([]any{"host", host, "directory_listing", false}, kv...)...))
}

// The four conditions are each one low finding per service, and a service with
// none of them has none.
func TestWebPostureFindings(t *testing.T) {
	f := newFixture()
	for _, h := range []string{"www", "ls", "old", "ck", "ok"} {
		f.host(h+".example.com", "203.0.113.5")
	}
	f.posture("https://www.example.com", "www.example.com", "hsts", false)
	f.posture("https://ls.example.com", "ls.example.com", "hsts", true, "directory_listing", true)
	f.posture("https://old.example.com", "old.example.com", "hsts", true, "version_disclosure", "Apache/2.4.41")
	f.posture("https://ck.example.com", "ck.example.com", "hsts", true, "cookies_no_secure", "sid;csrf")
	f.posture("https://ok.example.com", "ok.example.com", "hsts", true)
	got := f.derive(t)
	wantSet(t, got,
		"web-posture/missing-hsts=low",
		"web-posture/directory-listing=low",
		"web-posture/version-disclosure=low",
		"web-posture/insecure-cookie=low")
	by := map[string]findings.Finding{}
	for _, x := range got {
		by[x.Type] = x
	}
	for typ, target := range map[string]string{
		"missing-hsts": "https://www.example.com", "directory-listing": "https://ls.example.com",
		"version-disclosure": "https://old.example.com", "insecure-cookie": "https://ck.example.com",
	} {
		x := by[typ]
		if x.Target != target || x.Attrs["url"] != target || x.Detail == "" {
			t.Errorf("%s finding = %+v", typ, x)
		}
	}
	if d := by["insecure-cookie"].Detail; !strings.Contains(d, "sid") || !strings.Contains(d, "csrf") {
		t.Errorf("the cookie names are in one row: %q", d)
	}
	if d := by["version-disclosure"].Detail; !strings.Contains(d, "Apache/2.4.41") {
		t.Errorf("the header value is in the detail: %q", d)
	}
}

// One row per service and condition: several conditions of one service are
// separate findings, and an insecure-cookie row carries every cookie.
func TestWebPostureOneFindingPerServiceAndCondition(t *testing.T) {
	f := newFixture()
	f.host("www.example.com", "203.0.113.5")
	f.posture("https://www.example.com", "www.example.com", "hsts", false, "cookies_no_secure", "a;b;c",
		"directory_listing", true, "version_disclosure", "nginx/1.25.3;PHP/8.2.1")
	f.posture("http://www.example.com", "www.example.com", "version_disclosure", "nginx/1.25.3")
	wantSet(t, f.derive(t),
		"web-posture/missing-hsts=low", "web-posture/insecure-cookie=low",
		"web-posture/directory-listing=low", "web-posture/version-disclosure=low",
		"web-posture/version-disclosure=low")
}

// HSTS means nothing over HTTP, and Secure is judged only over HTTPS.
func TestWebPostureHTTPServiceHasNoHSTSOrSecureFinding(t *testing.T) {
	f := newFixture()
	f.host("www.example.com", "203.0.113.5")
	f.posture("http://www.example.com", "www.example.com") // hsts unset
	wantSet(t, f.derive(t))

	// A cookie name lacking Secure on an http service (it came from a hop) is not a finding.
	f = newFixture()
	f.host("www.example.com", "203.0.113.5")
	f.posture("http://www.example.com", "www.example.com", "cookies_no_secure", "sid")
	wantSet(t, f.derive(t))

	// A https service whose HSTS is unknown (no value) is not reported.
	f = newFixture()
	f.host("www.example.com", "203.0.113.5")
	f.posture("https://www.example.com", "www.example.com")
	wantSet(t, f.derive(t))
}

// A cookie without HttpOnly is evidence only.
func TestWebPostureHTTPOnlyAloneMakesNoFinding(t *testing.T) {
	f := newFixture()
	f.host("www.example.com", "203.0.113.5")
	f.posture("https://www.example.com", "www.example.com", "hsts", true, "cookies_no_httponly", "sid")
	f.posture("http://www.example.com", "www.example.com", "cookies_no_httponly", "sid")
	wantSet(t, f.derive(t))
}

// No posture finding for a service addressed by IP literal or served by a SaaS platform.
func TestWebPostureSkipsIPLiteralAndSaaSServices(t *testing.T) {
	f := newFixture()
	f.host("www.example.com", "203.0.113.5")
	f.host("help.example.com", "203.0.113.20")
	f.cname("help.example.com", "acme.zendesk.com")
	bad := []any{"hsts", false, "cookies_no_secure", "sid", "directory_listing", true, "version_disclosure", "Apache/2.4.41"}
	f.posture("https://198.51.100.5", "198.51.100.5", bad...)
	f.posture("https://[2001:db8::1]", "2001:db8::1", bad...)
	f.posture("https://help.example.com", "help.example.com", bad...)
	wantSet(t, f.derive(t))

	// The same conditions on an ordinary name are reported.
	f.posture("https://www.example.com", "www.example.com", bad...)
	if n := len(f.derive(t)); n != 4 {
		t.Errorf("the ordinary service has %d findings, want 4", n)
	}
}

// A posture record is shown only while its host is in scope and it is current.
func TestWebPostureFollowsScopeAndCurrency(t *testing.T) {
	f := newFixture()
	f.host("www.example.com", "203.0.113.5")
	f.host("ex.example.com", "203.0.113.6")
	f.excl = []string{"ex.example.com"}
	f.posture("https://www.example.com", "www.example.com", "hsts", false)
	f.posture("https://ex.example.com", "ex.example.com", "hsts", false)
	f.posture("https://off.example.org", "off.example.org", "hsts", false)
	stale := rec("web_posture", "https://old.example.com", "host", "old.example.com", "hsts", false)
	stale.Current = false
	f.host("old.example.com", "203.0.113.7")
	f.add(stale)
	got := f.derive(t)
	wantSet(t, got, "web-posture/missing-hsts=low")
	if len(got) == 1 && got[0].Target != "https://www.example.com" {
		t.Errorf("target = %s", got[0].Target)
	}
}
