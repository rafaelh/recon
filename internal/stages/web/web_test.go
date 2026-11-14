package web

import "testing"

// The crawl's check key carries its limits; the evidence it gives for a
// candidate is the service alone, so changing a limit never counts twice.
func TestCrawlEvidenceDropsTheLimits(t *testing.T) {
	var s *Crawl
	for _, key := range []string{"https://a.example.com|depth=2|pages=100", "https://a.example.com|depth=3|pages=50"} {
		if src, item := s.Evidence(key); src != "crawl" || item != "https://a.example.com" {
			t.Errorf("Evidence(%q) = %q, %q", key, src, item)
		}
	}
}

func TestNormaliseURLCanonicalisesIPLiteralsAndPorts(t *testing.T) {
	for raw, want := range map[string]string{
		"http://[2001:db8:0:0::1]:8080/x": "http://[2001:db8::1]:8080/x",
		"http://[2001:DB8::1]/":           "http://[2001:db8::1]/",
		"http://[::ffff:192.0.2.1]/":      "http://192.0.2.1/",
		"http://a.com:080/":               "http://a.com/",
		"https://a.com:0443":              "https://a.com/",
		"http://a.com:08080/p":            "http://a.com:8080/p",
	} {
		if got, ok := NormaliseURL(raw); !ok || got != want {
			t.Errorf("NormaliseURL(%q) = %q, %v; want %q", raw, got, ok, want)
		}
	}
	for _, raw := range []string{"http://a.com:0/", "http://a.com:65536/"} {
		if got, ok := NormaliseURL(raw); ok {
			t.Errorf("NormaliseURL(%q) = %q, want rejected", raw, got)
		}
	}
	// A normalised URL's origin is the service key Origin builds.
	if u, _ := NormaliseURL("http://[2001:db8:0::1]:8080/x"); originOf(u) != Origin("http", "2001:db8::1", 8080) {
		t.Errorf("originOf(%q) = %q", u, originOf(u))
	}
}

func TestLinksReadsTheFirstBaseHref(t *testing.T) {
	pg, ok := parsePage([]byte(`<html><head><base href="/static/app/"><base href="/other/"></head><body><a href="login">x</a></body></html>`))
	if !ok {
		t.Fatal("unparsable page")
	}
	if l := pg.links(); l.base != "/static/app/" || len(l.follow) != 1 || l.follow[0] != "login" {
		t.Errorf("links = %+v", l)
	}
}

// The fingerprints are embedded; a dependency upgrade that breaks them must
// fail here rather than silently empty the technologies column.
func TestFingerprintsLoad(t *testing.T) {
	if _, err := fingerprints(); err != nil {
		t.Fatal(err)
	}
	if got := technologies(map[string][]string{"Server": {"nginx/1.25.3"}}, nil); got == "" {
		t.Error("no technology detected from Server: nginx/1.25.3")
	}
}
