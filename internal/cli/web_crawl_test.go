package cli_test

import (
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- B7: the light crawl ---

const crawlRootHTML = `<html><body>
<a href="/p1">1</a> <a href="/p2">2</a> <a href="/p3">3</a>
<a href="/robots.txt">robots</a> <a href="/sitemap.xml">sitemap</a>
<a href="/img/logo.png">logo</a>
<a href="https://a.example.com/other-scheme">different scheme</a>
<a href="http://b.example.com/x">another in-scope host</a>
<a href="http://off.example.net/y">off scope</a>
<form action="/submit" method="post"><input name="q"></form>
<script src="/app.js"></script><link rel="stylesheet" href="/s.css">
<iframe src="/frame"></iframe><map><area href="/area" shape="rect" coords="0,0,1,1"></map>
</body></html>`

func crawlFixture(t *testing.T) (*web, *site) {
	t.Helper()
	x := newWeb(t)
	x.names("a.example.com")
	x.host("a.example.com", "203.0.113.5")
	s := x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/":                  page(crawlRootHTML),
		"/p1":                page(`<a href="/p1/deeper">d</a>`),
		"/p1/deeper":         page(`<a href="/p1/deeper/deepest">dd</a>`),
		"/p1/deeper/deepest": page("end"),
		"/p2":                page("p2"), "/p3": page("p3"), "/frame": page("frame"), "/area": page("area"),
	}))
	return x, s
}

func TestWebB7_FetchesAndRecordsAsSpecified(t *testing.T) {
	x, s := crawlFixture(t)
	x.mustRun("--crawl-depth", "2", "--crawl-pages", "100")

	for _, u := range []string{"/", "/p1", "/p2", "/p3", "/frame", "/area", "/p1/deeper"} {
		if s.count(u) == 0 {
			t.Errorf("%s was not crawled: %v", u, s.uris())
		}
	}
	if s.count("/") != 2 {
		t.Errorf("/ requested %d times, want 2 (the probe and the crawl's root)", s.count("/"))
	}
	if s.count("/p1/deeper/deepest") != 0 {
		t.Error("depth 3 was fetched with a depth limit of 2")
	}
	for _, u := range []string{"/submit", "/app.js", "/s.css", "/img/logo.png", "/other-scheme", "/x", "/y", "/robots.txt", "/sitemap.xml"} {
		if s.count(u) != 0 {
			t.Errorf("%s must be recorded or ignored, never fetched", u)
		}
	}
	if !s.onlyGET() {
		t.Errorf("non-GET request: %+v", s.requests())
	}

	rows := x.urls()
	for url, status := range map[string]string{
		"http://a.example.com/p1": "200", "http://a.example.com/p1/deeper": "200", "http://a.example.com/p1/deeper/deepest": "",
		"http://a.example.com/submit": "", "http://a.example.com/app.js": "", "http://a.example.com/s.css": "",
		"http://a.example.com/img/logo.png": "", "https://a.example.com/other-scheme": "", "http://b.example.com/x": "",
	} {
		r := find(rows, "url", url)
		if r == nil || r["status"] != status || !strings.Contains(r["found_by"], "crawl") {
			t.Errorf("%s = %v, want status %q found by crawl", url, r, status)
		}
	}
	for _, u := range x.urlSet() {
		if strings.Contains(u, "off.example.net") {
			t.Errorf("an off-scope link was recorded: %s", u)
		}
	}
	// An in-scope link host becomes a hostname; an off-scope one is neither a hostname nor a candidate.
	if got := x.observedBy("hostname", "crawl"); !slices.Equal(got, []string{"b.example.com"}) {
		t.Errorf("crawl hostnames = %v, want only b.example.com", got)
	}
	if hosts := x.lines(eng, "subdomains.txt"); !slices.Contains(hosts, "b.example.com") {
		t.Errorf("subdomains.txt = %v", hosts)
	}
	for _, c := range x.table(eng, "candidates.csv") {
		if strings.Contains(c["value"], "example.net") {
			t.Errorf("an off-scope link host became a candidate: %v", c)
		}
	}
}

func TestWebB7_RelativeLinksResolveAgainstBaseHref(t *testing.T) {
	x := newWeb(t)
	x.names("a.example.com")
	x.host("a.example.com", "203.0.113.5")
	s := x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/":                 page(`<html><head><base href="/static/app/"></head><body><a href="login">l</a><a href="/abs">a</a></body></html>`),
		"/static/app/login": page("login"),
		"/abs":              page("abs"),
	}))
	x.mustRun()

	if s.count("/static/app/login") != 1 || s.count("/login") != 0 || s.count("/abs") != 1 {
		t.Errorf("crawled %v, want /static/app/login and /abs", s.uris())
	}
	urls := x.urlSet()
	if !slices.Contains(urls, "http://a.example.com/static/app/login") || slices.Contains(urls, "http://a.example.com/login") {
		t.Errorf("urls.csv = %v", urls)
	}
}

func TestWebB7_PageAndDepthCaps(t *testing.T) {
	t.Run("pages count the root", func(t *testing.T) {
		x, s := crawlFixture(t)
		x.mustRun("--crawl-pages", "3")
		if got := s.uris(); !slices.Equal(got, []string{"/", "/p1", "/p2"}) {
			t.Errorf("fetched %v, want the root and the first two links in document order", got)
		}
	})
	t.Run("depth 0 is the root only", func(t *testing.T) {
		x, s := crawlFixture(t)
		x.mustRun("--crawl-depth", "0")
		if got := s.uris(); !slices.Equal(got, []string{"/"}) {
			t.Errorf("fetched %v", got)
		}
		if u := find(x.urls(), "url", "http://a.example.com/p1"); u == nil || u["status"] != "" {
			t.Errorf("links on the root are still recorded: %v", u)
		}
	})
}

func TestWebB7_RecordedURLsAreCappedAt20TimesPages(t *testing.T) {
	x := newWeb(t)
	x.names("a.example.com")
	x.host("a.example.com", "203.0.113.5")
	var links strings.Builder
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&links, `<a href="/l%d">l</a>`, i)
	}
	x.plain("203.0.113.5", 80, page(links.String()))
	x.mustRun("--crawl-pages", "2")
	n := 0
	for _, r := range x.urls() {
		if r["found_by"] == "crawl" {
			n++
		}
	}
	if n != 40 {
		t.Errorf("crawl recorded %d urls, want the 20×P = 40 cap", n)
	}
}

func TestWebB7_Errors(t *testing.T) {
	t.Run("a failing non-root page is skipped and the check completes", func(t *testing.T) {
		x := newWeb(t)
		x.names("a.example.com")
		x.host("a.example.com", "203.0.113.5")
		s := x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
			"/":     page(`<a href="/ok">ok</a><a href="/slow">slow</a>`),
			"/ok":   page("ok"),
			"/slow": func(w http.ResponseWriter, r *http.Request) { time.Sleep(1500 * time.Millisecond) }, // past the 1 s timeout
		}))
		x.mustRun()
		if got := x.completedKeys("crawl"); !slices.Equal(got, []string{"http://a.example.com|depth=2|pages=100"}) {
			t.Errorf("crawl checks = %v", got)
		}
		if s.count("/ok") == 0 {
			t.Error("pages after the failing one were not crawled")
		}
		if !slices.Contains(x.urlSet(), "http://a.example.com/slow") {
			t.Errorf("the link to the slow page is still recorded: %v", x.urlSet())
		}
	})
	t.Run("a failing root page fails the check and is retried next run", func(t *testing.T) {
		x := newWeb(t)
		x.names("a.example.com")
		x.host("a.example.com", "203.0.113.5")
		var n atomic.Int32
		var fail atomic.Bool
		fail.Store(true)
		x.plain("203.0.113.5", 80, func(w http.ResponseWriter, r *http.Request) {
			// Request 1 is the probe; request 2 is the crawl's root, which dies mid-body.
			if n.Add(1) >= 2 && fail.Load() {
				w.Header().Set("Content-Length", "1000")
				w.Write([]byte("short"))
				w.(http.Flusher).Flush()
				panic(http.ErrAbortHandler)
			}
			page(`<a href="/next">n</a>`)(w, r)
		})
		x.mustRun()
		if got := x.completedKeys("crawl"); len(got) != 0 {
			t.Errorf("a failed root must not complete the check: %v", got)
		}
		if st, _ := stateOf(x.world, "crawl"); st != "failed" {
			t.Errorf("crawl = %s, want failed", st)
		}
		fail.Store(false)
		x.mustRun()
		if got := x.completedKeys("crawl"); !slices.Equal(got, []string{"http://a.example.com|depth=2|pages=100"}) {
			t.Errorf("retry: crawl checks = %v", got)
		}
	})
}

func TestWebB7_RootRedirectToAnotherOriginEndsTheCrawl(t *testing.T) {
	x := newWeb(t)
	x.names("a.example.com")
	x.host("a.example.com", "203.0.113.5")
	x.plain("203.0.113.5", 80, redirectTo(301, "https://a.example.com/landing"))
	s443 := x.secure("203.0.113.5", 443, selfSigned(t, leafSpec{cn: "a.example.com", dns: []string{"a.example.com"}}),
		routes(map[string]http.HandlerFunc{
			"/":        page("home"),
			"/landing": page(`<a href="/inner">i</a>`),
			"/inner":   page("inner"),
		}))
	x.mustRun()

	// The probe follows the redirect once; the http service's crawl must not.
	if s443.count("/landing") != 1 {
		t.Errorf("/landing requested %d times, want 1 (the probe only)", s443.count("/landing"))
	}
	if s443.count("/inner") != 0 {
		t.Error("the http service's crawl continued on another origin")
	}
	if u := find(x.urls(), "url", "https://a.example.com/landing"); u == nil || !strings.Contains(u["found_by"], "crawl") {
		t.Errorf("the redirect target must be recorded by the crawl: %v", u)
	}
	if got := x.completedKeys("crawl"); !contains(got, "http://a.example.com|depth=2|pages=100") {
		t.Errorf("the http service's crawl must complete: %v", got)
	}
}

func TestWebB7_SameOriginRedirectsAreFollowedAndOnlyHTMLIsParsed(t *testing.T) {
	x := newWeb(t)
	x.names("a.example.com")
	x.host("a.example.com", "203.0.113.5")
	s := x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/":           page(`<a href="/old">o</a><a href="/notes">n</a><a href="/to-robots">r</a>`),
		"/old":        redirectTo(301, "/new"),
		"/to-robots":  redirectTo(301, "/robots.txt"),
		"/robots.txt": page("User-agent: *"),
		"/new":        page(`<a href="/newer">x</a>`),
		"/newer":      page("newer"),
		"/notes": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(`<a href="/hidden">h</a>`))
		},
		"/hidden": page("hidden"),
	}))
	x.mustRun("--crawl-depth", "3")
	if s.count("/new") == 0 || s.count("/newer") == 0 {
		t.Errorf("a same-origin redirect was not followed: %v", s.uris())
	}
	if s.count("/hidden") != 0 {
		t.Error("links in a text/plain body were followed")
	}
	if s.count("/robots.txt") != 0 {
		t.Error("a redirect to robots.txt was followed")
	}
}

func TestWebB7_DisabledAndSettingsAreInTheCheckKey(t *testing.T) {
	x, s := crawlFixture(t)
	x.mustRun("--crawl-pages", "0")
	if st, reason := stateOf(x.world, "crawl"); st != "not-configured" || reason != "disabled" {
		t.Errorf("crawl = %s (%s), want not-configured (disabled)", st, reason)
	}
	if s.hits() != 1 || len(x.completedKeys("crawl")) != 0 {
		t.Errorf("a disabled crawl sent requests or completed checks: hits=%d keys=%v", s.hits(), x.completedKeys("crawl"))
	}
	x.mustRun()
	key := func(d, p int) string { return fmt.Sprintf("http://a.example.com|depth=%d|pages=%d", d, p) }
	if got := x.completedKeys("crawl"); !slices.Equal(got, []string{key(2, 100)}) {
		t.Errorf("default crawl keys = %v", got)
	}
	x.mustRun("--crawl-depth", "1")
	x.mustRun("--crawl-pages", "50")
	want := []string{key(1, 100), key(2, 100), key(2, 50)}
	sort.Strings(want)
	if got := x.completedKeys("crawl"); !slices.Equal(got, want) {
		t.Errorf("crawl keys = %v, want %v: changing depth or pages must create new checks", got, want)
	}
}
