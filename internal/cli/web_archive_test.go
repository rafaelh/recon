package cli_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// passive runs recon with third-party sources only.
func (x *web) passive(args ...string) int {
	x.t.Helper()
	x.fill()
	full := append([]string{"--passive", "--no-permutations"}, args...)
	return x.world.run(append(full, "example.com")...)
}

func (x *web) mustPassive(args ...string) {
	x.t.Helper()
	if code := x.passive(args...); code != 0 {
		x.t.Fatalf("exit %d\n%s", code, x.h.stdout.String())
	}
}

func (x *web) summaryTotal(category string) int {
	x.t.Helper()
	sums := ofType(x.h.events(), "summary")
	if len(sums) == 0 {
		x.t.Fatal("no summary event")
	}
	totals, _ := sums[len(sums)-1]["totals"].(map[string]any)
	n, _ := totals[category].(float64)
	return int(n)
}

// --- Archived URLs ---

func TestArchive_ArchivedURLsUnderPassive(t *testing.T) {
	x := newWeb(t)
	x.host("a.example.com", "203.0.113.5")
	a80 := x.plain("203.0.113.5", 80, page("live"))
	a443 := x.secure("203.0.113.5", 443, selfSigned(t, leafSpec{cn: "a.example.com"}), page("live"))
	x.waybackURLs(
		"http://a.example.com/p?x=1#frag",
		"https://A.EXAMPLE.COM:443/Q",
		"http://a.example.com/logo.png",
		"http://a.example.com/site.css",
		"http://b.example.com/doc.pdf",
		"http://b.example.com/page",
		"http://off.example.net/x",
	)
	x.commonCrawl("CC-1", "https://a.example.com/Q", "http://c.example.com/z", "http://c.example.com/font.woff2")
	x.mustPassive()

	want := []string{"http://a.example.com/p?x=1", "http://b.example.com/page", "http://c.example.com/z", "https://a.example.com/Q"}
	if got := x.urlSet(); !slices.Equal(got, want) {
		t.Fatalf("urls.csv = %v, want %v (normalised, assets and other roots dropped)", got, want)
	}
	rows := x.urls()
	for url, by := range map[string]string{
		"http://a.example.com/p?x=1": "wayback", "https://a.example.com/Q": "commoncrawl,wayback", "http://c.example.com/z": "commoncrawl",
	} {
		r := find(rows, "url", url)
		if r["found_by"] != by || r["status"] != "" || r["host"] != strings.Split(strings.SplitN(url, "//", 2)[1], "/")[0] {
			t.Errorf("%s = %v, want found_by %q and no status", url, r, by)
		}
	}
	if a80.hits()+a443.hits() != 0 {
		t.Errorf("an archived URL was requested (%d+%d)", a80.hits(), a443.hits())
	}
	for _, st := range []string{"httpprobe", "crawl"} {
		if s, reason := stateOf(x.world, st); s != "not-configured" || reason != "passive-only" {
			t.Errorf("%s = %s (%s), want not-configured (passive-only)", st, s, reason)
		}
	}
	for _, st := range []string{"wayback", "commoncrawl"} {
		if s, _ := stateOf(x.world, st); s != "done" {
			t.Errorf("%s = %s, want done", st, s)
		}
	}
	if got := x.summaryTotal("urls"); got != len(want) {
		t.Errorf("summary urls = %d, want %d", got, len(want))
	}
}

func archiveWorld(t *testing.T) *web {
	x := newWeb(t)
	var urls []string
	for _, h := range []string{"a", "b"} {
		for i := 1; i <= map[string]int{"a": 4, "b": 2}[h]; i++ {
			urls = append(urls, fmt.Sprintf("http://%s.example.com/%d", h, i))
		}
	}
	x.waybackURLs(urls...)
	x.names("a.example.com")
	return x
}

// Archives return some URLs without a scheme; their hosts were always kept,
// and so are the URLs.
func TestArchive_ArchivedURLsWithoutASchemeAreKept(t *testing.T) {
	x := newWeb(t)
	x.waybackURLs("www.example.com/admin/login.php")
	x.commonCrawl("CC-1", "cc.example.com/z")
	x.mustPassive()

	want := []string{"http://cc.example.com/z", "http://www.example.com/admin/login.php"}
	if got := x.urlSet(); !slices.Equal(got, want) {
		t.Errorf("urls.csv = %v, want %v", got, want)
	}
	if hosts := x.lines(eng, "subdomains.txt"); !slices.Contains(hosts, "www.example.com") || !slices.Contains(hosts, "cc.example.com") {
		t.Errorf("subdomains.txt = %v", hosts)
	}
}

func TestArchive_CapIsRoundRobinDeterministicAndPartOfTheCheckKey(t *testing.T) {
	x := archiveWorld(t)
	x.mustPassive("--archive-max-urls", "4")
	capped := []string{"http://a.example.com/1", "http://a.example.com/2", "http://b.example.com/1", "http://b.example.com/2"}
	if got := x.urlSet(); !slices.Equal(got, capped) {
		t.Fatalf("cap 4 kept %v, want %v (one per host in turn, so early hosts cannot take the cap)", got, capped)
	}
	if got := x.completedKeys("wayback"); !slices.Equal(got, []string{"example.com|urls=4"}) {
		t.Errorf("wayback keys = %v", got)
	}
	crtsh := x.completedKeys("crtsh")

	y := archiveWorld(t)
	y.mustPassive("--archive-max-urls", "4")
	if a, b := x.file(eng, "urls.csv"), y.file(eng, "urls.csv"); a != b {
		t.Errorf("the capped selection is not deterministic:\n%s\n--\n%s", a, b)
	}

	x.mustPassive("--archive-max-urls", "6")
	if got := x.urlSet(); len(got) != 6 {
		t.Errorf("raising the cap kept %v", got)
	}
	if got := x.completedKeys("wayback"); !slices.Equal(got, []string{"example.com|urls=4", "example.com|urls=6"}) {
		t.Errorf("changing the cap must create a new check: %v", got)
	}
	if got := x.completedKeys("crtsh"); !slices.Equal(got, crtsh) || !slices.Equal(got, []string{"example.com"}) {
		t.Errorf("crtsh keys changed: %v (was %v)", got, crtsh)
	}
}

func TestArchive_CapSettingIsValidatedAndDocumented(t *testing.T) {
	for _, bad := range []string{"0", "-1", "many"} {
		x := archiveWorld(t)
		if code := x.passive("--archive-max-urls", bad); code != 2 {
			t.Errorf("--archive-max-urls %s: exit %d, want 2", bad, code)
		}
	}
	x := archiveWorld(t)
	t.Setenv("RECON_ARCHIVE_MAX_URLS", "4") // after the harness, which clears RECON_*
	x.mustPassive()
	if got := x.completedKeys("wayback"); !slices.Equal(got, []string{"example.com|urls=4"}) {
		t.Errorf("RECON_ARCHIVE_MAX_URLS ignored: %v", got)
	}

	h := newHarness(t, defaultStageList()...)
	if code := h.exec("--help"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"--archive-max-urls", "20000", "httpprobe", "crawl"} {
		if !strings.Contains(h.stdout.String(), want) {
			t.Errorf("help missing %q", want)
		}
	}
}

func TestArchive_AnExclusionAddedLaterHidesArchivedURLs(t *testing.T) {
	x := archiveWorld(t)
	x.mustPassive()
	if n := len(x.urlSet()); n != 6 {
		t.Fatalf("urls = %v", x.urlSet())
	}
	x.mustPassive("-x", "b.example.com")
	for _, r := range x.urls() {
		if r["host"] == "b.example.com" {
			t.Errorf("urls.csv still lists an excluded host: %v", r)
		}
	}
	current := 0
	for _, r := range x.urls() {
		if r["current"] == "true" {
			current++
		}
	}
	if current != 4 {
		t.Errorf("current urls = %d, want the 4 under a.example.com", current)
	}
	if got := x.summaryTotal("urls"); got != current {
		t.Errorf("summary urls = %d but urls.csv has %d current rows: both must use the same filter", got, current)
	}
}
