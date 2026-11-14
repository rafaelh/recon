package cli_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"
)

// The permutation tests use few words so the arithmetic is easy to follow. With
// W words a root check queries W names, and a seed check queries 2 + 6W (two
// digit variants, then six joins per word): 26 names for 4 words.
const (
	fourWords = "dev\ntest\nbeta\nold\n"
	rootNames = 4
	seedNames = 26
)

// derived are the queried names built from a seed label under example.com, not the seed itself.
func derived(w *world, label string) []string { return derivedUnder(w, label, "example.com") }

// worldWithSeeds is a world whose crt.sh answer gives two seeds, api and ftp.
func worldWithSeeds(t *testing.T, words string) (*world, string) {
	w := newWorld(t)
	wl := writeFile(t, t.TempDir(), "words.txt", words)
	w.crtsh(map[string][]string{"example.com": {"ftp.example.com", "api.example.com"}}, nil)
	w.dns.A("api.example.com", "203.0.113.5")
	w.dns.A("ftp.example.com", "203.0.113.6")
	return w, wl
}

// permRun runs the permutations on one root with a single worker, so names are
// queried in the order the stage yields them.
func permRun(w *world, wl string, args ...string) int {
	full := append([]string{"--passive", "--concurrency", "1", "--wordlist", wl}, args...)
	return w.run(append(full, "example.com")...)
}

// Roots come before seeds, and seeds are taken in name order. A seed that would
// pass the cap is deferred whole, with every seed after it; the next run does
// them. A seed that exactly fills the cap is taken.
func TestListsPermutations_RootsBeforeSeedsAndDeferralIsWhole(t *testing.T) {
	w, wl := worldWithSeeds(t, fourWords)
	if code := permRun(w, wl, "--permutations-max-names", "30"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if st, _ := stateOf(w, "permutations"); st != "done" {
		t.Errorf("a deferred stage must show done, got %s", st)
	}
	for _, word := range []string{"dev", "test", "beta", "old"} {
		if w.dns.Count(word+".example.com", "A") != 1 {
			t.Errorf("root name %s.example.com queried %d times, want once", word, w.dns.Count(word+".example.com", "A"))
		}
	}
	if got := derived(w, "api"); len(got) != seedNames {
		t.Errorf("api (the first seed in name order) queried %d derived names, want all %d: %v", len(got), seedNames, got)
	}
	if got := derived(w, "ftp"); len(got) != 0 {
		t.Errorf("ftp must be deferred whole, but %d of its names were queried: %v", len(got), got)
	}
	if n := deferredOf(t, w.h, "permutations"); n != seedNames {
		t.Errorf("deferred = %d, want %d", n, seedNames)
	}

	// The next run does what was deferred, and nothing again.
	before := w.dns.Count("dev.example.com", "A")
	if code := permRun(w, wl, "--permutations-max-names", "30"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got := derived(w, "ftp"); len(got) != seedNames {
		t.Errorf("after the second run ftp queried %d names, want %d", len(got), seedNames)
	}
	if w.dns.Count("dev.example.com", "A") != before {
		t.Error("a completed root check was repeated")
	}
	if n := deferredOf(t, w.h, "permutations"); n != 0 {
		t.Errorf("deferred after the last run = %d, want 0", n)
	}
}

// The cap falls part-way through a seed's names: none of them are queried.
func TestListsPermutations_SeedIsNeverSplit(t *testing.T) {
	w, wl := worldWithSeeds(t, fourWords)
	permRun(w, wl, "--permutations-max-names", "20") // the root's 4 names, then 26 would reach 30
	if got := derived(w, "api"); len(got) != 0 {
		t.Errorf("api would pass the cap, yet %d of its names were queried: %v", len(got), got)
	}
	if n := deferredOf(t, w.h, "permutations"); n != 2*seedNames {
		t.Errorf("deferred = %d, want %d (both seeds)", n, 2*seedNames)
	}
}

// The first check of the run is taken even if it alone exceeds the cap, so a
// small cap cannot stop the stage making progress.
func TestListsPermutations_RootAloneOverCapIsTaken(t *testing.T) {
	w, wl := worldWithSeeds(t, "dev\ntest\nbeta\nold\nqa\nuat\nstg\nprod\nint\nlab\n")
	if code := permRun(w, wl, "--permutations-max-names", "3"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, word := range strings.Fields("dev test beta old qa uat stg prod int lab") {
		if w.dns.Count(word+".example.com", "A") != 1 {
			t.Errorf("%s.example.com queried %d times; the root is 10 names over a cap of 3 yet must be taken whole", word, w.dns.Count(word+".example.com", "A"))
		}
	}
	if len(derived(w, "api"))+len(derived(w, "ftp")) != 0 {
		t.Error("seeds must wait once the root has spent the cap")
	}
	if n := deferredOf(t, w.h, "permutations"); n == 0 {
		t.Error("the seeds' names must be reported as deferred")
	}
}

// Names under a zone already known to be a wildcard are not generated, for a
// root or for a seed whose parent is that zone; other zones are unaffected.
func TestListsPermutations_NoNamesUnderWildcardZone(t *testing.T) {
	w := newWorld(t)
	wl := writeFile(t, t.TempDir(), "words.txt", fourWords)
	w.crtsh(map[string][]string{"example.com": {"api.example.com"}, "corp.net": {"vpn.corp.net"}}, nil)
	w.dns.Wildcard("example.com", "203.0.113.1")
	w.dns.A("api.example.com", "203.0.113.5")
	w.dns.A("vpn.corp.net", "203.0.113.6")
	if code := w.run("--passive", "--wordlist", wl, "example.com", "corp.net"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	// Under the wildcard zone only the known host and the wildcard probes (16 random
	// hex characters) are queried: not one generated name.
	for _, n := range w.dns.Queried("A") {
		label, parent, _ := strings.Cut(n, ".")
		if parent == "example.com" && label != "api" && len(label) != 16 {
			t.Errorf("%s was generated under a wildcard zone", n)
		}
	}
	for _, word := range []string{"dev", "test", "beta", "old"} {
		if w.dns.Count(word+".corp.net", "A") != 1 {
			t.Errorf("%s.corp.net queried %d times; a zone with no wildcard is permuted as usual", word, w.dns.Count(word+".corp.net", "A"))
		}
	}
	if got := derivedUnder(w, "vpn", "corp.net"); len(got) != seedNames {
		t.Errorf("vpn.corp.net: %d derived names queried, want %d", len(got), seedNames)
	}
	if st, _ := stateOf(w, "permutations"); st != "done" {
		t.Errorf("permutations = %s", st)
	}
}

// A seed that is itself a wildcard zone is still permuted beside it (api-dev,
// devapi, ...), but no generated name directly under it (dev.api) is queried.
func TestListsPermutations_SeedThatIsAWildcardZone(t *testing.T) {
	w := newWorld(t)
	wl := writeFile(t, t.TempDir(), "words.txt", fourWords)
	w.crtsh(map[string][]string{"example.com": {"api.example.com", "x.api.example.com"}}, nil)
	w.dns.A("api.example.com", "203.0.113.5")
	w.dns.Wildcard("api.example.com", "203.0.113.9")
	if code := w.run("--passive", "--wordlist", wl, "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, word := range []string{"dev", "test", "beta", "old"} {
		if n := w.dns.Count(word+".api.example.com", "A"); n != 0 {
			t.Errorf("%s.api.example.com queried %d times; it is under a wildcard zone", word, n)
		}
	}
	if w.dns.Count("api-dev.example.com", "A") != 1 {
		t.Error("api-dev.example.com is not under a wildcard zone and must still be queried")
	}
}

func derivedUnder(w *world, label, zone string) []string {
	var out []string
	for _, n := range w.dns.Queried("A") {
		if strings.Contains(n, label) && n != label+"."+zone && strings.HasSuffix(n, "."+zone) {
			out = append(out, n)
		}
	}
	return out
}

// The console and the --json summary both give the deferred count.
func TestListsPermutations_ConsoleAndJSONCounts(t *testing.T) {
	w, wl := worldWithSeeds(t, fourWords)
	args := []string{"--rate-per-source", "1000", "--rate-dns", "100000", "--passive", "--concurrency", "1",
		"--wordlist", wl, "--permutations-max-names", "30", "example.com"}
	if code := w.h.exec(args...); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if block := deferredBlock(t, w.h.stdout.String()); !strings.Contains(block, "permutations") || !strings.Contains(block, "26") {
		t.Errorf("block does not give the stage and the count of 26:\n%s", block)
	}
	// The second run does the rest, so nothing is deferred and the field says so.
	permRun(w, wl, "--permutations-max-names", "30")
	if n := deferredOf(t, w.h, "permutations"); n != 0 {
		t.Errorf("deferred after the last run = %d", n)
	}
}

func TestListsPermutations_InvalidCapExits2(t *testing.T) {
	w, wl := worldWithSeeds(t, fourWords)
	if code := permRun(w, wl, "--permutations-max-names", "0"); code != 2 {
		t.Errorf("exit %d, want 2", code)
	}
	if w.dns.Total() != 0 {
		t.Error("nothing may be queried after a validation error")
	}
}

// The first run after the list changes repeats every permutation check once;
// the run after that repeats none.
func TestListsPermutations_ChangedListRepeatsChecksOnce(t *testing.T) {
	w, wl := worldWithSeeds(t, fourWords)
	permRun(w, wl, "--permutations-max", "5")
	old := w.h.completed(eng, "permutations")
	if len(old) != 3 { // the root and the two seeds
		t.Fatalf("setup: %v", old)
	}
	// The upgrade: the engagement now runs with a different list (here the real
	// built-in one, which a new release has changed).
	t.Setenv("RECON_WORDLIST", "")
	w.run("--passive", "--permutations-max", "5", "example.com")
	upgraded := w.h.completed(eng, "permutations")
	if len(upgraded) != 6 {
		t.Fatalf("after the upgrade there are %d checks, want the 3 old and 3 new: %v", len(upgraded), upgraded)
	}
	root := w.dns.Count("www.example.com", "A")
	if root != 1 {
		t.Errorf("built-in word www queried %d times under the root after the upgrade, want 1", root)
	}
	w.run("--passive", "--permutations-max", "5", "example.com")
	if again := w.h.completed(eng, "permutations"); len(again) != 6 {
		t.Errorf("a further run changed the checks: %v", again)
	}
	if w.dns.Count("www.example.com", "A") != root {
		t.Error("a further run repeated a completed permutation check")
	}
}

// --- sensitive paths ---

const tierPathsYAML = `
- path: /low-one
  signature: 'LOW'
  severity: low
- path: /high-one
  signature: 'HIGH'
  severity: high
- path: /medium-one
  signature: 'MEDIUM'
  severity: medium
- path: /high-two
  signature: 'HIGH'
  severity: high
`

// tiers serves all four paths and a catch-all for the rest.
func tiers(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/low-one":
		_, _ = w.Write([]byte("LOW"))
	case "/high-one", "/high-two":
		_, _ = w.Write([]byte("HIGH"))
	case "/medium-one":
		_, _ = w.Write([]byte("MEDIUM"))
	default:
		_, _ = w.Write([]byte("<html>catch-all</html>"))
	}
}

func total(sites []*site, path string) int {
	n := 0
	for _, s := range sites {
		n += s.count(path)
	}
	return n
}

// twoServices is a risk world with two live web services serving tiers.
func twoServices(t *testing.T) (*risk, []*site) {
	x := newRisk(t, "sensitive-paths")
	x.names("plain.example.com", "www.example.com")
	x.host("plain.example.com", "203.0.113.6")
	x.host("www.example.com", "203.0.113.5")
	return x, []*site{x.plain("203.0.113.5", 80, tiers), x.plain("203.0.113.6", 80, tiers)}
}

// Requests are taken entry by entry in severity order, then by service, so
// every service gets its highest-severity paths first; what does not fit waits
// for later runs, which do not repeat what was done.
func TestListsSensitive_SeverityOrderAcrossServices(t *testing.T) {
	x, sites := twoServices(t)
	file := x.pathsFile(tierPathsYAML)
	// 2 services × 4 entries = 8 requests; 3 fit: high-one on both, then high-two on one.
	x.mustRun("--crawl-pages", "0", "--sensitive-paths", file, "--sensitive-path-max-requests", "3")
	if got := total(sites, "/high-one"); got != 2 || sites[0].count("/high-one") != 1 || sites[1].count("/high-one") != 1 {
		t.Errorf("/high-one requested %d times, want once on each service", got)
	}
	if got := total(sites, "/high-two"); got != 1 {
		t.Errorf("/high-two requested %d times, want once (the cap falls after its first service)", got)
	}
	if total(sites, "/medium-one")+total(sites, "/low-one") != 0 {
		t.Error("medium and low paths must wait behind the high ones")
	}
	if st := x.state("sensitive-paths"); st.str("state") != "done" || st.num("failed") != 0 {
		t.Errorf("state = %v, want done with nothing failed", st)
	}
	if n := deferredOf(t, x.h, "sensitive-paths"); n != 5 {
		t.Errorf("deferred = %d, want 5", n)
	}
	if got := col(current(x.rows("risk-sensitive-paths.csv")), "path"); !slices.Equal(got, []string{"/high-one", "/high-one", "/high-two"}) {
		t.Errorf("hits = %v", got)
	}

	// The next run takes up where this one stopped and repeats nothing: the rest of
	// high-two, then medium on both services; low is still behind them.
	x.mustRun("--crawl-pages", "0", "--sensitive-paths", file, "--sensitive-path-max-requests", "3")
	if total(sites, "/high-two") != 2 || total(sites, "/medium-one") != 2 || total(sites, "/low-one") != 0 {
		t.Errorf("second run (cap 3): high-two %d, medium %d, low %d", total(sites, "/high-two"), total(sites, "/medium-one"), total(sites, "/low-one"))
	}
	if n := deferredOf(t, x.h, "sensitive-paths"); n != 2 {
		t.Errorf("deferred after the second run = %d, want the 2 low requests", n)
	}
	x.mustRun("--crawl-pages", "0", "--sensitive-paths", file)
	for _, p := range []string{"/high-one", "/high-two", "/medium-one", "/low-one"} {
		if total(sites, p) != 2 {
			t.Errorf("%s requested %d times in all, want once per service", p, total(sites, p))
		}
	}
	if n := deferredOf(t, x.h, "sensitive-paths"); n != 0 {
		t.Errorf("deferred after the last run = %d", n)
	}
}

// A hit from an earlier run stays current in a run that defers other
// requests, even a redo that repeats only the first of them.
func TestListsSensitive_EarlierHitStaysCurrentWhenDeferring(t *testing.T) {
	x := newRisk(t, "sensitive-paths")
	x.names("www.example.com")
	x.host("www.example.com", "203.0.113.5")
	s := x.plain("203.0.113.5", 80, leaky)
	file := x.pathsFile(pathsYAML)
	x.mustRun("--crawl-pages", "0", "--sensitive-paths", file)
	if got := col(current(x.rows("risk-sensitive-paths.csv")), "path"); len(got) != 3 {
		t.Fatalf("setup: hits = %v", got)
	}

	x.mustRun("--crawl-pages", "0", "--sensitive-paths", file, "--redo", "sensitive-paths", "--sensitive-path-max-requests", "1")
	if s.count("/.git/config") != 2 || s.count("/.env") != 1 || s.count("/backup.gz") != 1 {
		t.Errorf("requests: .git/config %d, .env %d, backup.gz %d; only the high-severity path should be repeated",
			s.count("/.git/config"), s.count("/.env"), s.count("/backup.gz"))
	}
	if got := col(current(x.rows("risk-sensitive-paths.csv")), "path"); !slices.Equal(got, []string{"/.env", "/.git/config", "/backup.gz"}) {
		t.Errorf("hits after the deferring run = %v\n%s", got, x.file(eng, "risk-sensitive-paths.csv"))
	}
	if got := x.summaryTargets(); len(got) != 3 {
		t.Errorf("summary = %v, want the three earlier findings still reported", got)
	}
	if n := deferredOf(t, x.h, "sensitive-paths"); n != 2 {
		t.Errorf("deferred = %d, want 2", n)
	}
}

// Both the console summary and the --json summary give the deferred count.
func TestListsSensitive_ConsoleCount(t *testing.T) {
	x, _ := twoServices(t)
	x.fill()
	file := x.pathsFile(tierPathsYAML)
	code := x.h.exec("--authorised", "--rate-per-host", "1000", "--rate-per-source", "1000", "--rate-dns", "100000",
		"--no-permutations", "--crawl-pages", "0", "--sensitive-paths", file, "--sensitive-path-max-requests", "3", "example.com")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, x.h.stdout.String())
	}
	if block := deferredBlock(t, x.h.stdout.String()); !strings.Contains(block, "sensitive-paths") || !strings.Contains(block, "5") {
		t.Errorf("block does not give the stage and the count of 5:\n%s", block)
	}
}

func TestListsSensitive_InvalidCapExits2(t *testing.T) {
	x, sites := twoServices(t)
	if code := x.run("--sensitive-paths", x.pathsFile(tierPathsYAML), "--sensitive-path-max-requests", "0"); code != 2 {
		t.Errorf("exit %d, want 2", code)
	}
	if !strings.Contains(x.h.stdout.String(), "sensitive_path_max_requests") {
		t.Errorf("the error does not name the setting:\n%s", x.h.stdout.String())
	}
	if total(sites, "/high-one") != 0 {
		t.Error("nothing may be requested after a validation error")
	}
}

// After an upgrade the paths that were already checked are not requested
// again: only the entries the new list adds are.
func TestListsSensitive_UpgradeRequestsOnlyNewEntries(t *testing.T) {
	x, sites := twoServices(t)
	before := `
- path: /high-one
  signature: 'HIGH'
  severity: high
- path: /low-one
  signature: 'LOW'
  severity: low
`
	x.mustRun("--crawl-pages", "0", "--sensitive-paths", x.pathsFile(before))
	x.mustRun("--crawl-pages", "0", "--sensitive-paths", x.pathsFile(tierPathsYAML))
	for p, want := range map[string]int{"/high-one": 2, "/low-one": 2, "/medium-one": 2, "/high-two": 2} {
		if got := total(sites, p); got != want {
			t.Errorf("%s requested %d times in all, want %d (once per service)", p, got, want)
		}
	}
	if got := col(current(x.rows("risk-sensitive-paths.csv")), "path"); len(got) != 8 {
		t.Errorf("hits = %v, want all eight current", got)
	}
}
