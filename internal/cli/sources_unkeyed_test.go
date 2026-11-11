package cli_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/testkit"
)

// unkeyedSource describes one of the five sources that need no key: the answers
// it gives and the names its good answer must yield.
type unkeyedSource struct {
	stage, host string
	// ok holds the names in names plus noise that must not be recorded: a name
	// outside the root, an address and a URL.
	ok    string
	names []string
	// empty is a well-formed answer with no names; bad is an answer of the wrong shape.
	empty, bad string
	// checkKey is the key of the one check a run for example.com completes.
	checkKey string
}

var unkeyedSources = []unkeyedSource{
	{
		stage: "otx", host: "otx.alienvault.com", checkKey: "example.com",
		ok: `{"passive_dns":[
			{"hostname":"otx.example.com","address":"198.51.100.7"},
			{"hostname":"off.example.org","address":"198.51.100.8"},
			{"hostname":"198.51.100.9","address":"198.51.100.9"},
			{"hostname":"https://url.example.com/x","address":"198.51.100.10"}]}`,
		names: []string{"otx.example.com"},
		empty: `{"passive_dns":[]}`,
		bad:   `{"error":"nope"}`,
	},
	{
		stage: "hackertarget", host: "api.hackertarget.com", checkKey: "example.com",
		ok: "ht.example.com,198.51.100.7\noff.example.org,198.51.100.8\n198.51.100.9,198.51.100.9\n" +
			"https://url.example.com/x,198.51.100.10\n",
		names: []string{"ht.example.com"},
		empty: "No records found",
		bad:   "<html>oops</html>",
	},
	{
		stage: "urlscan", host: "urlscan.io", checkKey: "example.com",
		ok: `{"results":[
			{"page":{"domain":"us.example.com","url":"https://url.example.com/login","ip":"198.51.100.7"},"task":{"domain":"us2.example.com"}},
			{"page":{"domain":"off.example.org"},"task":{"domain":"198.51.100.9"}}]}`,
		names: []string{"us.example.com", "us2.example.com"},
		empty: `{"results":[],"total":0}`,
		bad:   `{"message":"nope"}`,
	},
	{
		stage: "anubis", host: "jldc.me", checkKey: "example.com",
		ok:    `["an.example.com","off.example.org","198.51.100.9","https://url.example.com/x"]`,
		names: []string{"an.example.com"},
		empty: `[]`,
		bad:   `{"error":"nope"}`,
	},
	{
		stage: "certspotter", host: "api.certspotter.com", checkKey: "example.com|pages=10",
		ok:    `[{"id":"1","dns_names":["cs.example.com","*.wild.example.com","off.example.org","198.51.100.9","https://url.example.com/x"]}]`,
		names: []string{"cs.example.com", "wild.example.com"},
		empty: `[]`,
		bad:   `{"error":"nope"}`,
	},
}

// serve answers with body. Cert Spotter is paged by after=<id>, so every page
// after the first is empty.
func (s unkeyedSource) serve(w *world, body string) {
	w.handle(s.host, func(rw http.ResponseWriter, r *http.Request) {
		if s.stage == "certspotter" && r.URL.Query().Get("after") != "" {
			_, _ = rw.Write([]byte("[]"))
			return
		}
		_, _ = rw.Write([]byte(body))
	})
}

// forEachUnkeyed runs fn as a subtest with a fresh world for each source.
func forEachUnkeyed(t *testing.T, fn func(t *testing.T, w *world, s unkeyedSource)) {
	t.Helper()
	for _, s := range unkeyedSources {
		t.Run(s.stage, func(t *testing.T) { fn(t, newWorld(t), s) })
	}
}

// messages returns the message of each event of type typ, from the last run,
// that contains containing.
func messages(w *world, typ, containing string) []string {
	var out []string
	for _, e := range ofType(w.h.events(), typ) {
		if m := e.str("message"); strings.Contains(m, containing) {
			out = append(out, m)
		}
	}
	return out
}

func TestUnkeyed_NamesAreRecorded(t *testing.T) {
	forEachUnkeyed(t, func(t *testing.T, w *world, s unkeyedSource) {
		s.serve(w, s.ok)
		for _, n := range s.names {
			w.dns.A(n, "203.0.113.5")
		}
		if code := w.run("--passive", "example.com"); code != 0 {
			t.Fatalf("exit %d", code)
		}
		got := w.lines(eng, "subdomains.txt")
		for _, n := range s.names {
			if !slices.Contains(got, n) {
				t.Errorf("subdomains.txt missing %s: %v", n, got)
			}
		}
		recorded := w.obsAttrs(eng, "hostname")
		for _, noise := range []string{"off.example.org", "198.51.100.9", "url.example.com", "https://url.example.com/x", "198.51.100.7"} {
			if _, ok := recorded[noise]; ok {
				t.Errorf("%q must not be recorded as a hostname", noise)
			}
		}
		if st, _ := stateOf(w, s.stage); st != "done" {
			t.Errorf("%s state = %s, want done", s.stage, st)
		}
		if done := w.h.completed(eng, s.stage); !slices.Equal(done, []string{s.checkKey}) {
			t.Errorf("completed checks = %v, want the root's check %q", done, s.checkKey)
		}
		if reqs := w.requests(s.host); len(reqs) == 0 || reqs[0].Method != "GET" || !strings.Contains(reqs[0].URI, "example.com") {
			t.Errorf("requests = %+v, want a GET naming the root", reqs)
		}
	})
}

// A root that is not in scope is not queried, for the new sources and the old.
func TestUnkeyed_ExcludedRootIsNotQueried(t *testing.T) {
	w := newWorld(t)
	for _, s := range unkeyedSources {
		s.serve(w, s.ok)
	}
	w.crtsh(map[string][]string{"example.com": {"a.example.com"}, "example.org": {"b.example.org"}}, nil)
	if code := w.run("--passive", "-x", "example.org", "example.com", "example.org"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, host := range []string{"otx.alienvault.com", "api.hackertarget.com", "urlscan.io", "jldc.me", "api.certspotter.com", "crt.sh"} {
		for _, r := range w.requests(host) {
			if strings.Contains(r.URI, "example.org") {
				t.Errorf("%s was asked about the excluded root: %s", host, r.URI)
			}
		}
		if len(w.requests(host)) == 0 {
			t.Errorf("%s was never queried for the in-scope root", host)
		}
	}
}

// Scope decides which file a returned name appears in.
func TestUnkeyed_ScopeDecidesTheFile(t *testing.T) {
	w := newWorld(t)
	w.handle("otx.alienvault.com", jsonBody(`{"passive_dns":[
		{"hostname":"junk1.example.com"},{"hostname":"junk2.example.com"},
		{"hostname":"real.example.com"},{"hostname":"ex.example.com"}]}`))
	w.dns.Wildcard("example.com", "203.0.113.1", "203.0.113.2")
	w.dns.A("real.example.com", "203.0.113.50")
	w.dns.A("ex.example.com", "203.0.113.51")
	for _, a := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.50", "203.0.113.51"} {
		w.owner(a, 64500, "ACME-NET")
	}
	if code := w.run("--passive", "--no-permutations", "-x", "ex.example.com", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got := w.lines(eng, "subdomains.txt"); !slices.Contains(got, "real.example.com") || slices.Contains(got, "ex.example.com") || slices.Contains(got, "junk1.example.com") {
		t.Errorf("subdomains.txt = %v", got)
	}
	if got := w.lines(eng, "wildcard-excluded.txt"); !slices.Equal(got, []string{"junk1.example.com", "junk2.example.com"}) {
		t.Errorf("wildcard-excluded.txt = %v", got)
	}
	if find(w.table(eng, "excluded.csv"), "value", "ex.example.com") == nil {
		t.Errorf("excluded.csv = %s", w.file(eng, "excluded.csv"))
	}
}

func TestUnkeyed_NamesAreNormalised(t *testing.T) {
	w := newWorld(t)
	// crt.sh and a new source both give a wildcard; the new source also gives
	// upper case, a trailing dot, a Unicode name and one that is not a hostname.
	w.crtsh(map[string][]string{"example.com": {"*.dev.example.com"}}, nil)
	w.handle("jldc.me", jsonBody(`["*.stage.example.com","UP.Example.com.","Bücher.example.com","under_score.example.com","sp ace.example.com"]`))
	resolveAll(w, "dev", "stage", "up", "xn--bcher-kva")
	if code := w.run("--passive", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	got := w.lines(eng, "subdomains.txt")
	for _, want := range []string{"dev.example.com", "stage.example.com", "up.example.com", "xn--bcher-kva.example.com"} {
		if !slices.Contains(got, want) {
			t.Errorf("subdomains.txt missing %s: %v", want, got)
		}
	}
	for k := range w.obsAttrs(eng, "hostname") {
		if strings.ContainsAny(k, "*_ üA") || strings.HasSuffix(k, ".") {
			t.Errorf("hostname %q was not normalised or should have been dropped", k)
		}
	}
}

// HackerTarget's two "nothing found" answers, and an empty body (no lines),
// complete the check without retry.
func TestUnkeyed_HackerTargetEmptyBodies(t *testing.T) {
	for _, body := range []string{"No records found", "error check your search parameter", ""} {
		t.Run(body, func(t *testing.T) {
			w := newWorld(t)
			w.handle("api.hackertarget.com", jsonBody(body))
			if code := w.run("--passive", "example.com"); code != 0 {
				t.Fatalf("exit %d", code)
			}
			if st, _ := stateOf(w, "hackertarget"); st != "done" {
				t.Errorf("state = %s, want done", st)
			}
			if done := w.h.completed(eng, "hackertarget"); !slices.Equal(done, []string{"example.com"}) {
				t.Errorf("completed = %v", done)
			}
			before := len(w.requests("api.hackertarget.com"))
			w.run("--passive", "example.com")
			if after := len(w.requests("api.hackertarget.com")); after != before {
				t.Errorf("an empty answer must not be retried: %d requests, then %d", before, after)
			}
		})
	}
}

// A spent quota stops that stage alone: one warning, the checks fail and are retried.
func TestUnkeyed_QuotaSpentAbortsOnlyThatStage(t *testing.T) {
	type variant struct {
		name  string
		serve func(w *world, s unkeyedSource)
		only  string // restrict to one stage
	}
	variants := []variant{
		{name: "HTTP 429", serve: func(w *world, s unkeyedSource) { w.handle(s.host, status(429)) }},
		{name: "API count exceeded", only: "hackertarget", serve: func(w *world, s unkeyedSource) {
			w.handle(s.host, jsonBody("API count exceeded - Increase Quota with Membership"))
		}},
	}
	for _, v := range variants {
		for _, s := range unkeyedSources {
			if v.only != "" && v.only != s.stage {
				continue
			}
			t.Run(v.name+"/"+s.stage, func(t *testing.T) {
				w := newWorld(t)
				v.serve(w, s)
				w.crtsh(map[string][]string{"example.com": {"c.example.com"}}, nil)
				w.dns.A("c.example.com", "203.0.113.5")
				if code := w.run("--passive", "--verbose", "--concurrency", "1", "example.com", "example.org"); code != 0 {
					t.Fatalf("exit %d", code)
				}
				if st, _ := stateOf(w, s.stage); st != "failed" {
					t.Errorf("state = %s, want failed", st)
				}
				if done := w.h.completed(eng, s.stage); len(done) != 0 {
					t.Errorf("a spent quota must not be recorded as done: %v", done)
				}
				if n := len(w.requests(s.host)); n != 1 {
					t.Errorf("the stage should stop after the first answer, saw %d requests", n)
				}
				warns := messages(w, "warning", s.stage)
				if len(warns) != 1 || !strings.Contains(warns[0], "quota") || !strings.Contains(warns[0], "retried next run") {
					t.Errorf("want one quota warning naming %s, got %q", s.stage, warns)
				}
				if st, _ := stateOf(w, "crtsh"); st != "done" {
					t.Errorf("other stages must be unaffected: crtsh = %s", st)
				}
				if !slices.Contains(w.lines(eng, "subdomains.txt"), "c.example.com") {
					t.Errorf("other sources' names must still be recorded: %v", w.lines(eng, "subdomains.txt"))
				}

				// Without --verbose there is no warning at all.
				w.run("--passive", "--concurrency", "1", "--redo", s.stage, "example.com", "example.org")
				if warns := ofType(w.h.events(), "warning"); len(warns) != 0 {
					t.Errorf("warnings without --verbose: %v", warns)
				}

				// The next run retries every check.
				s.serve(w, s.ok)
				if code := w.run("--passive", "example.com", "example.org"); code != 0 {
					t.Fatalf("exit %d", code)
				}
				if done := w.h.completed(eng, s.stage); len(done) != 2 {
					t.Errorf("both roots should complete on the next run: %v", done)
				}
				if got := w.lines(eng, "subdomains.txt"); !slices.Contains(got, s.names[0]) {
					t.Errorf("subdomains.txt missing %s after the retry: %v", s.names[0], got)
				}
			})
		}
	}
}

// A runner-level check of the abort warning, independent of any source.
func TestRunner_QuotaAbortWarnsOnce(t *testing.T) {
	if !errors.Is(run.ErrQuota, run.ErrAbortStage) {
		t.Error("ErrQuota must be an abort of the stage")
	}
	run.Warnf(context.Background(), "with no warner this does nothing %d", 1)

	st := &testkit.Stage{StageName: "quota", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check { return testkit.Keys("c", 4) },
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			run.Warnf(ctx, "inside %s", c.Key)
			return nil, fmt.Errorf("HTTP 429: %w", run.ErrQuota)
		}}
	h := newHarness(t, st)
	if code := h.exec("a.com", "--json", "--verbose", "--concurrency", "1"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	var inside, abort []string
	for _, e := range ofType(h.events(), "warning") {
		m := e.str("message")
		switch {
		case strings.Contains(m, "inside"):
			inside = append(inside, m)
		case strings.Contains(m, "quota"):
			abort = append(abort, m)
		}
	}
	if len(inside) != 1 {
		t.Errorf("a Warnf inside Run is shown under --verbose: %v", inside)
	}
	if want := "quota: quota spent or key rejected; 4 checks will be retried next run"; len(abort) != 1 || abort[0] != want {
		t.Errorf("abort warnings = %q, want one %q", abort, want)
	}
	if s := lastState(h.events(), "quota"); s.str("state") != "failed" || s.num("failed") != 4 {
		t.Errorf("state = %v", s)
	}

	// Not verbose: Warnf is silent too.
	h2 := newHarness(t, st)
	h2.exec("a.com", "--json", "--concurrency", "1")
	if w := ofType(h2.events(), "warning"); len(w) != 0 {
		t.Errorf("warnings without --verbose: %v", w)
	}
}

func TestUnkeyed_NotFoundIsEmpty(t *testing.T) {
	forEachUnkeyed(t, func(t *testing.T, w *world, s unkeyedSource) {
		w.handle(s.host, status(404))
		if code := w.run("--passive", "example.com"); code != 0 {
			t.Fatalf("exit %d", code)
		}
		if st, _ := stateOf(w, s.stage); st != "done" {
			t.Errorf("state = %s, want done", st)
		}
		if done := w.h.completed(eng, s.stage); !slices.Equal(done, []string{s.checkKey}) {
			t.Errorf("a 404 completes the check: %v", done)
		}
		s.serve(w, s.empty)
		w.run("--passive", "--redo", s.stage, "example.com")
		if st, _ := stateOf(w, s.stage); st != "done" {
			t.Errorf("a well-formed empty answer: state = %s, want done", st)
		}
	})
}

// A wrong-shaped body, a server error and an oversized body are transient: the
// check is not recorded, and the next run retries it.
func TestUnkeyed_TransientFailuresAreRetried(t *testing.T) {
	oversize := func(s unkeyedSource) http.HandlerFunc {
		return func(rw http.ResponseWriter, r *http.Request) {
			_, _ = rw.Write([]byte(s.ok))
			_, _ = rw.Write([]byte(strings.Repeat(" ", 10<<20+1000)))
		}
	}
	for _, s := range unkeyedSources {
		for _, v := range []struct {
			name  string
			serve func(w *world)
		}{
			{"wrong shape", func(w *world) { s.serve(w, s.bad) }},
			{"HTTP 500", func(w *world) { w.handle(s.host, status(500)) }},
			{"oversized", func(w *world) { w.handle(s.host, oversize(s)) }},
		} {
			t.Run(s.stage+"/"+v.name, func(t *testing.T) {
				w := newWorld(t)
				v.serve(w)
				for _, n := range s.names {
					w.dns.A(n, "203.0.113.5")
				}
				if code := w.run("--passive", "example.com"); code != 0 {
					t.Fatalf("exit %d", code)
				}
				if st, _ := stateOf(w, s.stage); st != "failed" {
					t.Errorf("state = %s, want failed", st)
				}
				if done := w.h.completed(eng, s.stage); len(done) != 0 {
					t.Errorf("must not be recorded as done: %v", done)
				}
				s.serve(w, s.ok)
				w.run("--passive", "example.com")
				if done := w.h.completed(eng, s.stage); !slices.Equal(done, []string{s.checkKey}) {
					t.Errorf("retry should complete: %v", done)
				}
				if got := w.lines(eng, "subdomains.txt"); !slices.Contains(got, s.names[0]) {
					t.Errorf("subdomains.txt missing %s after the retry: %v", s.names[0], got)
				}
			})
		}
	}
}

// Get is unchanged: a 429 from one range publisher fails that list's check and
// does not abort providerranges.
func TestGet_RangePublisher429StaysAFailedCheck(t *testing.T) {
	w := newWorld(t)
	w.handle("ip-ranges.amazonaws.com", status(429))
	w.handle("www.gstatic.com", jsonBody(`{"prefixes":[{"ipv4Prefix":"100.64.0.0/16","service":"Google Cloud","scope":"europe-west1"}]}`))
	if code := w.run("--passive", "--concurrency", "1", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got := w.h.completed(eng, "providerranges"); !slices.Equal(got, []string{"gcp"}) {
		t.Errorf("completed = %v, want only the list that answered", got)
	}
	if n := len(w.requests("www.gstatic.com")); n != 1 {
		t.Errorf("the other publisher must still be asked: %d requests", n)
	}
	if s := lastState(w.h.events(), "providerranges"); s.str("state") != "done" || s.num("failed") != 1 {
		t.Errorf("state = %v", s)
	}
}

// Re-running an engagement made before these sources existed does not repeat
// the old sources' checks and resolves only the names the new ones add.
func TestUnkeyed_RerunResolvesOnlyAddedNames(t *testing.T) {
	w := newWorld(t)
	w.crtsh(map[string][]string{"example.com": {"old.example.com"}}, nil)
	w.dns.A("old.example.com", "203.0.113.5")
	w.dns.A("new.example.com", "203.0.113.6")
	w.handle("otx.alienvault.com", jsonBody(`{"passive_dns":[{"hostname":"new.example.com"},{"hostname":"old.example.com"}]}`))
	var skipNew []string
	for _, s := range unkeyedSources {
		skipNew = append(skipNew, "--skip", s.stage)
	}
	if code := w.run(append([]string{"--passive", "--no-permutations"}, append(skipNew, "example.com")...)...); code != 0 {
		t.Fatalf("exit %d", code)
	}
	crtBefore := len(w.requests("crt.sh"))
	oldBefore, rootBefore := w.dns.Count("old.example.com", "A"), w.dns.Count("example.com", "A")
	if crtBefore == 0 || oldBefore == 0 {
		t.Fatalf("first run did nothing: %d crt.sh requests, %d lookups", crtBefore, oldBefore)
	}
	if n := len(w.requests("otx.alienvault.com")); n != 0 {
		t.Fatalf("skipped stage made %d requests", n)
	}

	if code := w.run("--passive", "--no-permutations", "-e", eng); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if n := len(w.requests("crt.sh")); n != crtBefore {
		t.Errorf("crtsh repeated its check: %d requests, then %d", crtBefore, n)
	}
	if n := len(w.requests("otx.alienvault.com")); n != 1 {
		t.Errorf("otx should run once: %d requests", n)
	}
	if w.dns.Count("new.example.com", "A") == 0 {
		t.Error("the name the new stage added was not resolved")
	}
	if got := w.dns.Count("old.example.com", "A"); got != oldBefore {
		t.Errorf("an existing name was resolved again: %d lookups, then %d", oldBefore, got)
	}
	if got := w.dns.Count("example.com", "A"); got != rootBefore {
		t.Errorf("the root was resolved again: %d lookups, then %d", rootBefore, got)
	}
	if !slices.Contains(w.lines(eng, "subdomains.txt"), "new.example.com") {
		t.Errorf("subdomains.txt = %v", w.lines(eng, "subdomains.txt"))
	}
}

func TestUnkeyed_HelpAndRedo(t *testing.T) {
	w := newWorld(t)
	w.h.exec("--help")
	help := w.h.stdout.String()
	for _, s := range unkeyedSources {
		if !strings.Contains(help, s.stage) {
			t.Errorf("--help does not list %s", s.stage)
		}
	}
	if !strings.Contains(help, "--skip") {
		t.Error("--help does not describe --skip")
	}

	w.crtsh(map[string][]string{"example.com": {}}, nil) // the default 404 would fail, and so repeat, crtsh
	if code := w.run("--passive", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	otx, crt := len(w.requests("otx.alienvault.com")), len(w.requests("crt.sh"))
	if code := w.run("--passive", "--redo", "otx", "-e", eng); code != 0 {
		t.Fatalf("--redo otx exited %d", code)
	}
	if n := len(w.requests("otx.alienvault.com")); n != otx+1 {
		t.Errorf("--redo otx should repeat the check: %d requests, then %d", otx, n)
	}
	if n := len(w.requests("crt.sh")); n != crt {
		t.Errorf("--redo otx repeated crtsh: %d requests, then %d", crt, n)
	}
}

// --- Cert Spotter ---

const certspotterKey = "cs-SECRET-key"

// certspotterPages serves three pages of issuances, paged by after=<last id>.
func certspotterPages(w *world, ok func(r *http.Request) bool) {
	pages := map[string]string{
		"":  `[{"id":"1","dns_names":["p1.example.com"]},{"id":"2","dns_names":["p1b.example.com"]}]`,
		"2": `[{"id":"3","dns_names":["p2.example.com"]}]`,
		"3": `[{"id":"4","dns_names":["p3.example.com"]}]`,
	}
	w.handle("api.certspotter.com", func(rw http.ResponseWriter, r *http.Request) {
		if !ok(r) {
			http.Error(rw, "no", http.StatusInternalServerError)
			return
		}
		body, found := pages[r.URL.Query().Get("after")]
		if !found {
			body = "[]"
		}
		_, _ = rw.Write([]byte(body))
	})
}

func always(*http.Request) bool { return true }

func resolveAll(w *world, names ...string) {
	for _, n := range names {
		w.dns.A(n+".example.com", "203.0.113.5")
	}
}

func TestCertSpotter_UnkeyedSendsNoCredentials(t *testing.T) {
	w := newWorld(t)
	certspotterPages(w, always)
	resolveAll(w, "p1", "p1b", "p2", "p3")
	if code := w.run("--passive", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if st, reason := stateOf(w, "certspotter"); st != "done" {
		t.Errorf("certspotter = %s (%s): it runs without a key", st, reason)
	}
	reqs := w.requests("api.certspotter.com")
	if len(reqs) != 4 {
		t.Errorf("want 3 pages and the empty page that ends them, got %d requests", len(reqs))
	}
	for _, r := range reqs {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("unkeyed request sent Authorization: %q", r.Header.Get("Authorization"))
		}
		if !strings.Contains(r.URI, "domain=example.com") {
			t.Errorf("request does not name the root: %s", r.URI)
		}
	}
	for _, n := range []string{"p1", "p1b", "p2", "p3"} {
		if !slices.Contains(w.lines(eng, "subdomains.txt"), n+".example.com") {
			t.Errorf("subdomains.txt missing %s: %v", n, w.lines(eng, "subdomains.txt"))
		}
	}
}

func TestCertSpotter_KeySentAndNeverShown(t *testing.T) {
	w := newWorld(t)
	t.Setenv("RECON_KEYS_CERTSPOTTER", certspotterKey)
	certspotterPages(w, func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer "+certspotterKey })
	resolveAll(w, "p1")
	if code := w.run("--passive", "--verbose", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if st, _ := stateOf(w, "certspotter"); st != "done" {
		t.Errorf("state = %s, want done", st)
	}
	if !slices.Contains(w.lines(eng, "subdomains.txt"), "p1.example.com") {
		t.Errorf("subdomains.txt = %v", w.lines(eng, "subdomains.txt"))
	}
	if hits := w.anywhere(eng, certspotterKey); len(hits) > 0 {
		t.Errorf("key leaked into %v", hits)
	}
}

// A rejected key stops the stage like a spent quota, and is not retried within
// the run.
func TestCertSpotter_RejectedKeyAborts(t *testing.T) {
	for _, code := range []int{401, 403} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			w := newWorld(t)
			t.Setenv("RECON_KEYS_CERTSPOTTER", certspotterKey)
			w.handle("api.certspotter.com", status(code))
			if c := w.run("--passive", "--verbose", "--concurrency", "1", "example.com", "example.org"); c != 0 {
				t.Fatalf("exit %d", c)
			}
			if st, _ := stateOf(w, "certspotter"); st != "failed" {
				t.Errorf("state = %s, want failed", st)
			}
			if n := len(w.requests("api.certspotter.com")); n != 1 {
				t.Errorf("the stage should stop after the rejection, saw %d requests", n)
			}
			if warns := messages(w, "warning", "certspotter"); len(warns) != 1 {
				t.Errorf("want one warning, got %q", warns)
			}
			if hits := w.anywhere(eng, certspotterKey); len(hits) > 0 {
				t.Errorf("key leaked into %v", hits)
			}
		})
	}
}

// A key added after checks failed applies to the checks not yet done, and the
// key is not part of the check, so --redo is only needed for the finished ones.
func TestCertSpotter_KeyAddedLaterAppliesToPendingChecks(t *testing.T) {
	w := newWorld(t)
	certspotterPages(w, func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer "+certspotterKey })
	resolveAll(w, "p1")
	if code := w.run("--passive", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if st, _ := stateOf(w, "certspotter"); st != "failed" {
		t.Fatalf("without the key the server refuses: state = %s", st)
	}
	t.Setenv("RECON_KEYS_CERTSPOTTER", certspotterKey)
	if code := w.run("--passive", "--verbose", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if done := w.h.completed(eng, "certspotter"); !slices.Equal(done, []string{"example.com|pages=10"}) {
		t.Errorf("completed = %v: the key must not change the check's key", done)
	}
	if !slices.Contains(w.lines(eng, "subdomains.txt"), "p1.example.com") {
		t.Errorf("subdomains.txt = %v", w.lines(eng, "subdomains.txt"))
	}
	before := len(w.requests("api.certspotter.com"))
	w.run("--passive", "example.com")
	if n := len(w.requests("api.certspotter.com")); n != before {
		t.Errorf("a finished check was repeated: %d requests, then %d", before, n)
	}
	w.run("--passive", "--redo", "certspotter", "-e", eng)
	if n := len(w.requests("api.certspotter.com")); n <= before {
		t.Errorf("--redo certspotter did not repeat the check: %d requests, then %d", before, n)
	}
	if hits := w.anywhere(eng, certspotterKey); len(hits) > 0 {
		t.Errorf("key leaked into %v", hits)
	}
}

// Paging stops at certspotter.max_pages with a warning; the cap is part of the
// check, so raising it repeats the check.
func TestCertSpotter_PageCap(t *testing.T) {
	w := newWorld(t)
	certspotterPages(w, always)
	resolveAll(w, "p1", "p1b", "p2", "p3")
	if code := w.run("--passive", "--no-permutations", "--verbose", "--certspotter-max-pages", "2", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if st, _ := stateOf(w, "certspotter"); st != "done" {
		t.Errorf("reaching the cap completes the check: state = %s", st)
	}
	if done := w.h.completed(eng, "certspotter"); !slices.Equal(done, []string{"example.com|pages=2"}) {
		t.Errorf("completed = %v", done)
	}
	if n := len(w.requests("api.certspotter.com")); n != 2 {
		t.Errorf("want exactly 2 pages requested, got %d", n)
	}
	got := w.lines(eng, "subdomains.txt")
	if !slices.Contains(got, "p2.example.com") || slices.Contains(got, "p3.example.com") {
		t.Errorf("subdomains.txt = %v, want the first two pages only", got)
	}
	if warns := messages(w, "warning", "certspotter"); len(warns) != 1 || !strings.Contains(warns[0], "truncated") {
		t.Errorf("want one truncation warning, got %q", warns)
	}

	// Raising the cap makes a new check, and the longer result is not truncated.
	if code := w.run("--passive", "--no-permutations", "--verbose", "-e", eng); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if done := w.h.completed(eng, "certspotter"); !slices.Equal(done, []string{"example.com|pages=10", "example.com|pages=2"}) {
		t.Errorf("completed = %v, want a new check for the new cap", done)
	}
	if !slices.Contains(w.lines(eng, "subdomains.txt"), "p3.example.com") {
		t.Errorf("subdomains.txt = %v", w.lines(eng, "subdomains.txt"))
	}
	if warns := messages(w, "warning", "truncated"); len(warns) != 0 {
		t.Errorf("an untruncated result must not warn: %q", warns)
	}
}

func TestCertSpotter_MaxPagesMustBePositive(t *testing.T) {
	w := newWorld(t)
	if code := w.run("--passive", "--certspotter-max-pages", "0", "example.com"); code != 2 {
		t.Errorf("exit %d, want 2", code)
	}
	if n := len(w.requests("api.certspotter.com")); n != 0 {
		t.Errorf("an invalid setting must not reach the network: %d requests", n)
	}
}

// --- README ---

func TestReadme_NamesTheNewSources(t *testing.T) {
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(b)
	start := strings.Index(readme, "## Passive boundary")
	end := strings.Index(readme[start+1:], "\n## ")
	if start < 0 || end < 0 {
		t.Fatal("README has no Passive boundary section")
	}
	section := strings.ToLower(readme[start : start+1+end])
	for _, src := range []string{"alienvault otx", "hackertarget", "urlscan", "anubis", "cert spotter"} {
		if !strings.Contains(section, src) {
			t.Errorf("the passive-boundary section does not name %q", src)
		}
	}
	// The bullet may wrap onto indented continuation lines.
	var keyed string
	in := false
	for line := range strings.SplitSeq(readme, "\n") {
		switch {
		case strings.HasPrefix(line, "- **Keyed sources:**"):
			in, keyed = true, line
		case in && strings.HasPrefix(line, "  "):
			keyed += " " + strings.TrimSpace(line)
		default:
			in = false
		}
	}
	if !strings.Contains(keyed, "certspotter") || !strings.Contains(keyed, "optional") {
		t.Errorf("the keyed-sources entry must name certspotter as optional: %q", keyed)
	}
	if !strings.Contains(readme, "--skip") {
		t.Error("README does not document --skip")
	}
}

// urlscan reads one page of results; it says so when the answer has more. The
// live service reports total beyond the page with has_more false.
func TestUrlscan_WarnsWhenResultsAreCutShort(t *testing.T) {
	const one = `"results":[{"page":{"domain":"us.example.com"},"task":{}}]`
	cases := []struct {
		name, body string
		warns      bool
	}{
		{"has_more", `{` + one + `,"has_more":true}`, true},
		{"total beyond the page", `{` + one + `,"total":7957,"has_more":false}`, true},
		{"complete", `{` + one + `,"total":1,"has_more":false}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			w.handle("urlscan.io", jsonBody(c.body))
			w.dns.A("us.example.com", "203.0.113.5")
			if code := w.run("--passive", "--verbose", "example.com"); code != 0 {
				t.Fatalf("exit %d", code)
			}
			if st, _ := stateOf(w, "urlscan"); st != "done" {
				t.Errorf("state = %s, want done", st)
			}
			if warns := messages(w, "warning", "urlscan"); (len(warns) == 1) != c.warns || len(warns) > 1 {
				t.Errorf("warnings = %q, want warning: %v", warns, c.warns)
			}
		})
	}
}
