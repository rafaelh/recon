package cli_test

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/engagement"
	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/testkit"
)

func noop() *testkit.Stage { return &testkit.Stage{StageName: "noop", Kind: run.ThirdParty} }

func obs(kind, key string, kv ...any) run.Observation {
	a := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		a[kv[i].(string)] = kv[i+1]
	}
	return run.Observation{Kind: kind, Key: key, Attrs: a}
}

func csvRows(t *testing.T, body string) [][]string {
	t.Helper()
	r, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("csv: %v\n%s", err, body)
	}
	return r
}

func hasRow(rows [][]string, cells ...string) bool {
outer:
	for _, r := range rows {
		if len(r) < len(cells) {
			continue
		}
		for i, c := range cells {
			if r[i] != c {
				continue outer
			}
		}
		return true
	}
	return false
}

// B1: every input form is stored; files ignore comments and blanks.
func TestInputsStored(t *testing.T) {
	h := newHarness(t, noop())
	df := writeFile(t, t.TempDir(), "d.txt", "# comment\n\nfile.example.org\n")
	xf := writeFile(t, t.TempDir(), "x.txt", "# c\n*.dev.example.com\n\n")
	code := h.exec("Example.com", "-d", df, "--org", "Acme Corp", "--asn", "13335", "--cidr", "10.1.2.3/24",
		"-x", "admin.example.com", "--exclude-file", xf)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	cmp := func(kind string, want ...string) {
		t.Helper()
		if got := h.inputs("example.com", kind); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s = %v, want %v", kind, got, want)
		}
	}
	cmp("root", "example.com", "file.example.org")
	cmp("org", "Acme Corp")
	cmp("asn", "AS13335")
	cmp("cidr", "10.1.2.0/24")
	cmp("exclude", "*.dev.example.com", "admin.example.com")
	rows := csvRows(t, h.readOut("example.com", "scope.csv"))
	for _, want := range [][]string{{"root", "example.com"}, {"org", "Acme Corp"}, {"asn", "AS13335"}, {"cidr", "10.1.2.0/24"}} {
		if !hasRow(rows, want...) {
			t.Errorf("scope.csv missing %v:\n%v", want, rows)
		}
	}
}

// B2: engagement naming.
func TestEngagementDirNaming(t *testing.T) {
	h := newHarness(t, noop())
	for _, c := range []struct {
		args []string
		dir  string
	}{
		{[]string{"Example.COM", "other.org"}, "example.com"},
		{[]string{"--org", "Acme Corp, Inc."}, "acme-corp-inc"},
		{[]string{"--asn", "64500"}, "as64500"},
		{[]string{"--cidr", "10.0.0.0/24"}, "10.0.0.0_24"},
		{[]string{"-e", "custom-name", "example.net"}, "custom-name"},
	} {
		if code := h.exec(c.args...); code != 0 {
			t.Fatalf("%v: exit %d %s", c.args, code, h.stderr.String())
		}
		if st, err := os.Stat(h.eng(c.dir)); err != nil || !st.IsDir() {
			t.Errorf("%v: expected dir %s", c.args, c.dir)
		}
	}
	for _, bad := range []string{"../x", "a/b", "UPPER", ".hid"} {
		if code := h.exec("-e", bad, "example.com"); code != 2 || !strings.Contains(h.stderr.String(), bad) {
			t.Errorf("-e %s: exit %d, stderr %q", bad, code, h.stderr.String())
		}
	}
	if _, err := os.Stat(filepath.Join(h.out, "x")); err == nil {
		t.Error("traversal created a directory")
	}
}

func TestNoInputsAndNoEngagement(t *testing.T) {
	h := newHarness(t, noop())
	if code := h.exec(); code != 2 {
		t.Errorf("no inputs: exit %d", code)
	}
}

// B2/B5/B10: help.
func TestHelp(t *testing.T) {
	st := &testkit.Stage{StageName: "alpha", Kind: run.ThirdParty}
	h := newHarness(t, st, &testkit.Stage{StageName: "beta", Kind: run.ThirdParty})
	if code := h.exec("--help"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	help := h.stdout.String()
	for _, w := range []string{
		"--ports", "21-23", "--risky-ports", "21,23,445,1433", "--concurrency", "10", "--rate-per-host", "--rate-per-source", "--rate-dns", "50",
		"--crawl-depth", "--crawl-pages", "100", "--output-dir", "--netblock-limit", "4096", "--wordlist", "--sensitive-paths", "built-in (0 entries)",
		"config.yaml", ".config/recon", "RECON_", "RECON_KEYS_", "alpha", "beta", "--redo", "order", "--passive", "--authorised", "--json",
	} {
		if !strings.Contains(help, w) {
			t.Errorf("help missing %q", w)
		}
	}
	if strings.Contains(help, "--key") || strings.Contains(help, "--api-key") {
		t.Error("help must not offer key flags")
	}
}

// B3: re-runs add inputs; the engagement name alone resumes; promoted candidates move into scope.
func TestRerunAddsAndResumes(t *testing.T) {
	var gotRoots, gotExcl []string
	st := &testkit.Stage{StageName: "spy", Kind: run.ThirdParty, ChecksFn: func(v run.View) []run.Check {
		in := v.Inputs()
		gotRoots, gotExcl = in.Roots, in.Exclusions
		return nil
	}}
	h := newHarness(t, st)
	if code := h.exec("a.com", "-x", "x.a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if code := h.exec("-e", "a.com", "b.com", "-x", "y.a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if strings.Join(gotRoots, ",") != "a.com,b.com" || strings.Join(gotExcl, ",") != "x.a.com,y.a.com" {
		t.Errorf("after add: %v %v", gotRoots, gotExcl)
	}
	if code := h.exec("-e", "a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if strings.Join(gotRoots, ",") != "a.com,b.com" || strings.Join(gotExcl, ",") != "x.a.com,y.a.com" {
		t.Errorf("resume must keep stored scope: %v %v", gotRoots, gotExcl)
	}
}

func TestPromotedCandidate(t *testing.T) {
	st := &testkit.Stage{StageName: "disc", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check { return testkit.Keys("c", 1) },
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			return []run.Observation{obs("root", "partner.net"), obs("hostname", "www.partner.net")}, nil
		}}
	h := newHarness(t, st)
	if code := h.exec("a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	cand := csvRows(t, h.readOut("a.com", "candidates.csv"))
	if !hasRow(cand, "root", "partner.net") || !hasRow(cand, "hostname", "www.partner.net") {
		t.Fatalf("candidates.csv: %v", cand)
	}
	if code := h.exec("-e", "a.com", "partner.net"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	cand = csvRows(t, h.readOut("a.com", "candidates.csv"))
	if hasRow(cand, "root", "partner.net") || hasRow(cand, "hostname", "www.partner.net") {
		t.Errorf("promoted root and its hosts must leave candidates.csv: %v", cand)
	}
	if !hasRow(csvRows(t, h.readOut("a.com", "scope.csv")), "root", "partner.net") {
		t.Error("promoted root missing from scope.csv")
	}
}

// B4.
func TestNonEngagementDirRefused(t *testing.T) {
	h := newHarness(t, noop())
	legacy := h.eng("legacy")
	os.MkdirAll(legacy, 0o755)
	os.WriteFile(filepath.Join(legacy, "subdomains.txt"), []byte("old\n"), 0o644)
	if code := h.exec("-e", "legacy", "a.com"); code != 1 || !strings.Contains(h.stderr.String(), legacy) {
		t.Errorf("exit %d stderr %q", code, h.stderr.String())
	}
	if _, err := os.Stat(filepath.Join(legacy, ".recon")); err == nil {
		t.Error("must not write into a foreign directory")
	}

	os.MkdirAll(h.eng("empty"), 0o755)
	if code := h.exec("-e", "empty", "a.com"); code != 0 {
		t.Errorf("empty dir should be adopted: %d %s", code, h.stderr.String())
	}
	os.MkdirAll(filepath.Join(h.eng("half"), ".recon"), 0o755)
	os.WriteFile(filepath.Join(h.eng("half"), ".recon", "lock"), nil, 0o600)
	if code := h.exec("-e", "half", "a.com"); code != 0 {
		t.Errorf("interrupted creation should be adopted: %d %s", code, h.stderr.String())
	}
}

// B6: re-runs perform only checks without a recorded result.
func TestResumeOnlyNewChecks(t *testing.T) {
	st := &testkit.Stage{StageName: "ports", Kind: run.ThirdParty, ChecksFn: func(v run.View) []run.Check {
		var cs []run.Check
		for _, p := range v.Settings().Ports {
			cs = append(cs, run.Check{Key: fmt.Sprintf("h:%d", p)})
		}
		return cs
	}}
	h := newHarness(t, st)
	if code := h.exec("a.com", "--ports", "80,443"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if len(st.Executed()) != 2 {
		t.Fatalf("first run: %v", st.Executed())
	}
	st.Reset()
	h.exec("-e", "a.com", "--ports", "80,443")
	if len(st.Executed()) != 0 {
		t.Errorf("second run repeated checks: %v", st.Executed())
	}
	st.Reset()
	h.exec("-e", "a.com", "--ports", "80,443,8080")
	if got := st.Executed(); len(got) != 1 || got[0] != "h:8080" {
		t.Errorf("added port: %v", got)
	}
}

func TestKeyEncodedSettingCreatesNewChecks(t *testing.T) {
	st := &testkit.Stage{StageName: "crawl", Kind: run.ThirdParty, ChecksFn: func(v run.View) []run.Check {
		return []run.Check{{Key: fmt.Sprintf("https://a.com|depth=%d|pages=%d", v.Settings().Crawl.MaxDepth, v.Settings().Crawl.MaxPages)}}
	}}
	h := newHarness(t, st)
	h.exec("a.com")
	st.Reset()
	h.exec("-e", "a.com")
	if len(st.Executed()) != 0 {
		t.Fatal("unchanged settings repeated work")
	}
	h.exec("-e", "a.com", "--crawl-depth", "3")
	if got := st.Executed(); len(got) != 1 || !strings.Contains(got[0], "depth=3") {
		t.Errorf("%v", got)
	}
}

// B8: transient failures.
func TestTransientFailure(t *testing.T) {
	flaky := &testkit.Stage{StageName: "flaky", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check {
			cs := []run.Check{{Key: "X"}, {Key: "Y"}}
			for _, hn := range v.InScopeHostnames() {
				cs = append(cs, run.Check{Key: "host:" + hn})
			}
			return cs
		},
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			if c.Key == "X" {
				return nil, fmt.Errorf("timeout talking to source")
			}
			return nil, nil
		}}
	// A later stage creates new in-scope hostnames so a second pass happens.
	later := &testkit.Stage{StageName: "later", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check { return testkit.Keys("l", 1) },
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			return []run.Observation{obs("hostname", "new.a.com")}, nil
		}}
	h := newHarness(t, flaky, later)
	if code := h.exec("a.com", "--json"); code != 0 {
		t.Fatalf("exit %d (failed checks must not change the exit code): %s", code, h.stderr.String())
	}
	count := 0
	for _, k := range flaky.Executed() {
		if k == "X" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("X attempted %d times in one run (passes: %v)", count, flaky.Executed())
	}
	if !contains(flaky.Executed(), "host:new.a.com") {
		t.Errorf("second pass did not happen: %v", flaky.Executed())
	}
	if contains(h.completed("a.com", "flaky"), "X") || !contains(h.completed("a.com", "flaky"), "Y") {
		t.Errorf("completed = %v", h.completed("a.com", "flaky"))
	}
	if f := queryStrings(t, h.openDB("a.com"), "SELECT key FROM failures WHERE stage='flaky'"); len(f) != 1 || f[0] != "X" {
		t.Errorf("failures = %v", f)
	}
	evs := h.events()
	if st := lastState(evs, "flaky"); st.str("state") != "done" || st.num("failed") != 1 {
		t.Errorf("stage state: %v", st)
	}
	sum := ofType(evs, "summary")[0]
	if f, _ := sum["failed"].(map[string]any); f["flaky"] != float64(1) {
		t.Errorf("summary failed = %v", sum["failed"])
	}
	// Retried on every subsequent run.
	flaky.Reset()
	h.exec("-e", "a.com")
	if !contains(flaky.Executed(), "X") {
		t.Error("X must be retried on the next run")
	}
}

func TestErrAbortStage(t *testing.T) {
	st := &testkit.Stage{StageName: "abort", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check { return testkit.Keys("c", 4) },
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			return nil, fmt.Errorf("source says no: %w", run.ErrAbortStage)
		}}
	h := newHarness(t, st)
	if code := h.exec("a.com", "--json", "--concurrency", "1"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if len(st.Executed()) != 1 {
		t.Errorf("abort must stop sending: %v", st.Executed())
	}
	s := lastState(h.events(), "abort")
	if s.str("state") != "failed" || s.num("failed") != 4 {
		t.Errorf("state = %v", s)
	}
	if len(h.completed("a.com", "abort")) != 0 {
		t.Error("aborted checks must not be recorded")
	}
}

// B8/B11: a stage whose check enumeration fails is counted as failed once per
// run, and the run still terminates.
func TestEnumerationErrorTerminates(t *testing.T) {
	st := &testkit.Stage{StageName: "enum", Kind: run.ThirdParty,
		ChecksFn:  func(v run.View) []run.Check { return testkit.Keys("c", 1) },
		ChecksErr: errors.New("cannot list checks"),
	}
	h := newHarness(t, st)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if code := h.execCtx(ctx, "a.com", "--json"); code != 0 {
		t.Fatalf("exit %d (the run must end on its own): %s", code, h.stderr.String())
	}
	s := lastState(h.events(), "enum")
	if s.str("state") != "done" || s.num("failed") != 1 {
		t.Errorf("state = %v", s)
	}
}

// B10: redo.
func redoStages(behaviour *int) (*testkit.Stage, *testkit.Stage) {
	s := &testkit.Stage{StageName: "src", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check {
			if *behaviour == 2 {
				return testkit.Keys("k", 2)[1:] // k1 only: k0 becomes an orphan
			}
			return testkit.Keys("k", 2)
		},
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			switch {
			case c.Key == "k000" && *behaviour == 0:
				return []run.Observation{obs("web_service", "u0", "host", "a.com")}, nil
			case c.Key == "k001":
				return []run.Observation{obs("web_service", "u1", "host", "a.com")}, nil
			}
			return nil, nil
		}}
	o := &testkit.Stage{StageName: "other", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check { return testkit.Keys("t", 1) },
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			return []run.Observation{obs("web_service", "u1", "host", "a.com")}, nil
		}}
	return s, o
}

func currentOf(t *testing.T, h *harness, kind string) map[string]string {
	rows, err := h.openDB("a.com").Query("SELECT key, current FROM records WHERE kind=?", kind)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var k string
		var c int
		rows.Scan(&k, &c)
		m[k] = fmt.Sprint(c)
	}
	return m
}

func TestRedo(t *testing.T) {
	b := 0
	src, other := redoStages(&b)
	h := newHarness(t, src, other)
	h.exec("a.com", "--json")
	if got := ofType(h.events(), "summary")[0]["totals"].(map[string]any)["web services"]; got != float64(2) {
		t.Fatalf("first summary web services = %v", got)
	}
	src.Reset()
	other.Reset()
	b = 1 // k0 no longer observes u0
	if code := h.exec("-e", "a.com", "--redo", "src", "--json"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if len(src.Executed()) != 2 || len(other.Executed()) != 0 {
		t.Errorf("redo executed src=%v other=%v", src.Executed(), other.Executed())
	}
	cur := currentOf(t, h, "web_service")
	if cur["u0"] != "0" || cur["u1"] != "1" {
		t.Errorf("currency = %v (u1 is still observed by another stage)", cur)
	}
	if got := ofType(h.events(), "summary")[0]["totals"].(map[string]any)["web services"]; got != float64(1) {
		t.Errorf("summary must count current records only: %v", got)
	}
	if _, ok := h.meta("a.com", "redo:src"); ok {
		t.Error("redo marker should be cleared")
	}
}

func TestRedoSweepsOrphanedChecks(t *testing.T) {
	b := 0
	src, other := redoStages(&b)
	h := newHarness(t, src, other)
	h.exec("a.com")
	b = 2
	if code := h.exec("-e", "a.com", "--redo", "src"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if cur := currentOf(t, h, "web_service"); cur["u0"] != "0" {
		t.Errorf("orphaned check's observation must be swept: %v", cur)
	}
}

// A redo whose enumeration fails part-way must not sweep the checks it never
// listed, and stays pending.
func TestRedoKeepsUnlistedChecksOnEnumerationError(t *testing.T) {
	b := 0
	src, other := redoStages(&b)
	h := newHarness(t, src, other)
	h.exec("a.com")
	b = 2                                        // k0 is not listed...
	src.ChecksErr = errors.New("listing failed") // ...because enumeration fails
	if code := h.exec("-e", "a.com", "--redo", "src"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if cur := currentOf(t, h, "web_service"); cur["u0"] != "1" {
		t.Errorf("unlisted check's observation must survive: %v", cur)
	}
	if _, ok := h.meta("a.com", "redo:src"); !ok {
		t.Error("redo must stay pending after an enumeration error")
	}
}

// A check key containing a configured key value is stored redacted, yet still
// recognised as completed: within the run and on the next one.
func TestRedactedCheckKeyCompletes(t *testing.T) {
	st := &testkit.Stage{StageName: "asnish", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check { return []run.Check{{Key: "AS4123"}} }}
	h := newHarness(t, st)
	t.Setenv("RECON_KEYS_FAKE", "123")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if code := h.execCtx(ctx, "a.com"); code != 0 {
		t.Fatalf("exit %d (the run must end on its own): %s", code, h.stderr.String())
	}
	if code := h.execCtx(ctx, "-e", "a.com"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if got := st.Executed(); len(got) != 1 {
		t.Errorf("executed %v; want the check once across both runs", got)
	}
}

func TestRedoUnknownStage(t *testing.T) {
	h := newHarness(t, noop())
	if code := h.exec("a.com", "--redo", "nope"); code != 2 || !strings.Contains(h.stderr.String(), "nope") {
		t.Errorf("exit %d stderr %q", code, h.stderr.String())
	}
	if _, err := os.Stat(h.eng("a.com")); err == nil {
		t.Error("nothing should be created before validation passes")
	}
}

// B11: discovery loop across stages and passes.
func TestDiscoveryLoop(t *testing.T) {
	perHost := func(prefix string) func(v run.View) []run.Check {
		return func(v run.View) []run.Check {
			var cs []run.Check
			for _, hn := range v.InScopeHostnames() {
				cs = append(cs, run.Check{Key: prefix + hn, Input: hn})
			}
			return cs
		}
	}
	a := &testkit.Stage{StageName: "A", Kind: run.ThirdParty, ChecksFn: perHost("A:")}
	b := &testkit.Stage{StageName: "B", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check {
			return append([]run.Check{{Key: "B:seed"}}, perHost("B:")(v)...)
		},
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			switch c.Key {
			case "B:seed":
				return []run.Observation{obs("hostname", "new1.a.com"), obs("hostname", "other.net")}, nil
			case "B:new1.a.com":
				return []run.Observation{obs("hostname", "later.a.com")}, nil
			}
			return nil, nil
		}}
	c := &testkit.Stage{StageName: "C", Kind: run.ThirdParty, ChecksFn: perHost("C:")}
	h := newHarness(t, a, b, c)
	done := make(chan int, 1)
	go func() { done <- h.exec("a.com") }()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatal(h.stderr.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("run did not terminate")
	}
	for _, want := range []string{"C:new1.a.com", "C:later.a.com"} {
		if !contains(c.Executed(), want) {
			t.Errorf("C executed %v, missing %s", c.Executed(), want)
		}
	}
	for _, want := range []string{"A:new1.a.com", "A:later.a.com"} {
		if !contains(a.Executed(), want) {
			t.Errorf("A needs a second pass for %s: %v", want, a.Executed())
		}
	}
	for _, st := range []*testkit.Stage{a, b, c} {
		for _, k := range st.Executed() {
			if strings.Contains(k, "other.net") {
				t.Errorf("out-of-scope name given to stage %s: %s", st.StageName, k)
			}
		}
	}
	if !hasRow(csvRows(t, h.readOut("a.com", "candidates.csv")), "hostname", "other.net") {
		t.Error("other.net must be recorded as a candidate")
	}
}

// B13: passive.
func TestPassive(t *testing.T) {
	target := &testkit.Stage{StageName: "probe", Kind: run.Target, ChecksFn: func(v run.View) []run.Check { return testkit.Keys("p", 3) }}
	third := &testkit.Stage{StageName: "third", Kind: run.ThirdParty, ChecksFn: func(v run.View) []run.Check { return testkit.Keys("t", 2) }}
	h := newHarness(t, third, target)
	if code := h.exec("a.com", "--passive", "--authorised", "--json"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if len(target.Executed()) != 0 || len(third.Executed()) != 2 {
		t.Errorf("target=%v third=%v", target.Executed(), third.Executed())
	}
	s := lastState(h.events(), "probe")
	if s.str("state") != "not-configured" || s.str("reason") != "passive-only" {
		t.Errorf("state = %v", s)
	}
	if h.network() != 0 {
		t.Error("traffic during passive run")
	}
}

// B14: acknowledgement.
// ackStage has two fixed checks plus one per root, so adding a root creates new work.
func ackStage() *testkit.Stage {
	return &testkit.Stage{StageName: "probe", Kind: run.Target, ChecksFn: func(v run.View) []run.Check {
		cs := testkit.Keys("p", 2)
		for _, r := range v.Inputs().Roots {
			cs = append(cs, run.Check{Key: "r:" + r})
		}
		return cs
	}}
}

func TestAckPromptYes(t *testing.T) {
	st := ackStage()
	h := newHarness(t, st)
	h.stdinTTY, h.stdin = true, "y\n"
	if code := h.exec("a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if !strings.Contains(h.stderr.String(), "authorised") {
		t.Errorf("prompt missing on stderr: %q", h.stderr.String())
	}
	if len(st.Executed()) != 3 {
		t.Error("stage should run after y")
	}
	if _, ok := h.meta("a.com", "ack_at"); !ok {
		t.Error("ack not stored")
	}
	// Never asked again, even when scope grows.
	st.Reset()
	h.stdin = "n\n"
	h.exec("-e", "a.com", "b.com")
	if strings.Contains(h.stderr.String(), "authorised") {
		t.Error("ack must not be asked again")
	}
	if got := st.Executed(); len(got) != 1 || got[0] != "r:b.com" {
		t.Errorf("stored ack must keep covering the engagement: %v", got)
	}
}

func TestAckPromptNo(t *testing.T) {
	st := ackStage()
	h := newHarness(t, st)
	h.stdinTTY, h.stdin = true, "n\n"
	if code := h.exec("a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if len(st.Executed()) != 0 {
		t.Error("stage must not run")
	}
	if !strings.Contains(h.stdout.String(), "no authorisation") {
		t.Errorf("console should show not-configured reason: %q", h.stdout.String())
	}
	if _, ok := h.meta("a.com", "ack_at"); ok {
		t.Error("ack stored on n")
	}
}

func TestAckNoPromptWithoutTTYOrInJSON(t *testing.T) {
	for name, c := range map[string]struct {
		tty  bool
		args []string
	}{
		"no tty":  {false, nil},
		"json":    {true, []string{"--json"}},
		"passive": {true, []string{"--passive"}},
	} {
		st := ackStage()
		h := newHarness(t, st)
		h.stdinTTY, h.stdin = c.tty, "y\n"
		if code := h.exec(append([]string{"a.com"}, c.args...)...); code != 0 {
			t.Fatalf("%s: %s", name, h.stderr.String())
		}
		if strings.Contains(h.stderr.String(), "authorised") || len(st.Executed()) != 0 {
			t.Errorf("%s: prompt=%q executed=%v", name, h.stderr.String(), st.Executed())
		}
	}
}

func TestAckFlag(t *testing.T) {
	for _, flag := range []string{"--authorised", "--authorized"} {
		st := ackStage()
		h := newHarness(t, st)
		if code := h.exec("a.com", flag); code != 0 {
			t.Fatal(h.stderr.String())
		}
		if len(st.Executed()) != 3 {
			t.Errorf("%s: executed %v", flag, st.Executed())
		}
	}
	st := ackStage()
	h := newHarness(t, st)
	h.exec("a.com", "--authorised", "--passive")
	if _, ok := h.meta("a.com", "ack_at"); !ok {
		t.Error("--authorised --passive must store the ack")
	}
	h.exec("-e", "a.com")
	if len(st.Executed()) != 3 {
		t.Errorf("stored ack should let the next non-passive run proceed: %v", st.Executed())
	}
}

// B15: netblock guard.
func asnServer(t *testing.T, h *harness, prefix *string) {
	srv := newPrefixServer(t, prefix)
	h.eopts.SourceBaseURLs = map[string]string{"stat.ripe.net": srv}
}

func TestNetblockGuard(t *testing.T) {
	var prefix = "10.0.0.0/22" // 1024 addresses
	after := &testkit.Stage{StageName: "after", Kind: run.ThirdParty, ChecksFn: func(v run.View) []run.Check { return testkit.Keys("a", 2) }}
	h := newHarness(t, newASN(), after)
	asnServer(t, h, &prefix)

	code := h.exec("--asn", "64500", "--netblock-limit", "1000")
	if code != 3 {
		t.Fatalf("exit %d, want 3: %s %s", code, h.stdout.String(), h.stderr.String())
	}
	if !strings.Contains(h.stdout.String()+h.stderr.String(), "1024") {
		t.Errorf("total not shown: %q %q", h.stdout.String(), h.stderr.String())
	}
	if len(after.Executed()) != 0 || h.network() != 0 {
		t.Errorf("later stages ran on unapproved netblocks: %v net=%d", after.Executed(), h.network())
	}

	if code = h.exec("-e", "as64500", "--netblock-limit", "1000", "--allow-large-netblocks"); code != 0 {
		t.Fatalf("override: exit %d: %s", code, h.stderr.String())
	}
	if len(after.Executed()) != 2 {
		t.Errorf("override should proceed: %v", after.Executed())
	}
	if v, ok := h.meta("as64500", "netblock_approved"); !ok || v != "1024" {
		t.Errorf("approval = %q %v", v, ok)
	}
	after.Reset()
	if code = h.exec("-e", "as64500", "--netblock-limit", "1000"); code != 0 {
		t.Fatalf("remembered approval: exit %d", code)
	}
	prefix = "10.0.0.0/21" // 2048: growth beyond the approved count
	if code = h.exec("-e", "as64500", "--netblock-limit", "1000", "--redo", "asn"); code != 3 {
		t.Errorf("growth beyond approval must stop again: exit %d", code)
	}
}

func TestNetblockInputGuard(t *testing.T) {
	first := &testkit.Stage{StageName: "first", Kind: run.ThirdParty, ChecksFn: func(v run.View) []run.Check { return testkit.Keys("a", 2) }}
	h := newHarness(t, first)
	if code := h.exec("--cidr", "10.0.0.0/16", "--netblock-limit", "100"); code != 3 || len(first.Executed()) != 0 {
		t.Errorf("exit %d executed %v", code, first.Executed())
	}
}

// B16 at CLI level: excluded.csv.
func TestExcludedCSV(t *testing.T) {
	st := &testkit.Stage{StageName: "disc", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check { return testkit.Keys("c", 1) },
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			return []run.Observation{
				obs("hostname", "admin.a.com"), obs("hostname", "db.a.com"), obs("hostname", "www.a.com"),
				obs("resolution", "db.a.com|A|198.51.100.7", "name", "db.a.com", "type", "A", "value", "198.51.100.7"),
				obs("resolution", "www.a.com|A|203.0.113.5", "name", "www.a.com", "type", "A", "value", "203.0.113.5"),
			}, nil
		}}
	h := newHarness(t, st)
	if code := h.exec("a.com", "-x", "admin.a.com", "-x", "198.51.100.0/24"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	rows := csvRows(t, h.readOut("a.com", "excluded.csv"))
	if !hasRow(rows, "admin.a.com") || !hasRow(rows, "db.a.com") || hasRow(rows, "www.a.com") {
		t.Fatalf("excluded.csv = %v", rows)
	}
	for _, r := range rows[1:] {
		if r[1] == "" {
			t.Errorf("no reason for %v", r)
		}
	}
	if strings.Contains(h.readOut("a.com", "candidates.csv"), "admin.a.com") {
		t.Error("excluded name must not be a candidate")
	}
}

// B17/B18: states, found lines, counts, summary.
func TestStageStatesAndFound(t *testing.T) {
	prev := &testkit.Stage{StageName: "prev", Kind: run.ThirdParty, ChecksFn: func(v run.View) []run.Check { return testkit.Keys("p", 2) }}
	failing := &testkit.Stage{StageName: "failing", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check { return testkit.Keys("f", 2) },
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			return nil, fmt.Errorf("source unavailable")
		}}
	partial := &testkit.Stage{StageName: "partial", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check { return testkit.Keys("q", 2) },
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			if c.Key == "q000" {
				return nil, fmt.Errorf("rate limited")
			}
			return []run.Observation{
				obs("web_service", "https://a.com"), obs("url", "https://a.com/x"), obs("url", "https://a.com/y"),
				obs("open_port", "1.2.3.4:80"), obs("hostname", "www.a.com"),
				obs("finding", "f1", "category", "exposed", "severity", "high", "target", "https://a.com/.git", "detail", "git"),
				obs("finding", "f2", "category", "banner", "severity", "medium", "target", "1.2.3.4:21", "detail", "ftp"),
				obs("finding", "f3", "category", "misc", "severity", "low", "target", "x", "detail", "minor"),
			}, nil
		}}
	nokey := &testkit.Stage{StageName: "nokey", Kind: run.ThirdParty, ConfiguredFn: func(run.Env) (bool, string) { return false, "no key" }}
	empty := &testkit.Stage{StageName: "empty", Kind: run.ThirdParty}
	target := &testkit.Stage{StageName: "probe", Kind: run.Target, ChecksFn: func(v run.View) []run.Check { return testkit.Keys("x", 1) }}
	h := newHarness(t, prev, failing, partial, nokey, empty, target)
	if code := h.exec("a.com", "--json"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	evs := h.events()
	want := map[string][2]string{ // state, reason
		"failing": {"failed", ""}, "partial": {"done", ""}, "nokey": {"not-configured", "no key"},
		"empty": {"done", ""}, "probe": {"not-configured", "no authorisation"}, "prev": {"done", ""},
	}
	for name, w := range want {
		s := lastState(evs, name)
		if s == nil || s.str("state") != w[0] || s.str("reason") != w[1] {
			t.Errorf("%s: %v, want %v", name, s, w)
		}
	}
	if s := lastState(evs, "partial"); s.num("checks") != 2 || s.num("failed") != 1 {
		t.Errorf("partial counts: %v", s)
	}
	if s := lastState(evs, "empty"); s.num("checks") != 0 {
		t.Errorf("empty: %v", s)
	}
	// One line per state change: no consecutive duplicates for any stage.
	for _, name := range []string{"prev", "failing", "partial", "nokey", "empty", "probe"} {
		se := stageEvents(evs, name)
		for i := 1; i < len(se); i++ {
			if se[i].str("state") == se[i-1].str("state") && se[i].num("checks") == se[i-1].num("checks") {
				t.Errorf("%s: repeated stage line %v", name, se)
			}
		}
	}
	// Found lines only for printed kinds; URLs counted, not printed.
	found := map[string]bool{}
	for _, e := range ofType(evs, "found") {
		found[e.str("category")+"|"+e.str("value")] = true
	}
	for _, w := range []string{"web service|https://a.com", "open port|1.2.3.4:80", "host|www.a.com"} {
		if !found[w] {
			t.Errorf("missing found %q in %v", w, found)
		}
	}
	for k := range found {
		if strings.Contains(k, "/x") || strings.Contains(k, "/y") {
			t.Errorf("URLs must not be printed: %s", k)
		}
	}
	urlCount := 0
	for _, e := range ofType(evs, "count") {
		if e.str("category") == "urls" {
			urlCount = e.num("n")
		}
	}
	if urlCount != 2 {
		t.Errorf("urls count = %d", urlCount)
	}
	// Summary: totals, failed counts, high and medium findings listed individually.
	sum := ofType(evs, "summary")
	if len(sum) != 1 {
		t.Fatalf("summaries: %d", len(sum))
	}
	totals := sum[0]["totals"].(map[string]any)
	if totals["urls"] != float64(2) || totals["hosts"] != float64(1) || totals["open ports"] != float64(1) {
		t.Errorf("totals = %v", totals)
	}
	failed := sum[0]["failed"].(map[string]any)
	if failed["failing"] != float64(2) || failed["partial"] != float64(1) {
		t.Errorf("failed = %v", failed)
	}
	fs := sum[0]["findings"].([]any)
	if len(fs) != 2 {
		t.Errorf("findings = %v (want high and medium only)", fs)
	}
	// Re-run: nothing new is printed, previously-done stages say so.
	h.exec("-e", "a.com", "--json")
	evs = h.events()
	if len(ofType(evs, "found")) != 0 {
		t.Errorf("records already known must not be printed again: %v", ofType(evs, "found"))
	}
	if s := lastState(evs, "prev"); s.str("state") != "done-previously" {
		t.Errorf("prev = %v", s)
	}
}

// B19.
func TestJSONMode(t *testing.T) {
	h := newHarness(t, noop())
	if code := h.exec("a.com", "--json"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	h.events() // fails on any non-JSON line
	if strings.Contains(h.stdout.String(), "\x1b") {
		t.Error("ANSI in JSON mode")
	}
	for _, typ := range []string{"run_start", "summary", "run_end"} {
		if len(ofType(h.events(), typ)) != 1 {
			t.Errorf("want exactly one %s event", typ)
		}
	}
	h.stdoutTTY = true
	h.exec("b.com", "--json")
	if strings.Contains(h.stdout.String(), "\x1b") {
		t.Error("ANSI in JSON mode on a TTY")
	}
	// Errors are JSON events too.
	if code := h.exec("co.uk", "--json"); code != 2 {
		t.Errorf("exit %d", code)
	}
	errs := ofType(h.events(), "error")
	if len(errs) != 1 || errs[0].num("exit_code") != 2 || !strings.Contains(errs[0].str("message"), "co.uk") {
		t.Errorf("error events = %v", errs)
	}
	if code := h.exec("--json", "--help"); code != 0 {
		t.Errorf("exit %d", code)
	}
}

func TestNonTTYNoANSI(t *testing.T) {
	st := &testkit.Stage{StageName: "s", Kind: run.ThirdParty, ChecksFn: func(v run.View) []run.Check { return testkit.Keys("c", 1) },
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			return []run.Observation{obs("web_service", "https://a.com")}, nil
		}}
	h := newHarness(t, st)
	h.exec("a.com")
	if strings.Contains(h.stdout.String(), "\x1b") || h.stdout.Len() == 0 {
		t.Errorf("non-TTY stdout: %q", h.stdout.String())
	}
	h.stdoutTTY = true
	h.exec("b.com")
	if !strings.Contains(h.stdout.String(), "\x1b[") {
		t.Errorf("TTY stdout should be styled: %q", h.stdout.String())
	}
}

// B21: concurrency bound.
func TestConcurrencyBound(t *testing.T) {
	st := &testkit.Stage{StageName: "s", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check { return testkit.Keys("c", 24) },
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			time.Sleep(15 * time.Millisecond)
			return nil, nil
		}}
	h := newHarness(t, st)
	if code := h.exec("a.com", "--concurrency", "3"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if m := st.MaxActive(); m > 3 || m < 2 {
		t.Errorf("max concurrent = %d, want 2..3", m)
	}
}

// B22: invalid input is rejected before any activity.
func TestInvalidInputsTouchNothing(t *testing.T) {
	st := &testkit.Stage{StageName: "s", Kind: run.Target, ChecksFn: func(v run.View) []run.Check { return testkit.Keys("c", 3) }}
	badCfg := writeFile(t, t.TempDir(), "bad.yaml", "concurency: 3\n")
	badList := writeFile(t, t.TempDir(), "d.txt", "ok.example.com\nco.uk\n")
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"malformed domain", []string{"bad domain.com"}, "bad domain.com"},
		{"public suffix", []string{"co.uk"}, "co.uk"},
		{"bad cidr", []string{"a.com", "--cidr", "10.0.0.0/33"}, "10.0.0.0/33"},
		{"bad asn", []string{"a.com", "--asn", "ASxyz"}, "ASxyz"},
		{"bad exclusion", []string{"a.com", "-x", "a b"}, "a b"},
		{"bad config value", []string{"a.com", "--concurrency", "0"}, "concurrency"},
		{"bad port", []string{"a.com", "--ports", "70000"}, "70000"},
		{"unknown config key", []string{"a.com", "--config", badCfg}, "concurency"},
		{"unknown redo", []string{"a.com", "--redo", "bogus"}, "bogus"},
		{"bad value in file", []string{"-d", badList}, "co.uk"},
		{"missing config", []string{"a.com", "--config", "/no/such/config.yaml"}, "/no/such/config.yaml"},
	}
	for _, c := range cases {
		h := newHarness(t, st)
		st.Reset()
		code := h.exec(append(c.args, "--authorised")...)
		if code != 2 {
			t.Errorf("%s: exit %d, stderr %q", c.name, code, h.stderr.String())
		}
		if !strings.Contains(h.stderr.String(), c.want) {
			t.Errorf("%s: stderr %q should name %q", c.name, h.stderr.String(), c.want)
		}
		if h.network() != 0 || len(st.Executed()) != 0 {
			t.Errorf("%s: activity before validation (net=%d executed=%v)", c.name, h.network(), st.Executed())
		}
		if entries, _ := os.ReadDir(h.out); len(entries) != 0 {
			t.Errorf("%s: created %v before validation", c.name, entries)
		}
	}
}

// B23: exit codes and lock.
func TestExitCodes(t *testing.T) {
	st := &testkit.Stage{StageName: "s", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check { return testkit.Keys("c", 2) },
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			return nil, fmt.Errorf("transient")
		}}
	h := newHarness(t, st)
	if code := h.exec("a.com"); code != 0 {
		t.Errorf("failed checks and not-configured stages still exit 0, got %d", code)
	}

	e, err := engagement.Open(h.eng("a.com"), engagement.Options{})
	if err != nil {
		t.Fatal(err)
	}
	code := h.exec("-e", "a.com")
	e.Close()
	if code != 1 || !strings.Contains(strings.ToLower(h.stderr.String()), "lock") && !strings.Contains(strings.ToLower(h.stderr.String()), "running") {
		t.Errorf("held lock: exit %d, stderr %q", code, h.stderr.String())
	}
	if code = h.exec("-e", "a.com"); code != 0 {
		t.Errorf("lock released: exit %d", code)
	}

	// A corrupt store is a fatal runtime error.
	os.MkdirAll(filepath.Join(h.eng("bad"), ".recon"), 0o755)
	os.WriteFile(filepath.Join(h.eng("bad"), ".recon", "state.db"), []byte("this is not a sqlite database, just some text padding padding padding padding"), 0o600)
	if code = h.exec("-e", "bad", "a.com"); code != 1 {
		t.Errorf("corrupt store: exit %d", code)
	}
}

func TestInterruptedByContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	st := &testkit.Stage{StageName: "s", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check { return testkit.Keys("c", 50) },
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			if c.Key == "c005" {
				cancel()
			}
			time.Sleep(5 * time.Millisecond)
			return nil, nil
		}}
	h := newHarness(t, st)
	if code := h.execCtx(ctx, "a.com", "--concurrency", "1"); code != 130 {
		t.Errorf("exit %d, want 130", code)
	}
	if len(h.completed("a.com", "s")) >= 50 {
		t.Error("run should have stopped early")
	}
	if _, err := os.Stat(h.eng("a.com") + "/scope.csv"); err != nil {
		t.Error("outputs should still be rendered on interrupt")
	}
}

// B24: keys never leak.
func TestSecretsNeverLeak(t *testing.T) {
	const envKey, fileKey = "ENVSENTINEL-7f3a91", "FILESENTINEL-c20b44"
	var gotEnv, gotFile string
	mk := func(name, source string, got *string) *testkit.Stage {
		return &testkit.Stage{StageName: name, Kind: run.ThirdParty, Src: []string{"api.example.net"},
			ConfiguredFn: func(e run.Env) (bool, string) {
				k, ok := e.Key(source)
				*got = k.Reveal()
				return ok, "no key"
			},
			ChecksFn: func(v run.View) []run.Check { return testkit.Keys("c", 3) },
			RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
				key := *got
				switch c.Key {
				case "c000":
					return []run.Observation{obs("web_service", "https://a.com/?k="+key, "token", key)}, nil
				case "c001":
					_, err := e.ThirdParty.Do(ctx, egress.ThirdPartyRequest{Method: "GET", URL: "https://api.example.net/x?key=" + key})
					return nil, fmt.Errorf("request failed: %v (key %s)", err, key)
				}
				return nil, fmt.Errorf("auth %s rejected", key)
			}}
	}
	cfgDir := t.TempDir()
	cfg := writeFile(t, cfgDir, "config.yaml", "keys:\n  other: "+fileKey+"\n")
	for _, jsonMode := range []bool{true, false} {
		a, b := mk("viaenv", "fake", &gotEnv), mk("viafile", "other", &gotFile)
		h := newHarness(t, a, b)
		h.eopts.SourceBaseURLs = map[string]string{"api.example.net": "http://127.0.0.1:1"} // refuses connections; error text includes the URL
		t.Setenv("RECON_KEYS_FAKE", envKey)
		args := []string{"a.com", "--verbose", "--config", cfg}
		if jsonMode {
			args = append(args, "--json")
		}
		if code := h.exec(args...); code != 0 {
			t.Fatalf("exit %d: %s", code, h.stderr.String())
		}
		if gotEnv != envKey || gotFile != fileKey {
			t.Fatalf("keys not delivered to stages: %q %q", gotEnv, gotFile)
		}
		scan := func(where string, data []byte) {
			for _, k := range []string{envKey, fileKey} {
				if strings.Contains(string(data), k) {
					t.Errorf("json=%v: %s contains %s", jsonMode, where, k)
				}
			}
		}
		scan("stdout", h.stdout.Bytes())
		scan("stderr", h.stderr.Bytes())
		filepath.WalkDir(h.eng("a.com"), func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				if b, rerr := os.ReadFile(p); rerr == nil {
					scan(p, b)
				}
			}
			return nil
		})
		os.Unsetenv("RECON_KEYS_FAKE")
	}
}
