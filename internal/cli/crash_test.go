package cli_test

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rafaelh/recon/internal/cli"
	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/testkit"
)

// TestMain lets the test binary re-execute itself as `recon` with a fake stage.
func TestMain(m *testing.M) {
	if os.Getenv("RECON_TEST_CHILD") == "1" {
		os.Exit(childMain())
	}
	os.Exit(m.Run())
}

func childMain() int {
	n, _ := strconv.Atoi(os.Getenv("RECON_TEST_N"))
	delay, _ := time.ParseDuration(os.Getenv("RECON_TEST_DELAY"))
	logPath := os.Getenv("RECON_TEST_LOG")
	st := &testkit.Stage{StageName: "fake", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check { return testkit.Keys("c", n) },
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			if logPath != "" {
				f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
				if err == nil {
					fmt.Fprintln(f, c.Key)
					f.Close()
				}
			}
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return []run.Observation{obs("web_service", "ws-"+c.Key)}, nil
		}}
	d := cli.DefaultDeps()
	d.Stages = []run.Stage{st}
	return cli.Execute(context.Background(), strings.Split(os.Getenv("RECON_TEST_ARGS"), "\x1f"), d)
}

type child struct {
	t   *testing.T
	cmd *exec.Cmd
	log string
	out string
}

type childOpts struct {
	n         int
	delay     time.Duration
	fault     string
	faultFile string
	args      []string
}

func startChild(t *testing.T, out string, o childOpts) *child {
	t.Helper()
	c := &child{t: t, log: filepath.Join(t.TempDir(), "log"), out: out}
	args := append([]string{"--output-dir", out, "--json"}, o.args...)
	c.cmd = exec.Command(os.Args[0], "-test.run=NoSuchTestEver")
	c.cmd.Env = append(os.Environ(),
		"RECON_TEST_CHILD=1", "RECON_TEST_N="+strconv.Itoa(o.n), "RECON_TEST_DELAY="+o.delay.String(),
		"RECON_TEST_LOG="+c.log, "RECON_TEST_ARGS="+strings.Join(args, "\x1f"),
		"XDG_CONFIG_HOME="+t.TempDir(), "HOME="+t.TempDir())
	if o.fault != "" {
		c.cmd.Env = append(c.cmd.Env, "RECON_FAULT="+o.fault, "RECON_FAULT_FILE="+o.faultFile)
	}
	if err := c.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.cmd.Process.Kill(); _ = c.cmd.Wait() })
	return c
}

// wait returns the exit code (-1 if killed by a signal).
func (c *child) wait() int {
	c.t.Helper()
	done := make(chan struct{})
	go func() { _ = c.cmd.Wait(); close(done) }() // ProcessState carries the outcome
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		_ = c.cmd.Process.Kill()
		c.t.Fatal("child did not exit")
	}
	return c.cmd.ProcessState.ExitCode()
}

func (c *child) executed() []string {
	f, err := os.Open(c.log)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (c *child) waitFault(file string) string {
	c.t.Helper()
	waitFor(c.t, "fault point", func() bool { _, err := os.Stat(file); return err == nil })
	time.Sleep(50 * time.Millisecond)
	b, _ := os.ReadFile(file)
	return strings.TrimSpace(string(b))
}

func (c *child) kill(sig syscall.Signal) { _ = c.cmd.Process.Signal(sig) }

const nChecks = 40

func engDirOf(out string) string { return filepath.Join(out, "a.com") }

func committed(t *testing.T, out string) map[string]bool {
	t.Helper()
	db := openDB(t, filepath.Join(engDirOf(out), ".recon", "state.db"))
	m := map[string]bool{}
	for _, k := range queryStrings(t, db, "SELECT key FROM checks WHERE stage='fake'") {
		m[k] = true
	}
	return m
}

func allKeys(n int) []string {
	var ks []string
	for _, c := range testkit.Keys("c", n) {
		ks = append(ks, c.Key)
	}
	return ks
}

func setDiff(all []string, exclude map[string]bool) []string {
	var out []string
	for _, k := range all {
		if !exclude[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func sorted(s []string) []string { c := append([]string(nil), s...); sort.Strings(c); return c }

func assertOutputsIntact(t *testing.T, out string) {
	t.Helper()
	entries, _ := os.ReadDir(engDirOf(out))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(engDirOf(out), e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if len(b) > 0 && b[len(b)-1] != '\n' {
			t.Errorf("%s ends mid-line: %q", e.Name(), b[max(0, len(b)-30):])
		}
		if strings.HasSuffix(e.Name(), ".csv") {
			r := csv.NewReader(strings.NewReader(string(b)))
			if _, err := r.ReadAll(); err != nil {
				t.Errorf("%s does not parse: %v", e.Name(), err)
			}
		}
	}
}

func finishAndCheck(t *testing.T, out string, wantRun2 []string, o childOpts) {
	t.Helper()
	c2 := startChild(t, out, childOpts{n: nChecks, args: o.args})
	if code := c2.wait(); code != 0 {
		t.Fatalf("recovery run exit %d", code)
	}
	if got := sorted(c2.executed()); strings.Join(got, ",") != strings.Join(wantRun2, ",") {
		t.Errorf("recovery run executed %d checks, want %d\n got %v\nwant %v", len(got), len(wantRun2), got, wantRun2)
	}
	if got := committed(t, out); len(got) != nChecks {
		t.Errorf("after recovery %d checks recorded, want %d", len(got), nChecks)
	}
	if entries, _ := os.ReadDir(filepath.Join(engDirOf(out), ".recon", "tmp")); len(entries) != 0 {
		t.Errorf("tmp not swept: %v", entries)
	}
	assertOutputsIntact(t, out)
}

// A kill -9 while an output file is mid-write.
func TestCrashRenderMidFile(t *testing.T) {
	out := t.TempDir()
	c1 := startChild(t, out, childOpts{n: nChecks, args: []string{"a.com"}})
	if code := c1.wait(); code != 0 {
		t.Fatalf("first run exit %d", code)
	}
	before, _ := os.ReadFile(filepath.Join(engDirOf(out), "scope.csv"))

	ff := filepath.Join(t.TempDir(), "fault")
	c2 := startChild(t, out, childOpts{n: nChecks, fault: "render-mid-file", faultFile: ff, args: []string{"-e", "a.com", "--redo", "fake"}})
	c2.waitFault(ff)
	c2.kill(syscall.SIGKILL)
	c2.wait()
	if entries, _ := os.ReadDir(filepath.Join(engDirOf(out), ".recon", "tmp")); len(entries) == 0 {
		t.Error("fault did not leave a partial temp file; the hook may not be reached")
	}
	assertOutputsIntact(t, out)
	if after, _ := os.ReadFile(filepath.Join(engDirOf(out), "scope.csv")); string(after) != string(before) {
		t.Error("scope.csv changed by an interrupted render")
	}
	// The interrupted redo is finished by the next run, which is not blocked by the dead lock.
	c3 := startChild(t, out, childOpts{n: nChecks, args: []string{"-e", "a.com"}})
	if code := c3.wait(); code != 0 {
		t.Fatalf("next run exit %d", code)
	}
	if entries, _ := os.ReadDir(filepath.Join(engDirOf(out), ".recon", "tmp")); len(entries) != 0 {
		t.Errorf("tmp not swept: %v", entries)
	}
	assertOutputsIntact(t, out)
}

// A kill -9 at in-check-tx, in-flight and after-commit.
func TestCrashPoints(t *testing.T) {
	for _, point := range []string{"in-check-tx", "in-flight", "after-commit"} {
		t.Run(point, func(t *testing.T) {
			out := t.TempDir()
			ff := filepath.Join(t.TempDir(), "fault")
			c1 := startChild(t, out, childOpts{n: nChecks, fault: point, faultFile: ff, args: []string{"a.com"}})
			detail := c1.waitFault(ff)
			if point == "in-flight" {
				time.Sleep(400 * time.Millisecond) // let the other workers' completions commit
			}
			c1.kill(syscall.SIGKILL)
			c1.wait()

			done := committed(t, out)
			if point == "after-commit" && len(done) == 0 {
				t.Error("after-commit pause but nothing committed")
			}
			if point == "in-flight" {
				key := strings.Fields(detail)[len(strings.Fields(detail))-1]
				if done[key] {
					t.Errorf("in-flight check %s must not be recorded", key)
				}
			}
			if point == "in-check-tx" && len(done) == nChecks {
				t.Error("in-check-tx: the pending transaction must not have committed")
			}
			finishAndCheck(t, out, setDiff(allKeys(nChecks), done), childOpts{args: []string{"-e", "a.com"}})
		})
	}
}

// A redo interrupted after a commit is finished by the next plain run.
func TestCrashDuringRedo(t *testing.T) {
	out := t.TempDir()
	c1 := startChild(t, out, childOpts{n: nChecks, args: []string{"a.com"}})
	if code := c1.wait(); code != 0 {
		t.Fatalf("first run exit %d", code)
	}
	ff := filepath.Join(t.TempDir(), "fault")
	// Slow checks spread completions over several commit batches, so the first commit is partial.
	c2 := startChild(t, out, childOpts{n: nChecks, delay: 30 * time.Millisecond, fault: "after-commit", faultFile: ff,
		args: []string{"-e", "a.com", "--redo", "fake", "--concurrency", "4"}})
	c2.waitFault(ff)
	c2.kill(syscall.SIGKILL)
	c2.wait()
	db := openDB(t, filepath.Join(engDirOf(out), ".recon", "state.db"))
	if v := queryStrings(t, db, "SELECT key FROM meta WHERE key='redo:fake'"); len(v) != 1 {
		t.Fatalf("redo marker must survive the crash: %v", v)
	}
	done := committed(t, out)
	if len(done) == 0 || len(done) == nChecks {
		t.Fatalf("want a partial redo at the crash point, got %d of %d checks recorded", len(done), nChecks)
	}
	finishAndCheck(t, out, setDiff(allKeys(nChecks), done), childOpts{args: []string{"-e", "a.com"}}) // no --redo
	db2 := openDB(t, filepath.Join(engDirOf(out), ".recon", "state.db"))
	if v := queryStrings(t, db2, "SELECT key FROM meta WHERE key='redo:fake'"); len(v) != 0 {
		t.Errorf("redo marker should be cleared: %v", v)
	}
}

// SIGINT and SIGTERM exit 130 with the same guarantees.
func TestSignals(t *testing.T) {
	for name, sig := range map[string]syscall.Signal{"SIGINT": syscall.SIGINT, "SIGTERM": syscall.SIGTERM, "SIGHUP": syscall.SIGHUP} {
		t.Run(name, func(t *testing.T) {
			out := t.TempDir()
			c1 := startChild(t, out, childOpts{n: nChecks, delay: 60 * time.Millisecond, args: []string{"a.com", "--concurrency", "2"}})
			waitFor(t, "some checks", func() bool { return len(c1.executed()) >= 6 })
			c1.kill(sig)
			if code := c1.wait(); code != 130 {
				t.Fatalf("exit %d, want 130", code)
			}
			assertOutputsIntact(t, out)
			done := committed(t, out)
			if len(done) == 0 || len(done) == nChecks {
				t.Fatalf("expected a partial run, got %d recorded", len(done))
			}
			if _, err := os.Stat(filepath.Join(engDirOf(out), "scope.csv")); err != nil {
				t.Error("outputs must be rendered on interrupt")
			}
			finishAndCheck(t, out, setDiff(allKeys(nChecks), done), childOpts{args: []string{"-e", "a.com"}})
		})
	}
}
