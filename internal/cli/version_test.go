package cli_test

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/rafaelh/recon/internal/cli"
)

// --version prints "recon <version>" and exits without doing any work.
func TestVersionFlag(t *testing.T) {
	h := newHarness(t, noop())
	h.version = "v0.0.0-20261106032157-7e34c1b8d74f"
	if code := h.exec("--version"); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, h.stderr.String())
	}
	if got, want := h.stdout.String(), "recon "+h.version+"\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
	if h.stderr.Len() != 0 {
		t.Errorf("stderr = %q", h.stderr.String())
	}
	if entries, _ := os.ReadDir(h.out); len(entries) != 0 {
		t.Errorf("--version created %d entries in the output dir", len(entries))
	}
	if h.network() != 0 {
		t.Error("--version made network contact")
	}
}

// With no Version in Deps (as the test harnesses build them), the version is "devel".
func TestVersionFlagZeroDeps(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Execute(context.Background(), []string{"--version"}, cli.Deps{Stdout: &stdout, Stderr: &stderr})
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}
	if got := stdout.String(); got != "recon devel\n" {
		t.Errorf("stdout = %q", got)
	}
}

// With --json every stdout line must be JSON, so the version line goes to stderr.
func TestVersionFlagJSON(t *testing.T) {
	h := newHarness(t, noop())
	h.version = "v1.2.3"
	if code := h.exec("--json", "--version"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if h.stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", h.stdout.String())
	}
	if got := h.stderr.String(); got != "recon v1.2.3\n" {
		t.Errorf("stderr = %q", got)
	}
}

// Every spelling pflag accepts for --json counts, and the last one wins.
func TestVersionFlagJSONSpellings(t *testing.T) {
	cases := []struct {
		args []string
		json bool
	}{
		{[]string{"--json=1", "--version"}, true},
		{[]string{"--json=True", "--version"}, true},
		{[]string{"--json=t", "--version"}, true},
		{[]string{"--version", "--json"}, true},
		{[]string{"--json", "--json=false", "--version"}, false},
		{[]string{"--json=0", "--version"}, false},
	}
	for _, c := range cases {
		h := newHarness(t, noop())
		h.version = "v1.2.3"
		if code := h.exec(c.args...); code != 0 {
			t.Fatalf("%v: exit %d", c.args, code)
		}
		out, other := h.stdout.String(), h.stderr.String()
		if c.json {
			out, other = other, out
		}
		if out != "recon v1.2.3\n" || other != "" {
			t.Errorf("%v: stdout %q, stderr %q", c.args, h.stdout.String(), h.stderr.String())
		}
	}
}

// --version is long-only; -v must not become a shorthand that could be mistaken for --verbose.
func TestNoVersionShorthand(t *testing.T) {
	h := newHarness(t, noop())
	if code := h.exec("-v"); code != 2 {
		t.Errorf("-v: exit %d, want 2 (unknown shorthand)", code)
	}
}
