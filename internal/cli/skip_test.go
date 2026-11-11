package cli_test

import (
	"slices"
	"strings"
	"testing"
)

// A skipped stage is shown as not-configured (skipped) before any other reason,
// performs no checks and sends no requests.
func TestSkip_StateAndNoChecks(t *testing.T) {
	w := newWorld(t)
	w.crtsh(map[string][]string{"example.com": {"a.example.com"}}, nil)
	// virustotal has no key and httpprobe is passive-only: skipped wins over both.
	args := []string{"--passive", "--skip", "crtsh", "--skip", "virustotal", "--skip", "httpprobe", "example.com"}
	if code := w.run(args...); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, s := range []string{"crtsh", "virustotal", "httpprobe"} {
		if st, reason := stateOf(w, s); st != "not-configured" || reason != "skipped" {
			t.Errorf("%s = %s (%s), want not-configured (skipped)", s, st, reason)
		}
	}
	if st, reason := stateOf(w, "securitytrails"); reason != "no key" {
		t.Errorf("an unskipped stage keeps its own reason: securitytrails = %s (%s)", st, reason)
	}
	if st, reason := stateOf(w, "crawl"); reason != "passive-only" {
		t.Errorf("crawl = %s (%s), want passive-only", st, reason)
	}
	if n := len(w.requests("crt.sh")); n != 0 {
		t.Errorf("a skipped stage sent %d requests", n)
	}
	if done := w.h.completed(eng, "crtsh"); len(done) != 0 {
		t.Errorf("a skipped stage completed checks: %v", done)
	}
	if st, _ := stateOf(w, "otx"); st != "done" {
		t.Errorf("other stages still run: otx = %s", st)
	}
	// The console form.
	if code := w.h.exec("--passive", "--rate-per-source", "1000", "--rate-dns", "100000", "--skip", "crtsh", "-e", eng); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(w.h.stdout.String(), "not-configured (skipped)") {
		t.Errorf("console does not show not-configured (skipped):\n%s", w.h.stdout.String())
	}
}

// Skipping marks nothing not current: what a stage found earlier stays.
func TestSkip_KeepsEarlierResults(t *testing.T) {
	w := newWorld(t)
	w.crtsh(map[string][]string{"example.com": {"a.example.com"}}, nil)
	w.dns.A("a.example.com", "203.0.113.5")
	if code := w.run("--passive", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !slices.Contains(w.lines(eng, "subdomains.txt"), "a.example.com") {
		t.Fatalf("first run found nothing: %v", w.lines(eng, "subdomains.txt"))
	}
	before := len(w.requests("crt.sh"))
	if code := w.run("--passive", "--skip", "crtsh", "-e", eng); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got := w.lines(eng, "subdomains.txt"); !slices.Contains(got, "a.example.com") {
		t.Errorf("skipping crtsh dropped its name: %v", got)
	}
	if st, _ := stateOf(w, "crtsh"); st != "not-configured" {
		t.Errorf("crtsh = %s", st)
	}
	if done := w.h.completed(eng, "crtsh"); !slices.Equal(done, []string{"example.com"}) {
		t.Errorf("completed checks changed: %v", done)
	}
	if n := len(w.requests("crt.sh")); n != before {
		t.Errorf("crt.sh was queried while skipped: %d, then %d", before, n)
	}
}

func TestSkip_InvalidExits2(t *testing.T) {
	protected := []string{"resolve", "wildcard", "ipowner", "providerranges"}
	type tc struct {
		name        string
		args        []string
		want        string // in the message
		listsStages bool   // the message names the stages that can be skipped
	}
	cases := []tc{
		{"unknown stage", []string{"--skip", "nonesuch"}, "nonesuch", true},
		{"also redo", []string{"--skip", "crtsh", "--redo", "crtsh"}, "crtsh", true},
		{"none with names", []string{"--skip", "none", "--skip", "crtsh"}, "none", false},
	}
	for _, p := range protected {
		cases = append(cases, tc{"protected " + p, []string{"--skip", p}, p, true})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			if code := w.run(append(c.args, "--passive", "example.com")...); code != 2 {
				t.Fatalf("exit %d, want 2", code)
			}
			msg := strings.Join(messages(w, "error", ""), "; ")
			if !strings.Contains(msg, c.want) {
				t.Errorf("message %q does not mention %q", msg, c.want)
			}
			if c.listsStages {
				for _, stage := range []string{"crtsh", "otx", "certspotter"} {
					if !strings.Contains(msg, stage) {
						t.Errorf("message does not list the stage names (missing %s): %q", stage, msg)
					}
				}
			}
			if w.dns.Total() != 0 || len(w.requests("crt.sh")) != 0 || len(w.requests("otx.alienvault.com")) != 0 {
				t.Error("an invalid --skip must exit before any stage runs")
			}
		})
	}
}

// Naming an unknown stage in the environment or file exits 2 too.
func TestSkip_InvalidSettingExits2(t *testing.T) {
	w := newWorld(t)
	t.Setenv("RECON_SKIP", "crtsh,nonesuch")
	if code := w.run("--passive", "example.com"); code != 2 {
		t.Errorf("exit %d, want 2", code)
	}
}

// The flag, the file and RECON_SKIP all set the list; the flag replaces the
// setting for the run, and none clears it.
func TestSkip_SettingAndFlagPrecedence(t *testing.T) {
	skipped := func(w *world) []string {
		var out []string
		for _, s := range []string{"crtsh", "wayback", "otx", "anubis"} {
			if st, reason := stateOf(w, s); st == "not-configured" && reason == "skipped" {
				out = append(out, s)
			}
		}
		return out
	}
	t.Run("environment is comma separated", func(t *testing.T) {
		w := newWorld(t)
		t.Setenv("RECON_SKIP", "crtsh,wayback")
		w.run("--passive", "example.com")
		if got := skipped(w); !slices.Equal(got, []string{"crtsh", "wayback"}) {
			t.Errorf("skipped = %v", got)
		}
	})
	t.Run("file", func(t *testing.T) {
		w := newWorld(t)
		cfg := writeFile(t, t.TempDir(), "config.yaml", "skip: [crtsh, wayback]\n")
		w.run("--passive", "--config", cfg, "example.com")
		if got := skipped(w); !slices.Equal(got, []string{"crtsh", "wayback"}) {
			t.Errorf("skipped = %v", got)
		}
	})
	t.Run("flag replaces the setting", func(t *testing.T) {
		w := newWorld(t)
		t.Setenv("RECON_SKIP", "crtsh,wayback")
		w.run("--passive", "--skip", "otx", "--skip", "anubis", "example.com")
		if got := skipped(w); !slices.Equal(got, []string{"otx", "anubis"}) {
			t.Errorf("skipped = %v", got)
		}
	})
	t.Run("none runs every stage", func(t *testing.T) {
		w := newWorld(t)
		t.Setenv("RECON_SKIP", "crtsh,wayback")
		w.run("--passive", "--skip", "none", "example.com")
		if got := skipped(w); len(got) != 0 {
			t.Errorf("skipped = %v, want nothing", got)
		}
		if n := len(w.requests("crt.sh")); n == 0 {
			t.Error("crtsh did not run")
		}
	})
}

// When every stage that contacts the target is skipped there is nothing to
// authorise, so there is no prompt.
func TestSkip_NoPromptWhenEveryTargetStageIsSkipped(t *testing.T) {
	const prompt = "Confirm you are authorised"
	runConsole := func(w *world, extra ...string) {
		w.h.stdinTTY = true
		w.h.stdin = "n\n"
		args := append([]string{"--rate-per-source", "1000", "--rate-dns", "100000"}, extra...)
		if code := w.h.exec(append(args, "example.com")...); code != 0 {
			t.Fatalf("exit %d: %s", code, w.h.stderr.String())
		}
	}

	w := newWorld(t)
	runConsole(w)
	if !strings.Contains(w.h.stderr.String(), prompt) {
		t.Fatalf("control: expected a prompt with target stages enabled; stderr = %q", w.h.stderr.String())
	}

	w = newWorld(t)
	runConsole(w, "--skip", "httpprobe", "--skip", "crawl")
	if strings.Contains(w.h.stderr.String(), prompt) {
		t.Errorf("prompted although every target stage is skipped: %q", w.h.stderr.String())
	}

	w = newWorld(t)
	runConsole(w, "--skip", "httpprobe")
	if !strings.Contains(w.h.stderr.String(), prompt) {
		t.Error("crawl still contacts the target, so the prompt is needed")
	}
}
