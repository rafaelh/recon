package cli_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/testkit"
)

// costed returns checks c0, c1, ... with the given costs.
func costed(costs ...int) []run.Check {
	var out []run.Check
	for i, c := range costs {
		out = append(out, run.Check{Key: fmt.Sprintf("c%d", i), Cost: c})
	}
	return out
}

func budgeted(limit int, checks func(v run.View) []run.Check) *testkit.Budgeted {
	return &testkit.Budgeted{Stage: &testkit.Stage{StageName: "budgeted", Kind: run.ThirdParty, ChecksFn: checks}, Limit: limit}
}

// deferredOf is the summary event's count of deferred work for a stage.
func deferredOf(t *testing.T, h *harness, stage string) int {
	t.Helper()
	sum := h.summaryEvent()
	m, ok := sum["deferred"].(map[string]any)
	if !ok {
		t.Fatalf("summary has no deferred object: %v", sum)
	}
	n, _ := m[stage].(float64)
	return int(n)
}

// deferredBlock is the console summary's "Deferred to the next run" block.
func deferredBlock(t *testing.T, out string) string {
	t.Helper()
	i := strings.Index(out, "Deferred to the next run")
	if i < 0 {
		t.Fatalf("the console summary has no deferred block:\n%s", out)
	}
	return out[i:]
}

// The first check that would pass the budget, and every check after it, is
// deferred. Deferred checks are not run, not failed and not recorded, and the
// stage shows done.
func TestBudget_StopsAtFirstOverflow(t *testing.T) {
	st := budgeted(3, func(run.View) []run.Check { return costed(1, 1, 1, 1, 1) })
	h := newHarness(t, st)
	if code := h.exec("--json", "a.com"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if got := ran(st); !slices.Equal(got, []string{"c0", "c1", "c2"}) {
		t.Errorf("executed = %v, want c0 c1 c2", got)
	}
	state := lastState(h.events(), "budgeted")
	if state.str("state") != "done" || state.num("checks") != 3 || state.num("failed") != 0 {
		t.Errorf("state = %v, want done with 3 checks and none failed", state)
	}
	if got := h.completed("a.com", "budgeted"); !slices.Equal(got, []string{"c0", "c1", "c2"}) {
		t.Errorf("completed = %v", got)
	}
	if n := deferredOf(t, h, "budgeted"); n != 2 {
		t.Errorf("deferred = %d, want 2", n)
	}
}

// A check is deferred when it would pass the budget, not when the budget is
// already spent, and the checks after it wait even if they are cheaper.
func TestBudget_CostsAddUpAndLaterChecksWait(t *testing.T) {
	st := budgeted(10, func(run.View) []run.Check { return costed(4, 4, 3, 1, 1) })
	h := newHarness(t, st)
	h.exec("--json", "a.com")
	if got := ran(st); !slices.Equal(got, []string{"c0", "c1"}) {
		t.Errorf("executed = %v, want c0 c1 (c2 would reach 11, and c3 and c4 follow it)", got)
	}
	if n := deferredOf(t, h, "budgeted"); n != 5 {
		t.Errorf("deferred = %d, want 5 (the cost of c2, c3 and c4)", n)
	}
}

// A cost of 0 counts as 1.
func TestBudget_ZeroCostIsOne(t *testing.T) {
	st := budgeted(2, func(run.View) []run.Check { return costed(0, 0, 0) })
	h := newHarness(t, st)
	h.exec("--json", "a.com")
	if got := ran(st); len(got) != 2 {
		t.Errorf("executed = %v, want two", got)
	}
}

// The first pending check of the run is taken even when it alone exceeds the
// budget, so a run always makes progress.
func TestBudget_FirstCheckAlwaysTaken(t *testing.T) {
	st := budgeted(3, func(run.View) []run.Check { return costed(10, 1) })
	h := newHarness(t, st)
	h.exec("--json", "a.com")
	if got := ran(st); !slices.Equal(got, []string{"c0"}) {
		t.Errorf("executed = %v, want only the oversized c0", got)
	}
	if n := deferredOf(t, h, "budgeted"); n != 1 {
		t.Errorf("deferred = %d, want 1", n)
	}
	// And it is the next run's first check that goes next.
	h.exec("--json", "-e", "a.com")
	if got := ran(st); !slices.Equal(got, []string{"c0", "c1"}) {
		t.Errorf("after the second run executed = %v", got)
	}
}

// Completed checks cost nothing, so each run does the next slice of the work
// and the last run defers nothing.
func TestBudget_RemainderRunsNextTime(t *testing.T) {
	st := budgeted(2, func(run.View) []run.Check { return costed(1, 1, 1, 1, 1) })
	h := newHarness(t, st)
	h.exec("--json", "a.com")
	want := [][]string{{"c0", "c1"}, {"c2", "c3"}, {"c4"}}
	wantDeferred := []int{3, 1, 0}
	var all []string
	for i, w := range want {
		if i > 0 {
			h.exec("--json", "-e", "a.com")
		}
		all = append(all, w...)
		if got := ran(st); !slices.Equal(got, all) {
			t.Fatalf("after run %d executed = %v, want %v", i+1, got, all)
		}
		if n := deferredOf(t, h, "budgeted"); n != wantDeferred[i] {
			t.Errorf("run %d deferred = %d, want %d", i+1, n, wantDeferred[i])
		}
	}
	// Nothing left: the stage has nothing to do and runs nothing.
	h.exec("--json", "-e", "a.com")
	if got := ran(st); len(got) != 5 {
		t.Errorf("a finished stage ran again: %v", got)
	}
}

// Within one run the budget is spent across passes: the exception for the
// first check does not take a second overflowing check in a later pass.
func TestBudget_LaterPassDoesNotTakeAnotherOverflowingCheck(t *testing.T) {
	passes := 0
	st := budgeted(3, func(run.View) []run.Check {
		passes++
		if passes == 1 {
			return costed(10)
		}
		return costed(10, 10) // c1 appears in a later pass
	})
	h := newHarness(t, st)
	h.exec("--json", "a.com")
	if got := ran(st); !slices.Equal(got, []string{"c0"}) {
		t.Errorf("executed = %v, want only c0", got)
	}
	if passes < 2 {
		t.Fatalf("the stage was enumerated in %d pass(es); the test needs a later pass", passes)
	}
	if n := deferredOf(t, h, "budgeted"); n != 10 {
		t.Errorf("deferred = %d, want the last pass's 10", n)
	}
}

// A stage without a budget is not limited, however many checks it has.
func TestBudget_UnbudgetedStageIsUnlimited(t *testing.T) {
	plain := &testkit.Stage{StageName: "plain", Kind: run.ThirdParty, ChecksFn: func(run.View) []run.Check { return costed(5, 5, 5) }}
	h := newHarness(t, plain, budgeted(1, func(run.View) []run.Check { return nil }))
	h.exec("--json", "a.com")
	if got := ran(plain); len(got) != 3 {
		t.Errorf("executed = %v", got)
	}
	if n := deferredOf(t, h, "plain"); n != 0 {
		t.Errorf("deferred = %d", n)
	}
}

// A check that fails still spent its share of the budget in this run, and the
// deferred checks are not counted as failures.
func TestBudget_FailedCheckSpendsBudgetDeferredAreNotFailures(t *testing.T) {
	st := budgeted(2, func(run.View) []run.Check { return costed(1, 1, 1) })
	st.RunFn = func(_ context.Context, c run.Check, _ egress.Clients) ([]run.Observation, error) {
		if c.Key == "c0" {
			return nil, fmt.Errorf("transient")
		}
		return nil, nil
	}
	h := newHarness(t, st)
	h.exec("--json", "a.com")
	if got := ran(st); !slices.Equal(got, []string{"c0", "c1"}) {
		t.Errorf("executed = %v, want c0 c1 (the failed c0 spent its budget; c2 waits)", got)
	}
	if state := lastState(h.events(), "budgeted"); state.num("checks") != 2 || state.num("failed") != 1 {
		t.Errorf("state = %v, want 2 checks and 1 failed", state)
	}
}

// With nothing deferred the console says nothing about it; with something
// deferred it lists each stage under its own heading.
func TestBudget_ConsoleBlock(t *testing.T) {
	st := budgeted(2, func(run.View) []run.Check { return costed(1, 1, 1, 1) })
	h := newHarness(t, st)
	h.exec("a.com")
	if block := deferredBlock(t, h.stdout.String()); !strings.Contains(block, "budgeted") || !strings.Contains(block, "2") {
		t.Errorf("block does not give the stage and count:\n%s", block)
	}
	h.exec("-e", "a.com")
	if strings.Contains(h.stdout.String(), "Deferred to the next run") {
		t.Errorf("nothing was deferred, yet the console says so:\n%s", h.stdout.String())
	}
}

// Redoing a budgeted stage that retires what it no longer yields keeps the
// earlier hits of the checks it defers current: they are still valid checks,
// only not repeated yet. A hit whose check ran again is replaced by the new result.
func TestBudget_RedoKeepsDeferredHitsCurrent(t *testing.T) {
	hit := func(_ context.Context, c run.Check, _ egress.Clients) ([]run.Observation, error) {
		return []run.Observation{obs("hostname", "host-"+c.Key+".a.com")}, nil
	}
	checks := func(run.View) []run.Check { return costed(1, 1, 1, 1) }
	st := &retiringBudgeted{Budgeted: *budgeted(100, checks)}
	st.RunFn = hit
	h := newHarness(t, st)
	h.exec("--json", "a.com")
	want := []string{"host-c0.a.com", "host-c1.a.com", "host-c2.a.com", "host-c3.a.com"}
	if got := h.lines("a.com", "subdomains.txt"); !slices.Equal(got, want) {
		t.Fatalf("setup: subdomains = %v", got)
	}

	st.Limit = 1
	st.Reset()
	h.exec("--json", "-e", "a.com", "--redo", "budgeted")
	if got := ran(st); !slices.Equal(got, []string{"c0"}) {
		t.Errorf("redo executed = %v, want only c0", got)
	}
	if got := h.lines("a.com", "subdomains.txt"); !slices.Equal(got, want) {
		t.Errorf("after the budgeted redo subdomains = %v, want all four still current", got)
	}
	if n := deferredOf(t, h, "budgeted"); n != 3 {
		t.Errorf("deferred = %d, want 3", n)
	}
}

// ran are the keys a fake stage has executed, sorted: workers run concurrently.
func ran(s interface{ Executed() []string }) []string {
	return slices.Sorted(slices.Values(s.Executed()))
}

// retiringBudgeted is a budgeted stage that also retires the checks it no longer yields.
type retiringBudgeted struct{ testkit.Budgeted }

func (retiringBudgeted) RetiresUnlistedChecks() {}
