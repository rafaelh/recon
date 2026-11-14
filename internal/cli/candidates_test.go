package cli_test

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/testkit"
)

// src is a fake stage named after a real source. Each of its check keys finds
// the observations listed under that key; a test edits finds between runs.
type src struct {
	*testkit.Stage
	finds map[string][]run.Observation
}

func newSrc(name string, finds map[string][]run.Observation) *src {
	s := &src{finds: finds}
	s.Stage = &testkit.Stage{StageName: name, Kind: run.ThirdParty,
		ChecksFn: func(run.View) []run.Check {
			var out []run.Check
			for _, k := range slices.Sorted(maps.Keys(s.finds)) {
				out = append(out, run.Check{Key: k})
			}
			return out
		},
		RunFn: func(_ context.Context, c run.Check, _ egress.Clients) ([]run.Observation, error) {
			return s.finds[c.Key], nil
		}}
	return s
}

// pivot is a stage whose check keys are "<source>:<item>|<settings>": like a
// stage that reports the mechanism that found a candidate, and whose key
// carries a setting, it says so through Evidence.
type pivot struct{ *src }

func (pivot) Evidence(key string) (source, item string) {
	source, item, _ = strings.Cut(key, ":")
	item, _, _ = strings.Cut(item, "|")
	return source, item
}

func root(v string) run.Observation { return obs("root", v) }
func host(v string) run.Observation { return obs("hostname", v) }
func block(v string) run.Observation {
	return obs("netblock", v)
}

func finds(keyAndObs ...any) map[string][]run.Observation {
	m := map[string][]run.Observation{}
	for i := 0; i+1 < len(keyAndObs); i += 2 {
		found, _ := keyAndObs[i+1].([]run.Observation) // nil: the check finds nothing
		m[keyAndObs[i].(string)] = found
	}
	return m
}

func list(o ...run.Observation) []run.Observation { return o }

// candidateRows are the rows of candidates.csv by column name.
func candidateRows(t *testing.T, h *harness, eng string) []map[string]string {
	t.Helper()
	recs := csvRows(t, h.readOut(eng, "candidates.csv"))
	var out []map[string]string
	for _, r := range recs[1:] {
		m := map[string]string{}
		for i, c := range recs[0] {
			m[c] = r[i]
		}
		out = append(out, m)
	}
	return out
}

func values(rows []map[string]string) string {
	var out []string
	for _, r := range rows {
		out = append(out, r["value"])
	}
	return strings.Join(out, " ")
}

func rowOf(t *testing.T, rows []map[string]string, value string) map[string]string {
	t.Helper()
	r := find(rows, "value", value)
	if r == nil {
		t.Fatalf("no candidates.csv row for %s in %v", value, rows)
	}
	return r
}

func wantRow(t *testing.T, r map[string]string, sources, count, confidence string) {
	t.Helper()
	if r["sources"] != sources || r["evidence_count"] != count || r["confidence"] != confidence {
		t.Errorf("%s: sources=%q evidence_count=%q confidence=%q, want %q %q %q", r["value"], r["sources"], r["evidence_count"], r["confidence"], sources, count, confidence)
	}
}

// candidates.csv has sources, evidence_count and confidence in place of
// found_by, and is sorted high first, then by evidence, then by value.
func TestCandidates_ColumnsAndOrder(t *testing.T) {
	h := newHarness(t,
		newSrc("whoisxml", finds("Acme", list(root("high.org"), root("med.org")))),
		newSrc("certspotter", finds("k1", list(root("high.org")))),
		newSrc("wayback", finds("k2", list(root("three.org")))),
		newSrc("crtsh", finds("k3", list(root("three.org")), "k5", list(root("low.org")), "k6", list(root("low.org")))),
		newSrc("otx", finds("k4", list(root("three.org")))),
	)
	if code := h.exec("a.com", "--org", "Acme"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if hdr := strings.SplitN(h.readOut("a.com", "candidates.csv"), "\n", 2)[0]; hdr != "type,value,sources,evidence_count,confidence,current,first_seen,last_seen" {
		t.Errorf("header = %s", hdr)
	}
	rows := candidateRows(t, h, "a.com")
	if got := values(rows); got != "three.org high.org med.org low.org" {
		t.Errorf("order = %s", got)
	}
	wantRow(t, rowOf(t, rows, "three.org"), "crtsh;otx;wayback", "3", "high")   // three families
	wantRow(t, rowOf(t, rows, "high.org"), "certspotter;whoisxml", "2", "high") // registrant match plus another family
	wantRow(t, rowOf(t, rows, "med.org"), "whoisxml", "1", "medium")            // registrant match alone
	wantRow(t, rowOf(t, rows, "low.org"), "crtsh", "2", "low")                  // two items, one family
	if r := rowOf(t, rows, "three.org"); r["type"] != "root" || r["current"] != "true" || r["first_seen"] != "2026-11-01" {
		t.Errorf("row = %v", r)
	}
}

// A row that is not current is last, with the confidence it last had; it is
// not listed in the summary.
func TestCandidates_NotCurrentSortsLastWithLastConfidence(t *testing.T) {
	pv := pivot{newSrc("pivot", finds("crtsh:a", list(root("x.org")), "wayback:b", list(root("x.org")), "otx:c", list(root("x.org"))))}
	h := newHarness(t, pv, newSrc("crtsh", finds("k", list(root("y.org")))))
	if code := h.exec("a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	rows := candidateRows(t, h, "a.com")
	if values(rows) != "x.org y.org" {
		t.Fatalf("first run order = %s", values(rows))
	}
	wantRow(t, rows[0], "crtsh;otx;wayback", "3", "high")

	pv.finds = finds("crtsh:a", nil, "wayback:b", nil, "otx:c", nil) // x.org is no longer found
	if code := h.exec("-e", "a.com", "--redo", "pivot", "--json"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	rows = candidateRows(t, h, "a.com")
	if values(rows) != "y.org x.org" {
		t.Fatalf("a not-current row sorts last whatever it had: %s", values(rows))
	}
	if rows[0]["current"] != "true" || rows[1]["current"] != "false" {
		t.Errorf("current = %s, %s", rows[0]["current"], rows[1]["current"])
	}
	wantRow(t, rows[1], "crtsh;otx;wayback", "3", "high")
	for _, e := range ofType(h.events(), "candidate") {
		t.Errorf("a candidate that is not current is not listed: %v", e)
	}
}

// A redo forgets the checks of its stage before they run again. When another
// stage does work first, the ranks are derived in between; a candidate whose
// only support is the redone stage keeps the rank it had, so that if the stage
// then no longer finds it, the row shows the confidence it last had while
// supported, not an empty one.
func TestCandidates_NotCurrentAfterRedoKeepsTheRankItHadWhileSupported(t *testing.T) {
	early := newSrc("asn", finds("k1", nil))
	who := newSrc("whoisxml", finds("Acme", list(root("x.org"))))
	h := newHarness(t, early, who)
	if code := h.exec("a.com", "--org", "Acme"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	wantRow(t, rowOf(t, candidateRows(t, h, "a.com"), "x.org"), "whoisxml", "1", "medium")

	early.finds = finds("k1", nil, "k2", nil) // does work before whoisxml runs again
	who.finds = finds("Acme", nil)            // x.org is no longer found
	if code := h.exec("-e", "a.com", "--redo", "whoisxml"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	r := rowOf(t, candidateRows(t, h, "a.com"), "x.org")
	if r["current"] != "false" {
		t.Fatalf("x.org should no longer be current: %v", r)
	}
	wantRow(t, r, "whoisxml", "1", "medium")
}

// The same holds for a root that a hostname under it also supports: the
// hostname's evidence does not make the root current, so while the redone
// stage is pending the root keeps the rank it had with both.
func TestCandidates_RootAwaitingRedoKeepsItsRankDespiteItsHostnames(t *testing.T) {
	early := newSrc("asn", finds("k1", nil))
	who := newSrc("whoisxml", finds("Acme", list(root("x.org"))))
	h := newHarness(t, early, who, newSrc("httpprobe", finds("a.com:443", list(host("www.x.org")))))
	if code := h.exec("a.com", "--org", "Acme"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	wantRow(t, rowOf(t, candidateRows(t, h, "a.com"), "x.org"), "httpprobe;whoisxml", "2", "high")

	early.finds = finds("k1", nil, "k2", nil) // does work before whoisxml runs again
	who.finds = finds("Acme", nil)            // x.org is no longer found
	if code := h.exec("-e", "a.com", "--redo", "whoisxml"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	r := rowOf(t, candidateRows(t, h, "a.com"), "x.org")
	if r["current"] != "false" {
		t.Fatalf("x.org should no longer be current: %v", r)
	}
	wantRow(t, r, "httpprobe;whoisxml", "2", "high")
}

// After a redo of a supporting stage that no longer finds the candidate, the
// candidate drops a level.
func TestCandidates_RedoLowersALevel(t *testing.T) {
	cs := newSrc("certspotter", finds("k", list(root("x.org"))))
	h := newHarness(t, newSrc("whoisxml", finds("Acme", list(root("x.org")))), cs)
	if code := h.exec("a.com", "--org", "Acme"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	wantRow(t, rowOf(t, candidateRows(t, h, "a.com"), "x.org"), "certspotter;whoisxml", "2", "high")

	cs.finds = finds("k", nil)
	if code := h.exec("-e", "a.com", "--redo", "certspotter"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	wantRow(t, rowOf(t, candidateRows(t, h, "a.com"), "x.org"), "whoisxml", "1", "medium")
}

// Confidence follows the evidence of every run: a stage that finds the
// candidate later raises it, with no redo.
func TestCandidates_RecomputedOnEveryRun(t *testing.T) {
	cs := newSrc("certspotter", finds())
	h := newHarness(t, newSrc("whoisxml", finds("Acme", list(root("x.org")))), cs)
	if code := h.exec("a.com", "--org", "Acme"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	wantRow(t, rowOf(t, candidateRows(t, h, "a.com"), "x.org"), "whoisxml", "1", "medium")

	cs.finds = finds("k", list(root("x.org")))
	if code := h.exec("-e", "a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	wantRow(t, rowOf(t, candidateRows(t, h, "a.com"), "x.org"), "certspotter;whoisxml", "2", "high")
}

// Without --org there is no registrant match: the same evidence is only as
// strong as the number of families that agree.
func TestCandidates_NoOrgInput(t *testing.T) {
	h := newHarness(t, newSrc("whoisxml", finds("Acme", list(root("x.org")))))
	if code := h.exec("a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	wantRow(t, rowOf(t, candidateRows(t, h, "a.com"), "x.org"), "whoisxml", "1", "low")
}

// A candidate root also counts the evidence of the candidate hostnames under
// it; each hostname keeps its own rank.
func TestCandidates_HostnameEvidenceRaisesItsRoot(t *testing.T) {
	h := newHarness(t,
		newSrc("whoisxml", finds("Acme", list(root("other.org")))),
		newSrc("httpprobe", finds("a.com:443", list(host("www.other.org")))),
	)
	if code := h.exec("a.com", "--org", "Acme"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	rows := candidateRows(t, h, "a.com")
	wantRow(t, rowOf(t, rows, "other.org"), "httpprobe;whoisxml", "2", "high")
	wantRow(t, rowOf(t, rows, "www.other.org"), "httpprobe", "1", "low")
}

// A stage reports the source and the item of its check through Evidence, so a
// setting in the key cannot count one piece of support twice; without it the
// stage name and the whole key are the source and the item.
func TestCandidates_EvidencerSetsSourceAndItem(t *testing.T) {
	probe := newSrc("httpprobe", finds("a.com:80", list(host("h1.other.org")), "a.com:443", list(host("h1.other.org"))))
	pv := pivot{newSrc("pivot", finds("crtsh:https://a.com|depth=2", list(host("h2.other.org")), "crtsh:https://a.com|depth=3", list(host("h2.other.org"))))}
	h := newHarness(t, probe, pv)
	if code := h.exec("a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	rows := candidateRows(t, h, "a.com")
	wantRow(t, rowOf(t, rows, "h1.other.org"), "httpprobe", "2", "low") // two keys, two pairs
	wantRow(t, rowOf(t, rows, "h2.other.org"), "crtsh", "1", "low")     // two keys, one item, source named by the stage
}

// A change to an evidence kind alone still re-derives the findings, with the
// candidate ranks unchanged.
func TestCandidates_FindingsStillDerivedWhenOnlyEvidenceChanges(t *testing.T) {
	spf := ""
	posture := &testkit.Stage{StageName: "posture", Kind: run.ThirdParty,
		ChecksFn: func(run.View) []run.Check { return testkit.Keys("p", 1) },
		RunFn: func(context.Context, run.Check, egress.Clients) ([]run.Observation, error) {
			return []run.Observation{obs("email_posture", "a.com", "mx", "mail.a.com", "spf", spf, "spf_records", 0,
				"dmarc", "v=DMARC1; p=reject", "dmarc_policy", "reject")}, nil
		}}
	h := newHarness(t, newSrc("whoisxml", finds("Acme", list(root("x.org")))), posture)
	if code := h.exec("a.com", "--org", "Acme"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	spfRows := func() []map[string]string {
		var out []map[string]string
		recs := csvRows(t, h.readOut("a.com", "risk-email.csv"))
		for _, r := range recs[1:] {
			m := map[string]string{}
			for i, c := range recs[0] {
				m[c] = r[i]
			}
			if m["type"] == "spf-missing" {
				out = append(out, m)
			}
		}
		return out
	}
	if rows := spfRows(); len(rows) != 1 || rows[0]["current"] != "true" {
		t.Fatalf("first run: spf-missing rows = %v\n%s", rows, h.readOut("a.com", "risk-email.csv"))
	}
	spf = "v=spf1 -all"
	if code := h.exec("-e", "a.com", "--redo", "posture"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if rows := spfRows(); len(rows) != 1 || rows[0]["current"] != "false" {
		t.Errorf("the finding is no longer derived once the evidence changes: %v", rows)
	}
	wantRow(t, rowOf(t, candidateRows(t, h, "a.com"), "x.org"), "whoisxml", "1", "medium")
}

// highSet is 23 high candidates (a netblock and 22 roots), one medium root and
// one low root.
func highSet() []*src {
	roots := list()
	for i := 0; i < 22; i++ {
		roots = append(roots, root(fmt.Sprintf("r%02d.org", i)))
	}
	return []*src{
		newSrc("whoisxml", finds("Acme", append(list(root("mid.org")), roots...))),
		newSrc("org-asn", finds("Acme", list(block("198.51.100.0/24")))),
		newSrc("certspotter", finds("k", roots)),
		newSrc("otx", finds("k", list(block("198.51.100.0/24"), root("low.org")))),
	}
}

func highHarness(t *testing.T) *harness {
	var stages []run.Stage
	for _, s := range highSet() {
		stages = append(stages, s)
	}
	return newHarness(t, stages...)
}

// The console lists up to 20 high candidates with the input that promotes each,
// then how many more there are; --verbose also lists the medium ones.
func TestCandidates_ConsoleSummary(t *testing.T) {
	h := highHarness(t)
	if code := h.exec("a.com", "--org", "Acme"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	out := h.stdout.String()
	if !strings.Contains(out, "promote: --cidr 198.51.100.0/24") || !strings.Contains(out, "promote: r00.org") || !strings.Contains(out, "promote: r18.org") {
		t.Errorf("high candidates are listed with their promoting input:\n%s", out)
	}
	for _, v := range []string{"r19.org", "r20.org", "r21.org"} {
		if strings.Contains(out, v) {
			t.Errorf("%s is past the 20 listed:\n%s", v, out)
		}
	}
	if !strings.Contains(out, "and 3 more in candidates.csv") {
		t.Errorf("missing the overflow line:\n%s", out)
	}
	if strings.Contains(out, "mid.org") || strings.Contains(out, "low.org") {
		t.Errorf("medium and low candidates are not listed without --verbose:\n%s", out)
	}

	if code := h.exec("-e", "a.com", "--org", "Acme", "--verbose"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	out = h.stdout.String()
	if !strings.Contains(out, "promote: mid.org") || strings.Contains(out, "low.org") {
		t.Errorf("--verbose lists the medium candidates, not the low ones:\n%s", out)
	}
}

// --json emits one candidate event per high candidate before the summary, and
// the summary carries the same list.
func TestCandidates_JSONEvents(t *testing.T) {
	h := highHarness(t)
	if code := h.exec("a.com", "--org", "Acme", "--json", "--verbose"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	evs := h.events()
	var cands []event
	summaryAt := -1
	for i, e := range evs {
		switch e.str("type") {
		case "candidate":
			if summaryAt >= 0 {
				t.Error("a candidate event came after the summary")
			}
			cands = append(cands, e)
		case "summary":
			summaryAt = i
		}
	}
	if len(cands) != 23 || summaryAt < 0 {
		t.Fatalf("%d candidate events, summary at %d", len(cands), summaryAt)
	}
	var nb event
	for _, e := range cands {
		if e.str("confidence") != "high" {
			t.Errorf("only high candidates: %v", e)
		}
		if e.str("value") == "198.51.100.0/24" {
			nb = e
		}
	}
	if nb == nil || nb.str("kind") != "netblock" || nb.str("promote") != "--cidr 198.51.100.0/24" ||
		nb.str("sources") != "org-asn;otx" || nb.num("evidence_count") != 2 {
		t.Errorf("netblock event = %v", nb)
	}
	listed, _ := evs[summaryAt]["candidates"].([]any)
	if len(listed) != 23 {
		t.Errorf("summary candidates = %d, want 23", len(listed))
	}
	if med, _ := evs[summaryAt]["medium_candidates"].([]any); len(med) != 1 {
		t.Errorf("--verbose summary medium_candidates = %v", evs[summaryAt]["medium_candidates"])
	}
}
