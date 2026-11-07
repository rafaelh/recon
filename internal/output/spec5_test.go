package output_test

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/inventory"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/output"
	"github.com/rafaelh/recon/internal/provider"
	"github.com/rafaelh/recon/internal/scope"
	"github.com/rafaelh/recon/internal/store"
)

// The findings files' columns and rows are tested in the findings package;
// TestDefaultRegistry checks that they are registered.

func snapshot(recs map[string][]store.Record) output.Snapshot {
	inv := inventory.New(inventory.Data{}, provider.Default())
	sc := scope.New(scope.Config{Roots: []string{"example.com"}, Netblocks: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}})
	return output.Snapshot{Today: "2026-11-01", Records: recs, Scope: sc, Inv: inv}
}

func file(t *testing.T, name string) output.File {
	t.Helper()
	for _, f := range output.Default() {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("no file %s", name)
	return output.File{}
}

func srec(kind, key string, current bool, kv ...any) store.Record {
	a := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		a[kv[i].(string)] = kv[i+1]
	}
	return store.Record{Kind: kind, Key: key, Current: current, Attrs: a, FirstSeen: "2026-10-01", LastSeen: "2026-11-01"}
}

func cellMap(f output.File, r output.Row) map[string]string {
	m := map[string]string{}
	for i, c := range f.Columns {
		m[c] = r.Cells[i]
	}
	return m
}

// D13: email-posture.csv has one row per in-scope root.
func TestEmailPostureFile(t *testing.T) {
	snap := snapshot(map[string][]store.Record{"email_posture": {
		srec("email_posture", "example.com", true, "mx", "mail.example.com", "spf", "v=spf1 -all", "spf_lookups", 3.0,
			"dmarc", "v=DMARC1; p=none", "dmarc_policy", "none", "dkim_selectors", "google;k1"),
		srec("email_posture", "other.org", true, "spf", "v=spf1 -all"),
	}})
	f := file(t, "email-posture.csv")
	if !slices.Equal(f.Columns, []string{"root", "mx", "spf", "spf_lookups", "dmarc", "dmarc_policy", "dkim_selectors"}) {
		t.Errorf("columns = %v", f.Columns)
	}
	rows := f.Rows(snap)
	if len(rows) != 1 {
		t.Fatalf("rows = %v", rows)
	}
	got := cellMap(f, rows[0])
	if got["root"] != "example.com" || got["spf_lookups"] != "3" || got["dkim_selectors"] != "google;k1" || got["dmarc_policy"] != "none" {
		t.Errorf("row = %v", got)
	}
}

// A findings file is written with the dates of the record each row lists.
func TestFindingsFileRows(t *testing.T) {
	snap := snapshot(map[string][]store.Record{"finding": {
		srec("finding", "email|spf-missing|example.com", false),
	}})
	rows := file(t, "risk-email.csv").Rows(snap)
	if len(rows) != 1 || rows[0].Current || rows[0].FirstSeen != "2026-10-01" || rows[0].LastSeen != "2026-11-01" {
		t.Errorf("rows = %+v", rows)
	}
	if got := cellMap(file(t, "risk-email.csv"), rows[0]); got["root"] != "example.com" || got["type"] != "spf-missing" {
		t.Errorf("row = %v", got)
	}
}

// candidates.csv and excluded.csv list exactly what the summary counts: a
// netblock key that does not parse is neither, and a value excluded under
// several records is one excluded row, shown as current while any record is.
func TestCandidateExcludedFilesMatchTotals(t *testing.T) {
	inv := inventory.New(inventory.Data{}, provider.Default())
	x, err := input.ParseExclusion("bad.example.com")
	if err != nil {
		t.Fatal(err)
	}
	sc := scope.New(scope.Config{Roots: []string{"example.com"}, Netblocks: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		Exclusions: []input.Exclusion{x}})
	recs := map[string][]store.Record{
		"hostname": {srec("hostname", "www.example.com", true), srec("hostname", "www.other.org", true),
			srec("hostname", "bad.example.com", false)},
		"root":     {srec("root", "other.org", true)},
		"netblock": {srec("netblock", "198.51.100.0/24", true), srec("netblock", "203.0.113.0/24", true), srec("netblock", "not-a-prefix", true)},
		"excluded": {srec("excluded", "bad.example.com", true, "reason", "guard"), srec("excluded", "192.0.2.1", true, "reason", "guard")},
	}
	vis := kinds.NewVisibility(sc, inv)
	snap := output.Snapshot{Today: "2026-11-01", Records: recs, Scope: sc, Inv: inv, Vis: vis}
	totals := vis.Totals(recs)
	current := func(name string) (n int, values []string) {
		for _, r := range file(t, name).Rows(snap) {
			if r.Current {
				n++
			}
			values = append(values, r.Cells[0]+"/"+r.Cells[len(r.Cells)-1])
		}
		return n, values
	}
	if n, v := current("candidates.csv"); n != totals[kinds.Candidates] || n != 3 {
		t.Errorf("candidates.csv current rows = %d %v, totals = %d", n, v, totals[kinds.Candidates])
	}
	if n, v := current("excluded.csv"); n != totals[kinds.Excluded] || n != 2 || len(v) != 2 {
		t.Errorf("excluded.csv current rows = %d %v, totals = %d", n, v, totals[kinds.Excluded])
	}
}
