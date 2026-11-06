package output_test

import (
	"encoding/csv"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/inventory"
	"github.com/rafaelh/recon/internal/output"
	"github.com/rafaelh/recon/internal/provider"
	"github.com/rafaelh/recon/internal/scope"
	"github.com/rafaelh/recon/internal/store"
)

func rows(rs ...output.Row) func(output.Snapshot) []output.Row {
	return func(output.Snapshot) []output.Row { return rs }
}

func read(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func newDir(t *testing.T) string {
	d := t.TempDir()
	os.MkdirAll(filepath.Join(d, ".recon"), 0o700)
	return d
}

// B20: TXT lists current records only, sorted; CSV lists all with date and currency columns.
func TestTXTAndCSV(t *testing.T) {
	dir := newDir(t)
	rs := rows(
		output.Row{Cells: []string{"b.example.com", "x"}, Current: true, FirstSeen: "2026-11-01", LastSeen: "2026-11-02"},
		output.Row{Cells: []string{"a.example.com", "y"}, Current: true, FirstSeen: "2026-11-01", LastSeen: "2026-11-01"},
		output.Row{Cells: []string{"gone.example.com", "z"}, Current: false, FirstSeen: "2026-10-01", LastSeen: "2026-10-05"},
	)
	files := []output.File{
		{Name: "list.txt", Format: output.TXT, Rows: rs},
		{Name: "table.csv", Format: output.CSV, Columns: []string{"host", "src"}, Rows: rs},
	}
	if err := output.Render(dir, files, output.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	if got := read(t, dir, "list.txt"); got != "a.example.com\nb.example.com\n" {
		t.Errorf("txt = %q", got)
	}
	recs, err := csv.NewReader(strings.NewReader(read(t, dir, "table.csv"))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"host", "src", "current", "first_seen", "last_seen"},
		{"a.example.com", "y", "true", "2026-11-01", "2026-11-01"},
		{"b.example.com", "x", "true", "2026-11-01", "2026-11-02"},
		{"gone.example.com", "z", "false", "2026-10-01", "2026-10-05"},
	}
	if len(recs) != len(want) {
		t.Fatalf("csv = %v", recs)
	}
	for i := range want {
		if strings.Join(recs[i], "|") != strings.Join(want[i], "|") {
			t.Errorf("row %d = %v, want %v", i, recs[i], want[i])
		}
	}
}

// A file with no rows is not written, and one that had rows is removed once it has none.
// A TXT file lists current rows only, so one with no current rows counts as empty.
func TestEmptyFilesNotWritten(t *testing.T) {
	dir := newDir(t)
	gone := output.Row{Cells: []string{"gone.example.com"}, Current: false}
	files := []output.File{
		{Name: "e.txt", Format: output.TXT, Rows: rows()},
		{Name: "stale.txt", Format: output.TXT, Rows: rows(gone)},
		{Name: "e.csv", Format: output.CSV, Columns: []string{"a"}, Rows: rows()},
	}
	for _, f := range files {
		os.WriteFile(filepath.Join(dir, f.Name), []byte("old\n"), 0o644)
	}
	if err := output.Render(dir, files, output.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if _, err := os.Stat(filepath.Join(dir, f.Name)); !os.IsNotExist(err) {
			t.Errorf("%s: want no file, got err %v", f.Name, err)
		}
	}
	if err := output.Render(dir, files, output.Snapshot{}); err != nil {
		t.Errorf("rendering again with nothing to remove: %v", err)
	}
}

// B20: CSV injection and control characters.
func TestCSVSafety(t *testing.T) {
	dir := newDir(t)
	files := []output.File{{Name: "t.csv", Format: output.CSV, Columns: []string{"a", "b"}, Rows: rows(
		output.Row{Cells: []string{"=cmd()", "+1"}, Current: true},
		output.Row{Cells: []string{"-2", "@sum"}, Current: true},
		output.Row{Cells: []string{"\tx", "\rx"}, Current: true},
		output.Row{Cells: []string{"ok\x1b[31mred\x00", "line\nbreak"}, Current: true},
	)}}
	if err := output.Render(dir, files, output.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(strings.NewReader(read(t, dir, "t.csv"))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range recs[1:] {
		got[r[0]+"|"+r[1]] = true
	}
	for _, w := range []string{"'=cmd()|'+1", "'-2|'@sum", "'x|'x", "ok[31mred|linebreak"} {
		if !got[w] {
			t.Errorf("missing %q in %v", w, got)
		}
	}
	for _, r := range recs {
		for _, c := range r {
			if strings.ContainsAny(c, "\x00\x1b\n") {
				t.Errorf("control character survived in %q", c)
			}
		}
	}
}

// B20/B7/D12: rendered through .recon/tmp then renamed; no leftovers; sweep clears stale temp files.
func TestAtomicRenderAndSweep(t *testing.T) {
	dir := newDir(t)
	f := output.File{Name: "a.txt", Format: output.TXT, Rows: rows(output.Row{Cells: []string{"one"}, Current: true})}
	if err := output.Render(dir, []output.File{f}, output.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, ".recon", "tmp"))
	if len(entries) != 0 {
		t.Errorf("temp files left behind: %v", entries)
	}
	// A stale partial file from a crash.
	os.MkdirAll(filepath.Join(dir, ".recon", "tmp"), 0o700)
	stale := filepath.Join(dir, ".recon", "tmp", "a.txt")
	os.WriteFile(stale, []byte("partial"), 0o600)
	if err := output.Sweep(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("sweep should remove stale temp files")
	}
	if read(t, dir, "a.txt") != "one\n" {
		t.Error("sweep must not touch rendered files")
	}
}

// Spec 1 registered scope, candidates and excluded; Spec 2 adds the DNS files (D27);
// Spec 3 adds the web files, Spec 4 open-ports.csv.
func TestDefaultRegistry(t *testing.T) {
	var names []string
	for _, f := range output.Default() {
		names = append(names, f.Name)
		if f.Format == output.CSV {
			if len(f.Columns) == 0 {
				t.Errorf("%s has no columns", f.Name)
			}
		}
	}
	if strings.Join(names, ",") != "scope.csv,candidates.csv,excluded.csv,subdomains.txt,resolutions.csv,unresolved.txt,wildcard-excluded.txt,ips.csv,provider-hosts.csv,web-services.csv,urls.csv,open-ports.csv,email-posture.csv,storage-unattributed.csv,risk-takeover.csv,risk-storage.csv,risk-sensitive-paths.csv,risk-email.csv,risk-ports.csv,risk-certificates.csv" {
		t.Errorf("default files = %v", names)
	}
}

// Spec 4 D9: an open_port is shown only while its address is port-eligible.
func TestPortVisible(t *testing.T) {
	d := inventory.Data{
		Resolutions: []inventory.Resolution{{Name: "www.example.com", Type: "A", Value: "203.0.113.5"}, {Name: "cdn.example.com", Type: "A", Value: "104.16.0.1"}},
		IPs:         []netip.Addr{netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("104.16.0.1")},
		Owners: map[netip.Addr]provider.Owner{
			netip.MustParseAddr("203.0.113.5"): {ASN: 64500, Holder: "ACME-NET", Known: true},
			netip.MustParseAddr("104.16.0.1"):  {ASN: 13335, Holder: "CLOUDFLARENET", Known: true},
		},
	}
	inv := inventory.New(d, provider.Default())
	mk := func(excl ...string) *scope.Scope {
		var xs []input.Exclusion
		for _, e := range excl {
			x, err := input.ParseExclusion(e)
			if err != nil {
				t.Fatal(err)
			}
			xs = append(xs, x)
		}
		return scope.New(scope.Config{Roots: []string{"example.com"}, Netblocks: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
			Exclusions: xs, Resolutions: inv.Addrs(), WildcardOnly: inv.WildcardOnly()})
	}
	rec := func(key string) store.Record { return store.Record{Key: key, Current: true} }
	for _, c := range []struct {
		name, key string
		excl      []string
		want      bool
	}{
		{"hostname-resolved address", "203.0.113.5:8080", nil, true},
		{"address in an in-scope netblock", "198.51.100.7:22", nil, true},
		{"IPv4-mapped IPv6 key", "[::ffff:203.0.113.5]:8080", nil, true},
		{"shared provider address", "104.16.0.1:443", nil, false},
		{"address nothing is known about", "192.0.2.9:80", nil, false},
		{"address excluded later", "203.0.113.5:8080", []string{"203.0.113.5/32"}, false},
		{"netblock address excluded later", "198.51.100.7:22", []string{"198.51.100.0/28"}, false},
		{"key that is not an address and port", "203.0.113.5", nil, false},
	} {
		if got := output.PortVisible(mk(c.excl...), inv, rec(c.key)); got != c.want {
			t.Errorf("%s: PortVisible(%s) = %v, want %v", c.name, c.key, got, c.want)
		}
	}
}
