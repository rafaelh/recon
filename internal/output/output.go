// Package output renders the engagement's TXT and CSV files from the store.
// Files are written to .recon/tmp and renamed into place, so a reader never
// sees a truncated file.
package output

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"github.com/rafaelh/recon/internal/fault"
	"github.com/rafaelh/recon/internal/inventory"
	"github.com/rafaelh/recon/internal/scope"
	"github.com/rafaelh/recon/internal/store"
)

// Format is TXT (plain list, current records only) or CSV (all records).
type Format int

const (
	TXT Format = iota
	CSV
)

// Row is one output row. Cells are the key and attribute columns.
type Row struct {
	Cells               []string
	Current             bool
	FirstSeen, LastSeen string
}

// Snapshot is the store contents a render works from.
type Snapshot struct {
	Today   string
	Inputs  []store.Input
	Records map[string][]store.Record // by kind, including not-current records
	Scope   *scope.Scope
	Inv     *inventory.Inventory
	// ASNNetblocks maps an in-scope netblock to the "AS<n>" input it came from.
	ASNNetblocks map[string]string
}

// File is a registry entry. CSV files get the columns Columns followed by
// current, first_seen and last_seen.
type File struct {
	Name    string
	Format  Format
	Columns []string
	Rows    func(Snapshot) []Row
}

// Render writes every file via .recon/tmp and renames it into dir.
func Render(dir string, files []File, snap Snapshot) error {
	tmp := filepath.Join(dir, ".recon", "tmp")
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return err
	}
	for _, f := range files {
		if err := renderFile(dir, tmp, f, snap); err != nil {
			return fmt.Errorf("render %s: %w", f.Name, err)
		}
	}
	return nil
}

// Sweep removes stale temporary files left by an interrupted render.
func Sweep(dir string) error {
	tmp := filepath.Join(dir, ".recon", "tmp")
	entries, err := os.ReadDir(tmp)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(tmp, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func renderFile(dir, tmp string, f File, snap Snapshot) error {
	rows := f.Rows(snap)
	slices.SortStableFunc(rows, func(a, b Row) int { return slices.Compare(a.Cells, b.Cells) })
	var buf bytes.Buffer
	switch f.Format {
	case TXT:
		for _, r := range rows {
			if r.Current && len(r.Cells) > 0 {
				buf.WriteString(stripControl(r.Cells[0]))
				buf.WriteByte('\n')
			}
		}
	case CSV:
		w := csv.NewWriter(&buf)
		w.Write(append(append([]string(nil), f.Columns...), "current", "first_seen", "last_seen"))
		for _, r := range rows {
			rec := make([]string, 0, len(r.Cells)+3)
			for _, c := range r.Cells {
				rec = append(rec, csvSafe(c))
			}
			rec = append(rec, fmt.Sprint(r.Current), r.FirstSeen, r.LastSeen)
			w.Write(rec)
		}
		w.Flush()
		if err := w.Error(); err != nil {
			return err
		}
	}
	tmpPath := filepath.Join(tmp, f.Name)
	out, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	data := buf.Bytes()
	half := len(data) / 2
	if _, err := out.Write(data[:half]); err != nil {
		out.Close()
		return err
	}
	fault.Point("render-mid-file")
	if _, err := out.Write(data[half:]); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, filepath.Join(dir, f.Name))
}

func stripControl(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// csvSafe neutralises spreadsheet formulas, then removes control characters.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		s = "'" + s
	}
	return stripControl(s)
}

// Default returns the registered files: Spec 1's scope, candidates and excluded,
// then Spec 2's DNS files (D27).
func Default() []File {
	return []File{
		{Name: "scope.csv", Format: CSV, Columns: []string{"type", "value", "source"}, Rows: scopeRows},
		{Name: "candidates.csv", Format: CSV, Columns: []string{"type", "value", "found_by"}, Rows: candidateRows},
		{Name: "excluded.csv", Format: CSV, Columns: []string{"value", "reason"}, Rows: excludedRows},
		{Name: "subdomains.txt", Format: TXT, Rows: inScopeHostRows(false)},
		{Name: "resolutions.csv", Format: CSV, Columns: []string{"name", "type", "value"}, Rows: resolutionRows},
		{Name: "unresolved.txt", Format: TXT, Rows: unresolvedRows},
		{Name: "wildcard-excluded.txt", Format: TXT, Rows: inScopeHostRows(true)},
		{Name: "ips.csv", Format: CSV, Columns: []string{"ip", "asn", "owner", "provider", "service", "in_scope", "port_eligible", "hostnames"}, Rows: ipRows},
		{Name: "provider-hosts.csv", Format: CSV, Columns: []string{"hostname", "provider", "service", "evidence", "cname", "resolves"}, Rows: providerHostRows},
	}
}

func scopeRows(s Snapshot) []Row {
	var rows []Row
	for _, in := range s.Inputs {
		if in.Kind == "exclude" {
			continue
		}
		rows = append(rows, Row{Cells: []string{in.Kind, in.Value, "input"}, Current: true, FirstSeen: in.AddedAt, LastSeen: s.Today})
	}
	for _, r := range s.Records["netblock"] {
		if src, ok := s.ASNNetblocks[r.Key]; ok {
			rows = append(rows, recordRow(r, "netblock", r.Key, src))
		}
	}
	return rows
}

func recordRow(r store.Record, cells ...string) Row {
	return Row{Cells: cells, Current: r.Current, FirstSeen: r.FirstSeen, LastSeen: r.LastSeen}
}

func candidateRows(s Snapshot) []Row {
	var rows []Row
	for _, kind := range []string{"root", "hostname"} {
		for _, r := range s.Records[kind] {
			if s.Scope.ClassifyHost(r.Key).Class == scope.Candidate {
				rows = append(rows, recordRow(r, kind, r.Key, strings.Join(r.Stages, ",")))
			}
		}
	}
	for _, r := range s.Records["netblock"] {
		if _, err := netip.ParsePrefix(r.Key); err != nil || s.Scope.HasNetblock(r.Key) {
			continue
		}
		rows = append(rows, recordRow(r, "netblock", r.Key, strings.Join(r.Stages, ",")))
	}
	return rows
}

func excludedRows(s Snapshot) []Row {
	var rows []Row
	seen := map[string]bool{}
	for _, kind := range []string{"root", "hostname"} {
		for _, r := range s.Records[kind] {
			if c := s.Scope.ClassifyHost(r.Key); c.Class == scope.Excluded && !seen[r.Key] {
				seen[r.Key] = true
				rows = append(rows, recordRow(r, r.Key, c.Reason))
			}
		}
	}
	for _, r := range s.Records["excluded"] {
		if seen[r.Key] {
			continue
		}
		rows = append(rows, recordRow(r, r.Key, r.Str("reason")))
	}
	return rows
}

// inScopeHostRows lists the in-scope hostnames that exist only because of a
// wildcard (wildcard-excluded.txt), or all the others (subdomains.txt).
func inScopeHostRows(wildcardOnly bool) func(Snapshot) []Row {
	return func(s Snapshot) []Row {
		var rows []Row
		wo := s.Inv.WildcardOnly()
		for _, r := range s.Records["hostname"] {
			if wo[r.Key] == wildcardOnly && s.Scope.ClassifyHost(r.Key).Class == scope.InScope {
				rows = append(rows, recordRow(r, r.Key))
			}
		}
		return rows
	}
}

func unresolvedRows(s Snapshot) []Row {
	var rows []Row
	for _, r := range s.Records["unresolved"] {
		rows = append(rows, recordRow(r, r.Key))
	}
	return rows
}

func resolutionRows(s Snapshot) []Row {
	var rows []Row
	for _, r := range s.Records["resolution"] {
		rows = append(rows, recordRow(r, r.Str("name"), r.Str("type"), r.Str("value")))
	}
	return rows
}

// derivedRows builds rows computed from the inventory. Each is dated by the
// record of kind whose key is the row's first cell, or today if there is none.
func derivedRows(s Snapshot, kind string, cells [][]string) []Row {
	seen := map[string]store.Record{}
	for _, r := range s.Records[kind] {
		seen[r.Key] = r
	}
	rows := make([]Row, 0, len(cells))
	for _, c := range cells {
		row := Row{Cells: c, Current: true, FirstSeen: s.Today, LastSeen: s.Today}
		if rec, ok := seen[c[0]]; ok {
			row.FirstSeen, row.LastSeen = rec.FirstSeen, rec.LastSeen
		}
		rows = append(rows, row)
	}
	return rows
}

func ipRows(s Snapshot) []Row {
	var cells [][]string
	for _, ir := range s.Inv.IPRows(s.Scope) {
		asn := ""
		if ir.ASN != 0 {
			asn = fmt.Sprintf("AS%d", ir.ASN)
		}
		cells = append(cells, []string{ir.IP.String(), asn, ir.Owner, ir.Provider, ir.Service,
			fmt.Sprint(ir.InScope), fmt.Sprint(ir.PortEligible), strings.Join(ir.Hostnames, ";")})
	}
	return derivedRows(s, "ip", cells)
}

func providerHostRows(s Snapshot) []Row {
	var cells [][]string
	for _, ph := range s.Inv.ProviderHosts(s.Scope) {
		cells = append(cells, []string{ph.Hostname, ph.Provider, ph.Service, ph.Evidence, ph.CNAME, fmt.Sprint(ph.Resolves)})
	}
	return derivedRows(s, "hostname", cells)
}
