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
	"strconv"
	"strings"
	"unicode"

	"github.com/rafaelh/recon/internal/fault"
	"github.com/rafaelh/recon/internal/findings"
	"github.com/rafaelh/recon/internal/inventory"
	"github.com/rafaelh/recon/internal/kinds"
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
	// Vis decides which records are shown, for Scope and Inv; Render makes one
	// if it is nil. A caller that counts the same records passes its own, so
	// the files and the totals agree and each host is decided once.
	Vis *kinds.Visibility
	// Storage is the storage Attribution derived with the findings, which the
	// findings files are written from.
	Storage map[string]findings.StorageAttr
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
	if snap.Vis == nil {
		snap.Vis = kinds.NewVisibility(snap.Scope, snap.Inv)
	}
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

// renderFile writes f, or removes it when it would have no rows (a TXT file
// lists only current rows), so an empty file is never left in the engagement.
func renderFile(dir, tmp string, f File, snap Snapshot) error {
	rows := f.Rows(snap)
	if f.Format == TXT {
		var listed []Row
		for _, r := range rows {
			if r.Current && len(r.Cells) > 0 {
				listed = append(listed, r)
			}
		}
		rows = listed
	}
	if len(rows) == 0 {
		if err := os.Remove(filepath.Join(dir, f.Name)); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	slices.SortStableFunc(rows, func(a, b Row) int { return slices.Compare(a.Cells, b.Cells) })
	var buf bytes.Buffer
	switch f.Format {
	case TXT:
		for _, r := range rows {
			buf.WriteString(stripControl(r.Cells[0]))
			buf.WriteByte('\n')
		}
	case CSV:
		w := csv.NewWriter(&buf)
		if err := w.Write(append(append([]string(nil), f.Columns...), "current", "first_seen", "last_seen")); err != nil {
			return err
		}
		for _, r := range rows {
			rec := make([]string, 0, len(r.Cells)+3)
			for _, c := range r.Cells {
				rec = append(rec, csvSafe(c))
			}
			rec = append(rec, fmt.Sprint(r.Current), r.FirstSeen, r.LastSeen)
			if err := w.Write(rec); err != nil {
				return err
			}
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
// then Spec 2's DNS files (D27), Spec 3's web files, Spec 4's open-ports.csv,
// Spec 5's email-posture.csv and the findings files.
func Default() []File {
	files := []File{
		{Name: "scope.csv", Format: CSV, Columns: []string{"type", "value", "source"}, Rows: scopeRows},
		{Name: "candidates.csv", Format: CSV, Columns: []string{"type", "value", "found_by"}, Rows: candidateRows},
		{Name: "excluded.csv", Format: CSV, Columns: []string{"value", "reason"}, Rows: excludedRows},
		{Name: "subdomains.txt", Format: TXT, Rows: inScopeHostRows(false)},
		{Name: "resolutions.csv", Format: CSV, Columns: []string{"name", "type", "value"}, Rows: resolutionRows},
		{Name: "unresolved.txt", Format: TXT, Rows: unresolvedRows},
		{Name: "wildcard-excluded.txt", Format: TXT, Rows: inScopeHostRows(true)},
		{Name: "ips.csv", Format: CSV, Columns: []string{"ip", "asn", "owner", "provider", "service", "in_scope", "port_eligible", "hostnames"}, Rows: ipRows},
		{Name: "provider-hosts.csv", Format: CSV, Columns: []string{"hostname", "provider", "service", "evidence", "cname", "resolves"}, Rows: providerHostRows},
		{Name: "web-services.csv", Format: CSV, Columns: webServiceColumns, Rows: webServiceRows},
		{Name: "urls.csv", Format: CSV, Columns: []string{"url", "host", "status", "found_by"}, Rows: urlRows},
		{Name: "open-ports.csv", Format: CSV, Columns: []string{"ip", "port", "banner", "hostnames"}, Rows: openPortRows},
		{Name: "email-posture.csv", Format: CSV, Columns: emailPostureColumns, Rows: emailPostureRows},
	}
	for _, f := range findings.Files() {
		files = append(files, findingsFile(f))
	}
	return files
}

var webServiceColumns = []string{"url", "host", "port", "scheme", "status", "title", "server", "technologies", "redirect",
	"final_url", "tls_subject", "tls_sans", "tls_issuer", "tls_expiry", "tls_error", "tls_self_signed"}

// vis is the snapshot's Visibility. Render always sets one; a file's Rows
// called on its own (in a test) gets a new one.
func (s Snapshot) vis() *kinds.Visibility {
	if s.Vis != nil {
		return s.Vis
	}
	return kinds.NewVisibility(s.Scope, s.Inv)
}

// attrCell renders an attribute for a CSV cell. Numbers come back from the
// store as float64.
func attrCell(r store.Record, k string) string {
	switch v := r.Attrs[k].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	}
	return ""
}

func webServiceRows(s Snapshot) []Row {
	var rows []Row
	vis := s.vis()
	for _, r := range s.of(kinds.WebService) {
		if !vis.Shown("web_service", r) {
			continue
		}
		cells := []string{r.Key}
		for _, col := range webServiceColumns[1:] {
			cells = append(cells, attrCell(r, col))
		}
		rows = append(rows, recordRow(r, cells...))
	}
	return rows
}

func urlRows(s Snapshot) []Row {
	var rows []Row
	vis := s.vis()
	for _, r := range s.of(kinds.URL) {
		if vis.Shown("url", r) {
			rows = append(rows, recordRow(r, r.Key, attrCell(r, "host"), attrCell(r, "status"), strings.Join(r.Stages, ",")))
		}
	}
	return rows
}

// openPortRows lists the shown open ports. The record's key is authoritative
// for the address and port.
func openPortRows(s Snapshot) []Row {
	recs := s.of(kinds.OpenPort)
	if len(recs) == 0 {
		return nil
	}
	hostnames := s.Inv.HostnamesByIP(s.Scope)
	vis := s.vis()
	var rows []Row
	for _, r := range recs {
		if !vis.Shown("open_port", r) {
			continue
		}
		ap := netip.MustParseAddrPort(r.Key) // shown, so it parsed
		addr := ap.Addr().Unmap()
		rows = append(rows, recordRow(r, addr.String(), strconv.Itoa(int(ap.Port())), r.Str("banner"), strings.Join(hostnames[addr], ";")))
	}
	return rows
}

func scopeRows(s Snapshot) []Row {
	var rows []Row
	for _, in := range s.Inputs {
		if in.Kind == "exclude" {
			continue
		}
		rows = append(rows, Row{Cells: []string{in.Kind, in.Value, "input"}, Current: true, FirstSeen: in.AddedAt, LastSeen: s.Today})
	}
	for _, r := range s.of(kinds.Netblock) {
		if src, ok := s.ASNNetblocks[r.Key]; ok {
			rows = append(rows, recordRow(r, "netblock", r.Key, src))
		}
	}
	return rows
}

// of is the records of a kind, current or not.
func (s Snapshot) of(k kinds.Named) []store.Record { return s.Records[k.Name()] }

func recordRow(r store.Record, cells ...string) Row {
	return Row{Cells: cells, Current: r.Current, FirstSeen: r.FirstSeen, LastSeen: r.LastSeen}
}

func candidateRows(s Snapshot) []Row {
	var rows []Row
	for _, kind := range []kinds.Named{kinds.Root, kinds.Hostname} {
		for _, r := range s.of(kind) {
			if s.Scope.ClassifyHost(r.Key).Class == scope.Candidate {
				rows = append(rows, recordRow(r, kind.Name(), r.Key, strings.Join(r.Stages, ",")))
			}
		}
	}
	for _, r := range s.of(kinds.Netblock) {
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
	for _, kind := range []kinds.Named{kinds.Root, kinds.Hostname} {
		for _, r := range s.of(kind) {
			if c := s.Scope.ClassifyHost(r.Key); c.Class == scope.Excluded && !seen[r.Key] {
				seen[r.Key] = true
				rows = append(rows, recordRow(r, r.Key, c.Reason))
			}
		}
	}
	for _, r := range s.of(kinds.ExcludedKind) {
		if seen[r.Key] {
			continue
		}
		rows = append(rows, recordRow(r, r.Key, kinds.ExcludedKind.Attrs(r).Reason))
	}
	return rows
}

// inScopeHostRows lists the in-scope hostnames that exist only because of a
// wildcard (wildcard-excluded.txt), or all the others (subdomains.txt).
func inScopeHostRows(wildcardOnly bool) func(Snapshot) []Row {
	return func(s Snapshot) []Row {
		var rows []Row
		wo := s.Inv.WildcardOnly()
		for _, r := range s.of(kinds.Hostname) {
			if wo[r.Key] == wildcardOnly && s.Scope.ClassifyHost(r.Key).Class == scope.InScope {
				rows = append(rows, recordRow(r, r.Key))
			}
		}
		return rows
	}
}

func unresolvedRows(s Snapshot) []Row {
	var rows []Row
	for _, r := range s.of(kinds.Unresolved) {
		rows = append(rows, recordRow(r, r.Key))
	}
	return rows
}

func resolutionRows(s Snapshot) []Row {
	var rows []Row
	for _, r := range s.of(kinds.Resolution) {
		a := kinds.Resolution.Attrs(r)
		rows = append(rows, recordRow(r, a.Name, a.Type, a.Value))
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
