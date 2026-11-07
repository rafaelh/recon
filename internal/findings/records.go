package findings

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/rafaelh/recon/internal/cloudstorage"
	"github.com/rafaelh/recon/internal/store"
)

// This file is everything outside the package needs to know about a stored
// finding record: its key, how to read one back, which ones the summary lists,
// and the files that list them. Adding a category changes only this package.

// Key is the finding's record key: one per hostname for takeovers, otherwise
// category, type and target. ParseKey reverses it.
func (f Finding) Key() string {
	if f.Category == Takeover {
		return f.Category + "|" + f.Target
	}
	return f.Category + "|" + f.Type + "|" + f.Target
}

// ParseKey reads the category, type and target from a finding's record key. A
// takeover key carries no type.
func ParseKey(key string) (category, typ, target string) {
	category, rest, _ := strings.Cut(key, "|")
	if category == Takeover {
		return category, "", rest
	}
	typ, target, _ = strings.Cut(rest, "|")
	return category, typ, target
}

// FromRecord reads a stored finding record back. A record no longer derived
// keeps no attributes (the store drops them with its last observation), so the
// category, type and target then come from its key.
func FromRecord(r store.Record) Finding {
	category, typ, target := ParseKey(r.Key)
	f := Finding{Category: category, Type: typ, Target: target, Attrs: r.Attrs}
	if v := r.Str("category"); v != "" {
		f.Category = v
	}
	if v := r.Str("type"); v != "" {
		f.Type = v
	}
	if v := r.Str("target"); v != "" {
		f.Target = v
	}
	f.Severity, f.Detail = r.Str("severity"), r.Str("detail")
	return f
}

// Headline lists the current high and medium findings among recs, high first,
// then by target: the findings the run summary shows.
func Headline(recs []store.Record) []Finding {
	var out []Finding
	for _, r := range recs {
		if f := FromRecord(r); r.Current && (f.Severity == High || f.Severity == Medium) {
			out = append(out, f)
		}
	}
	slices.SortStableFunc(out, func(a, b Finding) int {
		if a.Severity != b.Severity {
			return rank[b.Severity] - rank[a.Severity]
		}
		return strings.Compare(a.Target, b.Target)
	})
	return out
}

// Listing is what the findings files are written from: the records of every
// kind, current or not, and the storage Attribution derived with the findings.
type Listing struct {
	Records map[string][]store.Record
	Storage map[string]StorageAttr
}

// File is a CSV file of findings. The output package writes it like its own
// files, adding the current, first_seen and last_seen columns.
type File struct {
	Name    string
	Columns []string
	Rows    func(Listing) []FileRow
}

// FileRow is one row of a File: its cells, one per column, and the record it lists,
// which dates it.
type FileRow struct {
	Record store.Record
	Cells  []string
}

// riskFiles are the categories with a risk-<category>.csv file, its columns, and
// for a finding no longer derived, the columns its key identifies.
var riskFiles = []struct {
	category string
	columns  []string
	fromKey  func(typ, target string) map[string]string
}{
	{Takeover, []string{"severity", "target", "type", "service", "cname", "detail"}, nil},
	{Storage, []string{"severity", "provider", "name", "url", "exists", "public", "listable", "object_count", "first_keys", "referenced_by"},
		func(_, target string) map[string]string { return map[string]string{"url": target} }},
	{SensitivePaths, []string{"severity", "url", "path", "status", "size", "signature"},
		func(typ, target string) map[string]string { return map[string]string{"path": typ, "url": target} }},
	{Email, []string{"severity", "root", "type", "detail"},
		func(_, target string) map[string]string { return map[string]string{"root": target} }},
	{Ports, []string{"severity", "ip", "port", "banner", "hostnames"},
		func(_, target string) map[string]string {
			ap, err := netip.ParseAddrPort(target)
			if err != nil {
				return nil
			}
			return map[string]string{"ip": ap.Addr().String(), "port": strconv.Itoa(int(ap.Port()))}
		}},
	{Certificates, []string{"severity", "url", "type", "tls_subject", "tls_issuer", "tls_expiry"},
		func(_, target string) map[string]string { return map[string]string{"url": target} }},
}

// Files are the findings files: storage-unattributed.csv, then one
// risk-<category>.csv per category.
func Files() []File {
	files := []File{{Name: "storage-unattributed.csv", Columns: storageUnattributedColumns, Rows: storageUnattributedRows}}
	for _, rf := range riskFiles {
		files = append(files, riskFile(rf.category, rf.columns, rf.fromKey))
	}
	return files
}

// riskFile lists every finding record of a category: current ones and those no
// longer derived, which stay on record (Spec 5 D13). The findings are derived
// with scope and visibility already applied, so the file does not filter again.
func riskFile(category string, columns []string, fromKey func(typ, target string) map[string]string) File {
	return File{Name: "risk-" + category + ".csv", Columns: columns, Rows: func(l Listing) []FileRow {
		var rows []FileRow
		for _, r := range l.Records["finding"] {
			cat, typ, target := ParseKey(r.Key)
			if cat != category {
				continue
			}
			fallback := map[string]string{"type": typ, "target": target}
			if !r.Current && fromKey != nil {
				for k, v := range fromKey(typ, target) {
					fallback[k] = v
				}
			}
			cells := make([]string, len(columns))
			for i, c := range columns {
				if cells[i] = cell(r, c); cells[i] == "" && !r.Current {
					cells[i] = fallback[c]
				}
			}
			rows = append(rows, FileRow{Record: r, Cells: cells})
		}
		return rows
	}}
}

var storageUnattributedColumns = []string{"provider", "name", "url", "exists", "public", "listable", "object_count", "first_keys", "generated_from", "severity"}

// storageUnattributedRows lists every existing bucket or container nothing in
// scope references and that a root or organisation input would have guessed.
// A public or listable one is a low finding; a private one is listed, not reported.
func storageUnattributedRows(l Listing) []FileRow {
	var rows []FileRow
	for _, r := range l.Records["storage"] {
		attr, known := l.Storage[r.Key]
		if !flag(r, "exists") || !known || attr.Attributed || len(attr.GeneratedFrom) == 0 {
			continue
		}
		provider, name, container := r.Str("provider"), r.Str("name"), r.Str("container")
		rows = append(rows, FileRow{Record: r, Cells: []string{provider, name, cloudstorage.URL(provider, name, container), "true", attr.Public,
			cell(r, "listable"), r.Str("object_count"), cell(r, "first_keys"), strings.Join(attr.GeneratedFrom, ";"), attr.Severity}})
	}
	return rows
}

// cell renders an attribute for a CSV cell. Numbers come back from the store
// as float64; a list is joined with ";".
func cell(r store.Record, k string) string {
	switch v := r.Attrs[k].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	case []any:
		var parts []string
		for _, x := range v {
			if s, ok := x.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ";")
	}
	return ""
}
