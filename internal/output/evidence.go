package output

import (
	"strings"

	"github.com/rafaelh/recon/internal/findings"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/scope"
	"github.com/rafaelh/recon/internal/store"
)

// findingsFile writes a findings file like the other CSV files. The findings
// package decides its columns and rows; output only writes them.
func findingsFile(f findings.File) File {
	return File{Name: f.Name, Format: CSV, Columns: f.Columns, Rows: func(s Snapshot) []Row {
		var rows []Row
		for _, r := range f.Rows(findings.Listing{Records: s.Records, Storage: s.Storage}) {
			rows = append(rows, recordRow(r.Record, r.Cells...))
		}
		return rows
	}}
}

// listCell is an attribute as a cell: a list is joined with ";".
func listCell(r store.Record, k string) string {
	if v, ok := r.Attrs[k].([]any); ok {
		var parts []string
		for _, x := range v {
			if s, ok := x.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ";")
	}
	return attrCell(r, k)
}

var emailPostureColumns = []string{"root", "mx", "spf", "spf_lookups", "dmarc", "dmarc_policy", "dkim_selectors"}

// emailPostureRows lists the email posture evidence of each in-scope root.
func emailPostureRows(s Snapshot) []Row {
	var rows []Row
	for _, r := range s.of(kinds.EmailPosture) {
		if s.Scope.ClassifyHost(r.Key).Class != scope.InScope {
			continue
		}
		cells := []string{r.Key}
		for _, c := range emailPostureColumns[1:] {
			cells = append(cells, listCell(r, c))
		}
		rows = append(rows, recordRow(r, cells...))
	}
	return rows
}
