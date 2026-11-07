package output

import (
	"strconv"

	"github.com/rafaelh/recon/internal/findings"
	"github.com/rafaelh/recon/internal/kinds"
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

var emailPostureColumns = []string{"root", "mx", "spf", "spf_lookups", "dmarc", "dmarc_policy", "dkim_selectors"}

// emailPostureRows lists the email posture evidence of each in-scope root.
func emailPostureRows(s Snapshot) []Row {
	var rows []Row
	vis := s.vis()
	for _, r := range s.of(kinds.EmailPosture) {
		if !vis.Shown(kinds.EmailPosture, r) {
			continue
		}
		a := kinds.EmailPosture.Attrs(r)
		rows = append(rows, recordRow(r, r.Key, a.MX, a.SPF, strconv.Itoa(a.SPFLookups), a.DMARC, a.DMARCPolicy, a.DKIMSelectors))
	}
	return rows
}
