package output

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/rafaelh/recon/internal/cloudstorage"
	"github.com/rafaelh/recon/internal/scope"
	"github.com/rafaelh/recon/internal/store"
)

// riskFile lists every finding record of a category: current ones and those no
// longer derived, which stay on record (Spec 5 D13). The findings are derived
// with scope and visibility already applied, so the file does not filter again.
func riskFile(name, category string, columns []string) File {
	return File{Name: name, Format: CSV, Columns: columns, Rows: func(s Snapshot) []Row {
		var rows []Row
		for _, r := range s.Records["finding"] {
			if cat, _, _ := strings.Cut(r.Key, "|"); cat != category {
				continue
			}
			var fallback map[string]string
			if !r.Current {
				_, fallback = fromKey(r.Key) // a record no longer derived keeps no attributes, only its key
			}
			cells := make([]string, len(columns))
			for i, c := range columns {
				if cells[i] = findingCell(r, c); cells[i] == "" {
					cells[i] = fallback[c]
				}
			}
			rows = append(rows, recordRow(r, cells...))
		}
		return rows
	}}
}

// fromKey reads what a finding's key says: its category and, for a finding that
// is no longer current (the store keeps no attributes for it), the columns the
// key identifies. Keys are "takeover|<target>" and "<category>|<type>|<target>".
func fromKey(key string) (category string, cols map[string]string) {
	category, rest, _ := strings.Cut(key, "|")
	cols = map[string]string{}
	typ, target := "", rest
	if category != "takeover" {
		typ, target, _ = strings.Cut(rest, "|")
	}
	cols["type"], cols["target"] = typ, target
	switch category {
	case "storage", "certificates":
		cols["url"] = target
	case "sensitive-paths":
		cols["path"], cols["url"] = typ, target
	case "email":
		cols["root"] = target
	case "ports":
		if ap, err := netip.ParseAddrPort(target); err == nil {
			cols["ip"], cols["port"] = ap.Addr().String(), strconv.Itoa(int(ap.Port()))
		}
	}
	return category, cols
}

// findingCell is a finding attribute as a cell: a list is joined with ";".
func findingCell(r store.Record, k string) string {
	switch v := r.Attrs[k].(type) {
	case []any:
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

func emailPostureRows(s Snapshot) []Row {
	var rows []Row
	for _, r := range s.Records["email_posture"] {
		if s.Scope.ClassifyHost(r.Key).Class != scope.InScope {
			continue
		}
		cells := []string{r.Key}
		for _, c := range emailPostureColumns[1:] {
			cells = append(cells, findingCell(r, c))
		}
		rows = append(rows, recordRow(r, cells...))
	}
	return rows
}

var storageUnattributedColumns = []string{"provider", "name", "url", "exists", "public", "listable", "object_count", "first_keys", "generated_from", "severity"}

// storageUnattributedRows lists every existing bucket or container nothing in
// scope references and that a root or organisation input would have guessed.
// A public or listable one is a low finding; a private one is listed, not reported.
func storageUnattributedRows(s Snapshot) []Row {
	var rows []Row
	for _, r := range s.Records["storage"] {
		attr, known := s.Storage[r.Key]
		if exists, _ := r.Attrs["exists"].(bool); !exists || !known || attr.Attributed || len(attr.GeneratedFrom) == 0 {
			continue
		}
		provider, name, container := r.Str("provider"), r.Str("name"), r.Str("container")
		rows = append(rows, recordRow(r, provider, name, cloudstorage.URL(provider, name, container), "true", attr.Public,
			attrCell(r, "listable"), r.Str("object_count"), findingCell(r, "first_keys"), strings.Join(attr.GeneratedFrom, ";"), attr.Severity))
	}
	return rows
}
