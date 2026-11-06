package output_test

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/inventory"
	"github.com/rafaelh/recon/internal/output"
	"github.com/rafaelh/recon/internal/provider"
	"github.com/rafaelh/recon/internal/scope"
	"github.com/rafaelh/recon/internal/store"
)

func snapshot(recs map[string][]store.Record) output.Snapshot {
	inv := inventory.New(inventory.Data{}, provider.Default())
	sc := scope.New(scope.Config{Roots: []string{"example.com"}, Netblocks: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}})
	return output.Snapshot{Today: "2026-11-01", Records: recs, Scope: sc, Inv: inv, Storage: map[string]output.StorageAttr{}}
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

// D13: the risk files list every finding of their category, current or not, with their columns.
func TestRiskFiles(t *testing.T) {
	fnd := func(category, typ, target string, current bool, kv ...any) store.Record {
		attrs := append([]any{"category", category, "type", typ, "severity", "medium", "target", target, "detail", "d"}, kv...)
		return srec("finding", category+"|"+typ+"|"+target, current, attrs...)
	}
	snap := snapshot(map[string][]store.Record{"finding": {
		fnd("takeover", "dns-nxdomain", "shop.example.com", true, "service", "Cloud Services", "cname", "x.cloudapp.net"),
		fnd("storage", "listable", "https://s3.amazonaws.com/b", false, "provider", "s3", "name", "b", "url", "https://s3.amazonaws.com/b",
			"exists", "true", "public", "unknown", "listable", "true", "object_count", "3", "first_keys", "a;b", "referenced_by", "static.example.com"),
		fnd("sensitive-paths", "/.env", "https://www.example.com/.env", true, "url", "https://www.example.com/.env", "path", "/.env",
			"status", 200.0, "size", 42.0, "signature", "X"),
		fnd("email", "spf-missing", "example.com", true, "root", "example.com"),
		fnd("ports", "risky-port", "198.51.100.5:3389", true, "ip", "198.51.100.5", "port", 3389.0, "banner", "", "hostnames", "a.example.com"),
		fnd("certificates", "expired", "https://www.example.com", true, "url", "https://www.example.com", "tls_subject", "CN=www", "tls_issuer", "CN=CA", "tls_expiry", "2026-10-01"),
		fnd("storage-unattributed", "listable", "s3|guess", true, "provider", "s3"),
	}})
	cases := []struct {
		name    string
		columns []string
		count   int
		row     map[string]string
	}{
		{"risk-takeover.csv", []string{"severity", "target", "type", "service", "cname", "detail"}, 1,
			map[string]string{"severity": "medium", "target": "shop.example.com", "type": "dns-nxdomain", "service": "Cloud Services", "cname": "x.cloudapp.net"}},
		{"risk-storage.csv", []string{"severity", "provider", "name", "url", "exists", "public", "listable", "object_count", "first_keys", "referenced_by"}, 1,
			map[string]string{"provider": "s3", "name": "b", "listable": "true", "object_count": "3", "first_keys": "a;b", "referenced_by": "static.example.com"}},
		{"risk-sensitive-paths.csv", []string{"severity", "url", "path", "status", "size", "signature"}, 1,
			map[string]string{"url": "https://www.example.com/.env", "path": "/.env", "status": "200", "size": "42", "signature": "X"}},
		{"risk-email.csv", []string{"severity", "root", "type", "detail"}, 1, map[string]string{"root": "example.com", "type": "spf-missing"}},
		{"risk-ports.csv", []string{"severity", "ip", "port", "banner", "hostnames"}, 1,
			map[string]string{"ip": "198.51.100.5", "port": "3389", "hostnames": "a.example.com"}},
		{"risk-certificates.csv", []string{"severity", "url", "type", "tls_subject", "tls_issuer", "tls_expiry"}, 1,
			map[string]string{"url": "https://www.example.com", "type": "expired", "tls_expiry": "2026-10-01"}},
	}
	for _, c := range cases {
		f := file(t, c.name)
		if !slices.Equal(f.Columns, c.columns) {
			t.Errorf("%s columns = %v", c.name, f.Columns)
		}
		rows := f.Rows(snap)
		if len(rows) != c.count {
			t.Errorf("%s has %d rows, want %d", c.name, len(rows), c.count)
			continue
		}
		got := cellMap(f, rows[0])
		for k, v := range c.row {
			if got[k] != v {
				t.Errorf("%s %s = %q, want %q", c.name, k, got[k], v)
			}
		}
	}
	// risk-storage.csv is attributed only: the fixed storage finding is listed, not current.
	if rows := file(t, "risk-storage.csv").Rows(snap); rows[0].Current || rows[0].FirstSeen != "2026-10-01" {
		t.Errorf("fixed finding stays on record as not current: %+v", rows[0])
	}
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

// D9/D13: storage-unattributed.csv lists existing names that no current reference attributes.
func TestStorageUnattributedFile(t *testing.T) {
	st := func(key string, kv ...any) store.Record { return srec("storage", key, true, kv...) }
	snap := snapshot(map[string][]store.Record{
		"storage": {
			st("s3|example-backup", "provider", "s3", "name", "example-backup", "container", "", "exists", true, "listable", true, "object_count", "1000+", "first_keys", []any{"a", "b"}),
			st("gcs|example-dev", "provider", "gcs", "name", "example-dev", "container", "", "exists", true, "listable", false),
			st("s3|acme-assets", "provider", "s3", "name", "acme-assets", "container", "", "exists", true, "listable", true),
			st("s3|example-gone", "provider", "s3", "name", "example-gone", "container", "", "exists", false),
			st("azure|exampleacct/media", "provider", "azure", "name", "exampleacct", "container", "media", "exists", true, "listable", false),
		},
	})
	// The findings package derives the attribution, public state and severity; output lists them.
	snap.Storage = map[string]output.StorageAttr{
		"s3|example-backup":       {GeneratedFrom: []string{"example.com"}, Public: "unknown", Severity: "low"},
		"gcs|example-dev":         {GeneratedFrom: []string{"example.com", "Acme"}, Public: "yes", Severity: "low"},
		"s3|acme-assets":          {Attributed: true, Public: "unknown"},
		"s3|example-gone":         {GeneratedFrom: []string{"example.com"}, Public: "unknown"},
		"azure|exampleacct/media": {GeneratedFrom: []string{"example.com"}, Public: "unknown"},
	}
	f := file(t, "storage-unattributed.csv")
	if !slices.Equal(f.Columns, []string{"provider", "name", "url", "exists", "public", "listable", "object_count", "first_keys", "generated_from", "severity"}) {
		t.Errorf("columns = %v", f.Columns)
	}
	byName := map[string]map[string]string{}
	for _, r := range f.Rows(snap) {
		m := cellMap(f, r)
		byName[m["name"]] = m
	}
	if len(byName) != 3 || byName["acme-assets"] != nil || byName["example-gone"] != nil {
		t.Fatalf("rows = %v", byName)
	}
	b := byName["example-backup"]
	if b["url"] != "https://s3.amazonaws.com/example-backup" || b["listable"] != "true" || b["object_count"] != "1000+" || b["first_keys"] != "a;b" ||
		b["generated_from"] != "example.com" || b["severity"] != "low" || b["public"] != "unknown" || b["exists"] != "true" {
		t.Errorf("listable = %v", b)
	}
	d := byName["example-dev"]
	if d["public"] != "yes" || d["severity"] != "low" || d["generated_from"] != "example.com;Acme" {
		t.Errorf("public = %v", d)
	}
	// A private bucket is listed, but is not a finding.
	if p := byName["exampleacct"]; p == nil || p["severity"] != "" || p["url"] != "https://exampleacct.blob.core.windows.net/media" {
		t.Errorf("private azure = %v", p)
	}
}

// Findings come from derivation; a risky-port finding is not subject to a second visibility test in output.
func TestRiskFilesNeedNoScopeBeyondDerivation(t *testing.T) {
	snap := snapshot(map[string][]store.Record{"finding": {
		srec("finding", "ports|risky-port|203.0.113.9:445", false, "category", "ports", "type", "risky-port", "severity", "medium", "target", "203.0.113.9:445", "ip", "203.0.113.9", "port", 445.0),
	}})
	if rows := file(t, "risk-ports.csv").Rows(snap); len(rows) != 1 || rows[0].Current {
		t.Errorf("rows = %+v", rows)
	}
	_ = input.Parsed{}
	_ = strings.TrimSpace
}
