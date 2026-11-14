package findings_test

import (
	"slices"
	"testing"

	"github.com/rafaelh/recon/internal/findings"
	"github.com/rafaelh/recon/internal/store"
)

func srec(kind, key string, current bool, kv ...any) store.Record {
	a := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		a[kv[i].(string)] = kv[i+1]
	}
	return store.Record{Kind: kind, Key: key, Current: current, Attrs: a, FirstSeen: "2026-10-01", LastSeen: "2026-11-01"}
}

func file(t *testing.T, name string) findings.File {
	t.Helper()
	for _, f := range findings.Files() {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("no file %s", name)
	return findings.File{}
}

func cellMap(f findings.File, r findings.FileRow) map[string]string {
	m := map[string]string{}
	for i, c := range f.Columns {
		m[c] = r.Cells[i]
	}
	return m
}

func TestFiles(t *testing.T) {
	var names []string
	for _, f := range findings.Files() {
		names = append(names, f.Name)
	}
	want := []string{"storage-unattributed.csv", "risk-takeover.csv", "risk-storage.csv", "risk-sensitive-paths.csv",
		"risk-email.csv", "risk-ports.csv", "risk-certificates.csv", "risk-web-posture.csv"}
	if !slices.Equal(names, want) {
		t.Errorf("files = %v, want %v", names, want)
	}
}

// Keys are "takeover|<target>" and "<category>|<type>|<target>"; ParseKey reverses Key.
func TestKeyRoundTrip(t *testing.T) {
	for _, f := range []findings.Finding{
		{Category: findings.Takeover, Type: "dns-nxdomain", Target: "shop.example.com"},
		{Category: findings.Ports, Type: "risky-port", Target: "198.51.100.5:3389"},
		{Category: findings.SensitivePaths, Type: "/.env", Target: "https://www.example.com/.env"},
	} {
		cat, typ, target := findings.ParseKey(f.Key())
		wantType := f.Type
		if f.Category == findings.Takeover {
			wantType = "" // one finding per host: the key carries no type
		}
		if cat != f.Category || typ != wantType || target != f.Target {
			t.Errorf("ParseKey(%q) = %q %q %q", f.Key(), cat, typ, target)
		}
	}
}

func TestFromRecord(t *testing.T) {
	f := findings.FromRecord(srec("finding", "email|spf-missing|example.com", true,
		"category", "email", "type", "spf-missing", "severity", "medium", "target", "example.com", "detail", "no SPF record"))
	if f.Category != "email" || f.Type != "spf-missing" || f.Severity != "medium" || f.Target != "example.com" || f.Detail != "no SPF record" {
		t.Errorf("current = %+v", f)
	}
	// A finding no longer derived has no attributes: its key still says what it was.
	f = findings.FromRecord(srec("finding", "ports|risky-port|198.51.100.5:3389", false))
	if f.Category != "ports" || f.Type != "risky-port" || f.Target != "198.51.100.5:3389" || f.Severity != "" {
		t.Errorf("not current = %+v", f)
	}
}

// The summary lists current high and medium findings, high first, then by target.
func TestHeadline(t *testing.T) {
	fnd := func(key, sev, target string, current bool) store.Record {
		return srec("finding", key, current, "severity", sev, "target", target)
	}
	got := findings.Headline([]store.Record{
		fnd("email|dmarc-none|b.example.com", "low", "b.example.com", true),
		fnd("email|spf-missing|b.example.com", "medium", "b.example.com", true),
		fnd("takeover|z.example.com", "high", "z.example.com", true),
		fnd("email|spf-missing|a.example.com", "medium", "a.example.com", true),
		fnd("takeover|gone.example.com", "high", "gone.example.com", false),
		fnd("takeover|a.example.com", "high", "a.example.com", true),
	})
	var keys []string
	for _, f := range got {
		keys = append(keys, f.Severity+" "+f.Target)
	}
	want := []string{"high a.example.com", "high z.example.com", "medium a.example.com", "medium b.example.com"}
	if !slices.Equal(keys, want) {
		t.Errorf("headline = %v, want %v", keys, want)
	}
}

// The risk files list every finding of their category, current or not, with their columns.
func TestRiskFiles(t *testing.T) {
	fnd := func(category, typ, target string, current bool, kv ...any) store.Record {
		attrs := append([]any{"category", category, "type", typ, "severity", "medium", "target", target, "detail", "d"}, kv...)
		return srec("finding", category+"|"+typ+"|"+target, current, attrs...)
	}
	l := findings.Listing{Records: map[string][]store.Record{"finding": {
		fnd("takeover", "dns-nxdomain", "shop.example.com", true, "service", "Cloud Services", "cname", "x.cloudapp.net"),
		fnd("storage", "listable", "https://s3.amazonaws.com/b", false, "provider", "s3", "name", "b", "url", "https://s3.amazonaws.com/b",
			"exists", "true", "public", "unknown", "listable", "true", "object_count", "3", "first_keys", "a;b", "referenced_by", "static.example.com"),
		fnd("sensitive-paths", "/.env", "https://www.example.com/.env", true, "url", "https://www.example.com/.env", "path", "/.env",
			"status", 200.0, "size", 42.0, "signature", "X"),
		fnd("email", "spf-missing", "example.com", true, "root", "example.com"),
		fnd("ports", "risky-port", "198.51.100.5:3389", true, "ip", "198.51.100.5", "port", 3389.0, "banner", "", "hostnames", "a.example.com"),
		fnd("certificates", "expired", "https://www.example.com", true, "url", "https://www.example.com", "tls_subject", "CN=www", "tls_issuer", "CN=CA", "tls_expiry", "2026-10-01"),
		fnd("storage-unattributed", "listable", "s3|guess", true, "provider", "s3"),
	}}}
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
		rows := f.Rows(l)
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
	if rows := file(t, "risk-storage.csv").Rows(l); rows[0].Record.Current || rows[0].Record.FirstSeen != "2026-10-01" {
		t.Errorf("fixed finding stays on record as not current: %+v", rows[0])
	}
}

// A finding no longer derived keeps no attributes; its row is filled from its key.
func TestRiskFileRowFromKey(t *testing.T) {
	l := findings.Listing{Records: map[string][]store.Record{"finding": {
		srec("finding", "ports|risky-port|203.0.113.9:445", false),
		srec("finding", "sensitive-paths|/.git/config|https://www.example.com/.git/config", false),
		srec("finding", "takeover|shop.example.com", false),
	}}}
	for name, want := range map[string]map[string]string{
		"risk-ports.csv":           {"ip": "203.0.113.9", "port": "445", "severity": ""},
		"risk-sensitive-paths.csv": {"path": "/.git/config", "url": "https://www.example.com/.git/config"},
		"risk-takeover.csv":        {"target": "shop.example.com", "type": ""},
	} {
		f := file(t, name)
		rows := f.Rows(l)
		if len(rows) != 1 || rows[0].Record.Current {
			t.Errorf("%s rows = %+v", name, rows)
			continue
		}
		got := cellMap(f, rows[0])
		for k, v := range want {
			if got[k] != v {
				t.Errorf("%s %s = %q, want %q", name, k, got[k], v)
			}
		}
	}
}

// storage-unattributed.csv lists existing names that no current reference attributes.
func TestStorageUnattributedFile(t *testing.T) {
	st := func(key string, kv ...any) store.Record { return srec("storage", key, true, kv...) }
	l := findings.Listing{Records: map[string][]store.Record{
		"storage": {
			st("s3|example-backup", "provider", "s3", "name", "example-backup", "container", "", "exists", true, "listable", true, "object_count", "1000+", "first_keys", []any{"a", "b"}),
			st("gcs|example-dev", "provider", "gcs", "name", "example-dev", "container", "", "exists", true, "listable", false),
			st("s3|acme-assets", "provider", "s3", "name", "acme-assets", "container", "", "exists", true, "listable", true),
			st("s3|example-gone", "provider", "s3", "name", "example-gone", "container", "", "exists", false),
			st("azure|exampleacct/media", "provider", "azure", "name", "exampleacct", "container", "media", "exists", true, "listable", false),
		},
	}, Storage: map[string]findings.StorageAttr{
		"s3|example-backup":       {GeneratedFrom: []string{"example.com"}, Public: "unknown", Severity: "low"},
		"gcs|example-dev":         {GeneratedFrom: []string{"example.com", "Acme"}, Public: "yes", Severity: "low"},
		"s3|acme-assets":          {Attributed: true, Public: "unknown"},
		"s3|example-gone":         {GeneratedFrom: []string{"example.com"}, Public: "unknown"},
		"azure|exampleacct/media": {GeneratedFrom: []string{"example.com"}, Public: "unknown"},
	}}
	f := file(t, "storage-unattributed.csv")
	if !slices.Equal(f.Columns, []string{"provider", "name", "url", "exists", "public", "listable", "object_count", "first_keys", "generated_from", "severity"}) {
		t.Errorf("columns = %v", f.Columns)
	}
	byName := map[string]map[string]string{}
	for _, r := range f.Rows(l) {
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
