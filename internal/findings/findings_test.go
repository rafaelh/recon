package findings_test

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/rafaelh/recon/internal/config"
	"github.com/rafaelh/recon/internal/findings"
	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/inventory"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/provider"
	"github.com/rafaelh/recon/internal/scope"
	"github.com/rafaelh/recon/internal/store"
)

// fixture builds a findings.Input: a scope for example.com and 198.51.100.0/24.
type fixture struct {
	hosts []inventory.Host
	res   []inventory.Resolution
	recs  map[string][]store.Record
	excl  []string
	set   config.Settings
	today string
}

func newFixture() *fixture {
	return &fixture{recs: map[string][]store.Record{}, set: config.Defaults(), today: "2026-11-01"}
}

func rec(kind, key string, kv ...any) store.Record {
	a := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		a[kv[i].(string)] = kv[i+1]
	}
	return store.Record{Kind: kind, Key: key, Current: true, Attrs: a, FirstSeen: "2026-11-01", LastSeen: "2026-11-01"}
}

func (f *fixture) add(r store.Record) { f.recs[r.Kind] = append(f.recs[r.Kind], r) }

func (f *fixture) host(name string, addrs ...string) {
	f.hosts = append(f.hosts, inventory.Host{Name: name, Stages: []string{"crtsh"}})
	for _, a := range addrs {
		f.res = append(f.res, inventory.Resolution{Name: name, Type: "A", Value: a})
	}
}

func (f *fixture) cname(name, target string) {
	f.res = append(f.res, inventory.Resolution{Name: name, Type: "CNAME", Value: target})
	f.add(rec("resolution", name+"|CNAME|"+target, "name", name, "type", "CNAME", "value", target))
}

func (f *fixture) input(t *testing.T) findings.Input {
	t.Helper()
	inv := inventory.New(inventory.Data{Hosts: f.hosts, Resolutions: f.res}, provider.Default())
	var xs []input.Exclusion
	for _, e := range f.excl {
		x, err := input.ParseExclusion(e)
		if err != nil {
			t.Fatal(err)
		}
		xs = append(xs, x)
	}
	sc := scope.New(scope.Config{
		Roots: []string{"example.com"}, Netblocks: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		Exclusions: xs, Resolutions: inv.Addrs(), WildcardOnly: inv.WildcardOnly(),
	})
	recs := f.recs
	return findings.Input{Scope: sc, Inv: inv, Settings: f.set, Today: f.today, Roots: []string{"example.com"},
		Records: func(k kinds.Named) []store.Record { return recs[k.Name()] }}
}

func (f *fixture) derive(t *testing.T) []findings.Finding { return findings.Derive(f.input(t)) }

// types lists "category/type=severity" of the findings, sorted.
func summarise(fs []findings.Finding) []string {
	var out []string
	for _, x := range fs {
		out = append(out, fmt.Sprintf("%s/%s=%s", x.Category, x.Type, x.Severity))
	}
	sort.Strings(out)
	return out
}

func wantSet(t *testing.T, got []findings.Finding, want ...string) {
	t.Helper()
	sort.Strings(want)
	if g := summarise(got); !slices.Equal(g, want) {
		t.Errorf("findings = %v, want %v", g, want)
	}
}

// B1: every finding type has a documented severity and each is exactly this.
func TestSeverityTable(t *testing.T) {
	want := map[string]string{
		"takeover/dns-nxdomain":         "high",
		"takeover/http-fingerprint":     "high",
		"takeover/storage-missing":      "high",
		"takeover/storage-missing-link": "low",
		"storage/listable":              "high",
		"storage/public":                "medium",
		"storage/exists":                "low",
		"storage-unattributed/listable": "low",
		"storage-unattributed/public":   "low",
		"email/spf-all-plus":            "high",
		"email/spf-missing":             "medium",
		"email/spf-all-neutral":         "medium",
		"email/spf-invalid":             "medium",
		"email/spf-lookups":             "low",
		"email/dmarc-missing":           "medium",
		"email/dmarc-none":              "low",
		"email/no-mx-spf":               "low",
		"ports/risky-port":              "medium",
		"certificates/expired":          "medium",
		"certificates/expiring":         "low",
		"certificates/self-signed":      "low",
		"sensitive-paths/<path>":        "medium",
	}
	got := map[string]string{}
	for _, r := range findings.SeverityTable() {
		if r.Meaning == "" {
			t.Errorf("%s/%s has no meaning", r.Category, r.Type)
		}
		got[r.Category+"/"+r.Type] = r.Severity
	}
	for k, sev := range want {
		if got[k] != sev {
			t.Errorf("severity of %s = %q, want %q", k, got[k], sev)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("table row %s is not covered by the test", k)
		}
	}
	for _, sev := range got {
		if sev != "high" && sev != "medium" && sev != "low" {
			t.Errorf("severity %q is not high, medium or low", sev)
		}
	}
	// Unattributed storage is never high or medium, by construction.
	for k, sev := range got {
		if strings.HasPrefix(k, "storage-unattributed/") && sev != "low" {
			t.Errorf("%s = %s", k, sev)
		}
	}
	if s := findings.Severity("sensitive-paths", "/anything"); s != "medium" {
		t.Errorf("sensitive path default = %q", s)
	}
	help := findings.HelpTable()
	for _, w := range []string{"dns-nxdomain", "spf-all-plus", "risky-port", "self-signed", "high", "medium", "low"} {
		if !strings.Contains(help, w) {
			t.Errorf("help table lacks %q", w)
		}
	}
}

// B6: SPF, DMARC and MX cases.
func TestEmailFindings(t *testing.T) {
	good := map[string]any{
		"mx": "mail.example.com", "spf": "v=spf1 include:_spf.example.net -all", "spf_records": 1.0, "spf_all": "-all", "spf_lookups": 2.0,
		"dmarc": "v=DMARC1; p=reject", "dmarc_policy": "reject", "dmarc_source": "root",
	}
	with := func(kv ...any) map[string]any {
		m := map[string]any{}
		for k, v := range good {
			m[k] = v
		}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	cases := []struct {
		name  string
		attrs map[string]any
		want  []string
	}{
		{"all good", with(), nil},
		{"+all", with("spf", "v=spf1 +all", "spf_all", "+all"), []string{"email/spf-all-plus=high"}},
		{"bare all is +all", with("spf", "v=spf1 all", "spf_all", "+all"), []string{"email/spf-all-plus=high"}},
		{"?all", with("spf", "v=spf1 ?all", "spf_all", "?all"), []string{"email/spf-all-neutral=medium"}},
		{"~all is fine", with("spf", "v=spf1 ~all", "spf_all", "~all"), nil},
		{"spf missing", with("spf", "", "spf_records", 0.0, "spf_all", "", "spf_lookups", 0.0), []string{"email/spf-missing=medium"}},
		{"several records", with("spf_records", 2.0, "spf_error", "2 v=spf1 records"), []string{"email/spf-invalid=medium"}},
		{"unresolvable include", with("spf_error", "include:gone.example.net: NXDOMAIN"), []string{"email/spf-invalid=medium"}},
		{"include loop", with("spf_error", "include loop at a.example.net"), []string{"email/spf-invalid=medium"}},
		{"ten lookups is fine", with("spf_lookups", 10.0), nil},
		{"eleven lookups", with("spf_lookups", 11.0), []string{"email/spf-lookups=low"}},
		{"dmarc missing", with("dmarc", "", "dmarc_policy", "", "dmarc_source", ""), []string{"email/dmarc-missing=medium"}},
		{"p=none", with("dmarc", "v=DMARC1; p=none", "dmarc_policy", "none"), []string{"email/dmarc-none=low"}},
		{"applicable sp=none", with("dmarc", "v=DMARC1; p=reject; sp=none", "dmarc_policy", "none", "dmarc_source", "org"), []string{"email/dmarc-none=low"}},
		{"null MX with -all", with("mx", "", "spf", "v=spf1 -all"), nil},
		{"no MX lacking -all", with("mx", "", "spf", "v=spf1 include:x.example.net ~all", "spf_all", "~all"), []string{"email/no-mx-spf=low"}},
		{"no MX, no spf", with("mx", "", "spf", "", "spf_records", 0.0, "spf_all", "", "spf_lookups", 0.0), []string{"email/spf-missing=medium", "email/no-mx-spf=low"}},
		{"selectors found are not findings", with("dkim_selectors", "google;selector1"), nil},
		{"no selector found is informational", with("dkim_selectors", ""), nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture()
			f.add(rec("email_posture", "example.com", mapKV(c.attrs)...))
			wantSet(t, f.derive(t), c.want...)
		})
	}
	t.Run("out of scope root", func(t *testing.T) {
		f := newFixture()
		f.excl = []string{"example.com"}
		f.add(rec("email_posture", "example.com", mapKV(with("spf", ""))...))
		wantSet(t, f.derive(t))
	})
}

func mapKV(m map[string]any) []any {
	var kv []any
	for k, v := range m {
		kv = append(kv, k, v)
	}
	return kv
}

// B7: risky open ports are medium, filtered by port visibility.
func TestRiskyPorts(t *testing.T) {
	f := newFixture()
	f.add(rec("open_port", "198.51.100.5:3389", "ip", "198.51.100.5", "port", 3389.0, "banner", ""))
	f.add(rec("open_port", "198.51.100.5:8080", "ip", "198.51.100.5", "port", 8080.0, "banner", ""))
	f.add(rec("open_port", "203.0.113.9:445", "ip", "203.0.113.9", "port", 445.0, "banner", "")) // not port-eligible
	got := f.derive(t)
	wantSet(t, got, "ports/risky-port=medium")
	if got[0].Target != "198.51.100.5:3389" || got[0].Key() != "ports|risky-port|198.51.100.5:3389" {
		t.Errorf("finding = %+v key %q", got[0], got[0].Key())
	}
	f.set.RiskyPorts = []int{8080}
	wantSet(t, f.derive(t), "ports/risky-port=medium")
	f.excl = []string{"198.51.100.0/24"}
	wantSet(t, f.derive(t))
}

// B8: certificate findings follow the date.
func TestCertificates(t *testing.T) {
	f := newFixture()
	f.host("old.example.com")
	f.host("soon.example.com")
	f.host("far.example.com")
	f.host("self.example.com")
	f.host("both.example.com")
	f.host("edge.example.com")
	svc := func(host, expiry string, self bool) store.Record {
		return rec("web_service", "https://"+host, "host", host, "scheme", "https", "tls_expiry", expiry, "tls_self_signed", self,
			"tls_subject", "CN="+host, "tls_issuer", "CN=Test CA")
	}
	f.add(svc("old.example.com", "2026-10-31", false))
	f.add(svc("soon.example.com", "2026-11-30", false))
	f.add(svc("far.example.com", "2026-12-01", false)) // today + 30 days exactly: not within the window
	f.add(svc("self.example.com", "2030-01-01", true))
	f.add(svc("both.example.com", "2020-01-01", true))
	f.add(svc("edge.example.com", "2026-11-01", false)) // expires today
	f.add(rec("web_service", "http://plain.example.com", "host", "plain.example.com", "scheme", "http"))
	got := f.derive(t)
	wantSet(t, got,
		"certificates/expired=medium", "certificates/expiring=low", "certificates/self-signed=low",
		"certificates/expired;self-signed=medium", "certificates/expiring=low")
	byTarget := map[string]findings.Finding{}
	for _, x := range got {
		byTarget[x.Target] = x
	}
	if x := byTarget["https://old.example.com"]; x.Type != "expired" || x.Attrs["tls_expiry"] != "2026-10-31" || x.Attrs["tls_issuer"] != "CN=Test CA" {
		t.Errorf("old = %+v", x)
	}
	if x := byTarget["https://both.example.com"]; x.Type != "expired;self-signed" || x.Severity != "medium" {
		t.Errorf("both = %+v", x)
	}
	if _, ok := byTarget["https://far.example.com"]; ok {
		t.Error("far.example.com is outside the window")
	}

	// The clock moves the same data: no new requests, the expiring certificate is now expired.
	f.today = "2026-12-05"
	if x := byKey(f.derive(t))["certificates|expired|https://soon.example.com"]; x.Severity != "medium" {
		t.Errorf("after the clock moved: %+v", x)
	}
	// --cert-expiry-days changes the window.
	f.today = "2026-11-01"
	f.set.CertExpiryDays = 0
	if _, ok := byKey(f.derive(t))["certificates|expiring|https://soon.example.com"]; ok {
		t.Error("a 0-day window flags nothing as expiring")
	}
	f.set.CertExpiryDays = 60
	if _, ok := byKey(f.derive(t))["certificates|expiring|https://far.example.com"]; !ok {
		t.Error("a 60-day window flags far.example.com")
	}
	// An excluded host is not reported.
	f.excl = []string{"old.example.com"}
	if _, ok := byKey(f.derive(t))["certificates|expired|https://old.example.com"]; ok {
		t.Error("excluded host reported")
	}
}

func byKey(fs []findings.Finding) map[string]findings.Finding {
	m := map[string]findings.Finding{}
	for _, x := range fs {
		m[x.Key()] = x
	}
	return m
}

// B5/D11: a sensitive hit is a finding only while its service is current and visible.
func TestSensitiveHits(t *testing.T) {
	f := newFixture()
	f.host("www.example.com")
	f.add(rec("web_service", "https://www.example.com", "host", "www.example.com", "scheme", "https"))
	entry := config.SensitivePath{Path: "/.git/config", Signature: `\[core\]`, Status: 200, Severity: "high"}
	f.set.SensitivePathEntries = []config.SensitivePath{entry}
	f.add(rec("sensitive_hit", "https://www.example.com|/.git/config", "service", "https://www.example.com", "host", "www.example.com",
		"url", "https://www.example.com/.git/config", "path", "/.git/config", "status", 200.0, "size", 120.0, "signature", `\[core\]`, "hash", entry.Hash()))
	f.add(rec("sensitive_hit", "https://www.example.com|/.env", "service", "https://www.example.com", "host", "www.example.com",
		"url", "https://www.example.com/.env", "path", "/.env", "status", 200.0, "size", 10.0, "signature", "X", "hash", "deadbeef"))
	f.add(rec("sensitive_hit", "https://gone.example.com|/.env", "service", "https://gone.example.com", "host", "gone.example.com",
		"url", "https://gone.example.com/.env", "path", "/.env", "status", 200.0, "size", 10.0, "signature", "X", "hash", "deadbeef"))
	got := f.derive(t)
	wantSet(t, got, "sensitive-paths//.git/config=high", "sensitive-paths//.env=medium")
	m := byKey(got)
	x := m["sensitive-paths|/.git/config|https://www.example.com/.git/config"]
	if x.Attrs["status"] == nil || x.Attrs["size"] == nil || x.Attrs["signature"] != `\[core\]` || x.Attrs["path"] != "/.git/config" {
		t.Errorf("attrs = %+v", x.Attrs)
	}
	// The entry's severity follows the current configuration without a new request...
	f.set.SensitivePathEntries = []config.SensitivePath{{Path: "/.git/config", Signature: `\[core\]`, Status: 200, Severity: "low"}}
	if m := byKey(f.derive(t)); m["sensitive-paths|/.git/config|https://www.example.com/.git/config"].Severity != "low" {
		t.Errorf("a severity edit applies at once: %+v", m)
	}
	// ...but an entry whose signature changed no longer matches the hit's hash: the default applies.
	f.set.SensitivePathEntries = []config.SensitivePath{{Path: "/.git/config", Signature: `different`, Status: 200, Severity: "low"}}
	if m := byKey(f.derive(t)); m["sensitive-paths|/.git/config|https://www.example.com/.git/config"].Severity != "medium" {
		t.Errorf("a hit whose entry changed gets the default severity: %+v", m)
	}
	f.excl = []string{"www.example.com"}
	wantSet(t, f.derive(t))
}

func storageRec(provider, name, container string, kv ...any) store.Record {
	key := provider + "|" + name
	if container != "" {
		key += "/" + container
	}
	attrs := append([]any{"provider", provider, "name", name, "container", container}, kv...)
	return rec("storage", key, attrs...)
}

// B3: attributed storage findings.
func TestAttributedStorage(t *testing.T) {
	cases := []struct {
		name  string
		recs  []store.Record
		want  []string
		check func(*testing.T, findings.Finding)
	}{
		{"listable is high", []store.Record{storageRec("s3", "acme-assets", "", "exists", true, "listable", true, "object_count", "3", "first_keys", []any{"a", "b", "c"})},
			[]string{"storage/listable=high"}, func(t *testing.T, x findings.Finding) {
				if x.Attrs["object_count"] != "3" || x.Attrs["referenced_by"] != "static.example.com" || x.Attrs["url"] != "https://s3.amazonaws.com/acme-assets" || x.Attrs["exists"] != "true" {
					t.Errorf("attrs = %+v", x.Attrs)
				}
			}},
		{"public, not listable, is medium", []store.Record{
			storageRec("s3", "acme-assets", "", "exists", true, "listable", false),
			rec("storage_object", "s3|acme-assets/a.png", "bucket", "s3|acme-assets", "public", true)},
			[]string{"storage/public=medium"}, nil},
		{"private object leaves it low", []store.Record{
			storageRec("s3", "acme-assets", "", "exists", true, "listable", false),
			rec("storage_object", "s3|acme-assets/a.png", "bucket", "s3|acme-assets", "public", false)},
			[]string{"storage/exists=low"}, nil},
		{"exists and private is low", []store.Record{storageRec("s3", "acme-assets", "", "exists", true, "listable", false)}, []string{"storage/exists=low"}, nil},
		{"missing is a takeover", []store.Record{storageRec("s3", "acme-assets", "", "exists", false)},
			[]string{"takeover/http-fingerprint;storage-missing=high"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture()
			f.host("static.example.com")
			f.cname("static.example.com", "acme-assets.s3.amazonaws.com")
			for _, r := range c.recs {
				f.add(r)
			}
			if c.name == "missing is a takeover" { // the takeover stage's HTTP evidence
				f.add(rec("web_service", "https://static.example.com", "host", "static.example.com", "scheme", "https"))
				f.add(rec("takeover_http", "https://static.example.com", "host", "static.example.com", "service", "https://static.example.com",
					"url", "https://static.example.com/", "status", 404.0))
			}
			got := f.derive(t)
			wantSet(t, got, c.want...)
			if c.check != nil && len(got) == 1 {
				c.check(t, got[0])
			}
		})
	}
}

// B3/B4: attribution by reference; guessed names that are also referenced are attributed.
func TestStorageAttribution(t *testing.T) {
	f := newFixture()
	f.host("static.example.com")
	f.cname("static.example.com", "acme-assets.s3.amazonaws.com")
	f.add(storageRec("s3", "acme-assets", "", "exists", true, "listable", true))
	f.add(storageRec("s3", "example-backup", "", "exists", true, "listable", true))
	f.add(storageRec("gcs", "example-dev", "", "exists", true, "listable", false))
	f.add(rec("storage_object", "gcs|example-dev/x", "bucket", "gcs|example-dev", "public", true))
	f.add(storageRec("s3", "example-logs", "", "exists", true, "listable", false)) // private guess: not a finding
	f.add(storageRec("s3", "example-nothing", "", "exists", false))
	in := f.input(t)
	got := findings.Derive(in)
	wantSet(t, got, "storage/listable=high", "storage-unattributed/listable=low", "storage-unattributed/public=low")
	for _, x := range got {
		if x.Category == "storage-unattributed" && x.Severity != "low" {
			t.Errorf("unattributed finding %s is %s", x.Target, x.Severity)
		}
	}
	attr := findings.Attribution(in)
	if a := attr["s3|acme-assets"]; !a.Attributed || len(a.GeneratedFrom) != 0 {
		t.Errorf("referenced = %+v", a)
	}
	if a := attr["s3|example-backup"]; a.Attributed || !slices.Equal(a.GeneratedFrom, []string{"example.com"}) || a.Public != "unknown" || a.Severity != "low" {
		t.Errorf("guessed = %+v", a)
	}
	if a := attr["gcs|example-dev"]; a.Public != "yes" || a.Severity != "low" {
		t.Errorf("guessed public = %+v", a)
	}
	if a := attr["s3|example-logs"]; a.Public != "unknown" || a.Severity != "" {
		t.Errorf("guessed private = %+v", a) // listed, not a finding
	}
	if a := attr["s3|acme-assets"]; a.Severity != "" {
		t.Errorf("attributed = %+v: severity is only for the unattributed file", a)
	}
	// A guessed name that is also referenced is attributed, and not listed as unattributed.
	f.cname("cdn.example.com", "example-backup.s3.amazonaws.com")
	f.host("cdn.example.com")
	in = f.input(t)
	if a := findings.Attribution(in)["s3|example-backup"]; !a.Attributed {
		t.Errorf("now referenced = %+v", a)
	}
	wantSet(t, findings.Derive(in), "storage/listable=high", "storage/listable=high", "storage-unattributed/public=low")
}

// B3: Azure references attribute the account's containers.
func TestAzureAttribution(t *testing.T) {
	f := newFixture()
	f.add(rec("storage_ref", "https://www.example.com/|https://acctone.blob.core.windows.net/media/a.png",
		"provider", "azure", "name", "acctone", "container", "media", "object", "a.png",
		"page", "https://www.example.com/", "page_host", "www.example.com", "via", "asset"))
	f.host("www.example.com")
	f.add(storageRec("azure", "acctone", "media", "exists", true, "listable", true))
	f.add(storageRec("azure", "acctone", "$web", "exists", true, "listable", false))
	f.add(storageRec("azure", "other", "media", "exists", true, "listable", true)) // unreferenced account
	wantSet(t, f.derive(t), "storage/listable=high", "storage/exists=low", "storage-unattributed/listable=low")
}

// B2/D6: one takeover finding per hostname, merging every kind of evidence.
func TestTakeoverDNS(t *testing.T) {
	t.Run("dangling cname into an nxdomain provider", func(t *testing.T) {
		f := newFixture()
		f.host("shop.example.com")
		f.cname("shop.example.com", "acme.cloudapp.net")
		f.add(rec("unresolved", "shop.example.com", "rcode", "NXDOMAIN"))
		got := f.derive(t)
		wantSet(t, got, "takeover/dns-nxdomain=high")
		if got[0].Key() != "takeover|shop.example.com" || got[0].Target != "shop.example.com" {
			t.Errorf("finding = %+v", got[0])
		}
		if got[0].Attrs["cname"] != "acme.cloudapp.net" || got[0].Attrs["service"] != "Cloud Services" {
			t.Errorf("attrs = %+v", got[0].Attrs)
		}
	})
	t.Run("not claimable", func(t *testing.T) {
		for name, mod := range map[string]func(*fixture){
			"servfail, not nxdomain": func(f *fixture) {
				f.recs["unresolved"] = []store.Record{rec("unresolved", "shop.example.com", "rcode", "SERVFAIL")}
			},
			"it resolves": func(f *fixture) {
				f.recs["unresolved"] = nil
				f.res = append(f.res, inventory.Resolution{Name: "shop.example.com", Type: "A", Value: "203.0.113.1"})
			},
			"provider is not marked nxdomain": func(f *fixture) {
				f.cname("blog.example.com", "acme.cloudfront.net")
				f.host("blog.example.com")
				f.recs["unresolved"] = []store.Record{rec("unresolved", "blog.example.com", "rcode", "NXDOMAIN")}
			},
			"excluded host": func(f *fixture) { f.excl = []string{"shop.example.com"} },
		} {
			f := newFixture()
			f.host("shop.example.com")
			f.cname("shop.example.com", "acme.cloudapp.net")
			f.add(rec("unresolved", "shop.example.com", "rcode", "NXDOMAIN"))
			mod(f)
			if got := f.derive(t); len(got) != 0 {
				t.Errorf("%s: findings = %v", name, summarise(got))
			}
		}
	})
	t.Run("one finding for dns and storage evidence", func(t *testing.T) {
		f := newFixture()
		f.host("files.example.com")
		f.cname("files.example.com", "acctone.blob.core.windows.net")
		f.add(rec("unresolved", "files.example.com", "rcode", "NXDOMAIN"))
		f.add(rec("storage_account", "acctone", "exists", false))
		got := f.derive(t)
		wantSet(t, got, "takeover/dns-nxdomain;storage-missing=high")
	})
	t.Run("http evidence", func(t *testing.T) {
		f := newFixture()
		f.host("app.example.com", "203.0.113.7")
		f.cname("app.example.com", "acme.herokuapp.com")
		f.add(rec("web_service", "https://app.example.com", "host", "app.example.com", "scheme", "https"))
		f.add(rec("takeover_http", "https://app.example.com", "host", "app.example.com", "service", "https://app.example.com",
			"url", "https://app.example.com/", "status", 404.0))
		wantSet(t, f.derive(t), "takeover/http-fingerprint=high")
		// Not current service: not reported.
		f.recs["web_service"] = nil
		wantSet(t, f.derive(t))
	})
}

// B2/D2: a missing bucket referenced only by a link is low; by an asset, high.
func TestMissingBucketReferences(t *testing.T) {
	ref := func(via, key string) store.Record {
		return rec("storage_ref", key, "provider", "s3", "name", "lost-bucket", "container", "", "object", "x.js",
			"page", "https://www.example.com/", "page_host", "www.example.com", "via", via)
	}
	f := newFixture()
	f.host("www.example.com")
	f.add(storageRec("s3", "lost-bucket", "", "exists", false))
	f.add(ref("link", "https://www.example.com/|a"))
	got := f.derive(t)
	wantSet(t, got, "takeover/storage-missing-link=low")
	if got[0].Key() != "takeover|s3:lost-bucket" {
		t.Errorf("key = %q", got[0].Key())
	}
	f.add(ref("asset", "https://www.example.com/|b"))
	wantSet(t, f.derive(t), "takeover/storage-missing=high")
	// A reference from an out-of-scope page does not count.
	f2 := newFixture()
	f2.add(storageRec("s3", "lost-bucket", "", "exists", false))
	r := ref("asset", "https://elsewhere.test/|c")
	r.Attrs["page_host"] = "elsewhere.test"
	f2.add(r)
	wantSet(t, f2.derive(t))
}

// B2: a missing container in an existing Azure account cannot be claimed, so it
// is not a takeover; a missing account is.
func TestMissingAzureContainerIsNotTakeover(t *testing.T) {
	f := newFixture()
	f.host("www.example.com")
	f.add(rec("storage_ref", "https://www.example.com/|a", "provider", "azure", "name", "acctone", "container", "gone",
		"object", "x.js", "page", "https://www.example.com/", "page_host", "www.example.com", "via", "asset"))
	f.add(rec("storage_account", "acctone", "exists", true))
	f.add(storageRec("azure", "acctone", "gone", "exists", false))
	wantSet(t, f.derive(t))

	f.recs["storage_account"] = []store.Record{rec("storage_account", "acctone", "exists", false)}
	wantSet(t, f.derive(t), "takeover/storage-missing=high")
}

// D1: derivation is deterministic: the same input gives the same findings in the same order.
func TestDeriveDeterministic(t *testing.T) {
	f := newFixture()
	f.add(rec("open_port", "198.51.100.5:3389", "banner", ""))
	f.add(rec("open_port", "198.51.100.5:445", "banner", ""))
	f.add(rec("email_posture", "example.com", "mx", "m", "spf", "", "dmarc", "", "spf_records", 0.0))
	a, b := f.derive(t), f.derive(t)
	if fmt.Sprint(a) != fmt.Sprint(b) || len(a) < 4 {
		t.Errorf("\n%v\n%v", a, b)
	}
	for i := 1; i < len(a); i++ {
		if a[i-1].Key() > a[i].Key() {
			t.Errorf("not sorted by key: %s before %s", a[i-1].Key(), a[i].Key())
		}
	}
}
