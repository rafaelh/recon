package cli_test

import (
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

// B3: a bucket referenced by an in-scope CNAME is attributed. A listable bucket
// records an object count and the first keys; objects are never fetched, only
// the first listed key and referenced objects are HEADed.
func TestRiskB3_AttributedByCNAME(t *testing.T) {
	x := newRisk(t, "storage")
	x.names("static.example.com")
	x.dns.CNAME("static.example.com", "acme-assets.s3.amazonaws.com")
	x.host("acme-assets.s3.amazonaws.com", "203.0.113.30")
	x.handle("s3.amazonaws.com", bucketHandler(map[string]bucket{
		"acme-assets": {list: 200, keys: []string{"a.txt", "b.txt", "c.txt"}, objs: map[string]int{"a.txt": 200}},
	}))
	x.mustRun("--storage-max-names", "1")

	r := find(x.rows("risk-storage.csv"), "name", "acme-assets")
	if r == nil {
		t.Fatalf("risk-storage.csv:\n%s", x.file(eng, "risk-storage.csv"))
	}
	if r["provider"] != "s3" || r["exists"] != "true" || r["listable"] != "true" || r["public"] != "yes" || r["object_count"] != "3" ||
		r["first_keys"] != "a.txt;b.txt;c.txt" || r["severity"] != "high" || !strings.Contains(r["referenced_by"], "static.example.com") ||
		r["url"] != "https://s3.amazonaws.com/acme-assets" {
		t.Errorf("row = %v", r)
	}
	s3 := x.src["s3.amazonaws.com"]
	if n := s3.count("GET", "/acme-assets"); n != 1 {
		t.Errorf("list requests = %d", n)
	}
	if got := heads(s3); !slices.Equal(got, []string{"/acme-assets/a.txt"}) {
		t.Errorf("HEADs = %v, want only the first listed key", got)
	}
	for _, q := range s3.requestLog() {
		if q.Method == http.MethodGet && strings.Count(strings.SplitN(q.URI, "?", 2)[0], "/") > 1 {
			t.Errorf("an object was fetched: %s", q.URI)
		}
		if strings.Contains(q.URI, "list-type=2") && !strings.Contains(q.URI, "max-keys=1000") {
			t.Errorf("listing %s", q.URI)
		}
	}
	if got := x.summaryTargets(); len(got) != 1 {
		t.Errorf("summary = %v", got)
	}
	// A completed check is never repeated.
	x.mustRun("--storage-max-names", "1")
	if n := s3.count("GET", "/acme-assets"); n != 1 {
		t.Errorf("a second run listed the bucket again (%d)", n)
	}
}

// B3: a script reference is attributed; a truncated listing says 1000+ and keeps five keys.
func TestRiskB3_AttributedByScript(t *testing.T) {
	x := newRisk(t, "storage")
	x.names("www.example.com")
	x.host("www.example.com", "203.0.113.5")
	x.plain("203.0.113.5", 80, page(`<html><script src="https://storage.googleapis.com/acme-gcs/app.js"></script></html>`))
	x.handle("storage.googleapis.com", bucketHandler(map[string]bucket{
		"acme-gcs": {list: 200, keys: numberedKeys(1000), truncated: true, objs: map[string]int{"app.js": 200}},
	}))
	x.mustRun("--storage-max-names", "1")
	r := find(x.rows("risk-storage.csv"), "name", "acme-gcs")
	if r == nil || r["provider"] != "gcs" || r["object_count"] != "1000+" || r["first_keys"] != "k0000;k0001;k0002;k0003;k0004" || r["severity"] != "high" {
		t.Fatalf("row = %v\n%s", r, x.file(eng, "risk-storage.csv"))
	}
	if !strings.Contains(r["referenced_by"], "http://www.example.com/") {
		t.Errorf("referenced_by = %q", r["referenced_by"])
	}
	// The referenced object and the first key are HEADed; nothing is downloaded.
	if got := heads(x.src["storage.googleapis.com"]); !slices.Equal(got, []string{"/acme-gcs/app.js", "/acme-gcs/k0000"}) {
		t.Errorf("HEADs = %v", got)
	}
}

// B3: a redirect hop to a storage URL is a reference, and 403 means it exists and is private.
func TestRiskB3_AttributedByRedirectAndPrivate(t *testing.T) {
	x := newRisk(t, "storage")
	x.names("www.example.com")
	x.host("www.example.com", "203.0.113.5")
	x.plain("203.0.113.5", 80, redirectTo(302, "https://acme-red.s3.amazonaws.com/"))
	x.handle("s3.amazonaws.com", bucketHandler(map[string]bucket{"acme-red": {list: 403}}))
	x.mustRun("--storage-max-names", "1", "--crawl-pages", "0")
	r := find(x.rows("risk-storage.csv"), "name", "acme-red")
	if r == nil || r["exists"] != "true" || r["listable"] != "false" || r["public"] != "unknown" || r["severity"] != "low" {
		t.Fatalf("row = %v\n%s", r, x.file(eng, "risk-storage.csv"))
	}
	if got := x.summaryTargets(); len(got) != 0 {
		t.Errorf("a private bucket is low and not in the summary: %v", got)
	}
}

// B3: the region a bucket lives in is followed from the 301.
func TestRiskB3_RegionRedirectFollowed(t *testing.T) {
	x := newRisk(t, "storage")
	x.names("static.example.com")
	x.dns.CNAME("static.example.com", "acme-eu.s3.amazonaws.com")
	x.host("acme-eu.s3.amazonaws.com", "203.0.113.30")
	x.handle("s3.amazonaws.com", bucketHandler(map[string]bucket{"acme-eu": {list: 301, redirect: "eu-west-1"}}))
	eu := x.serve("s3.eu-west-1.amazonaws.com", bucketHandler(map[string]bucket{"acme-eu": {list: 200, keys: []string{"a"}}}))
	x.mustRun("--storage-max-names", "1")
	if eu.count("GET", "/acme-eu") != 1 {
		t.Errorf("regional requests = %v", eu.requestLog())
	}
	if r := find(x.rows("risk-storage.csv"), "name", "acme-eu"); r == nil || r["listable"] != "true" {
		t.Errorf("row = %v", r)
	}
	// A region that is not a plain label is not followed.
	x2 := newRisk(t, "storage")
	x2.names("static.example.com")
	x2.dns.CNAME("static.example.com", "acme-eu.s3.amazonaws.com")
	x2.host("acme-eu.s3.amazonaws.com", "203.0.113.30")
	x2.handle("s3.amazonaws.com", bucketHandler(map[string]bucket{"acme-eu": {list: 301, redirect: "evil.example.net/x"}}))
	x2.mustRun("--storage-max-names", "1")
	if r := find(x2.rows("risk-storage.csv"), "name", "acme-eu"); r != nil {
		t.Errorf("a malformed region produced a result: %v", r)
	}
}

// B3: an Azure account is found by DNS, then the fixed container list is tried.
// The account's host is a candidate (a redirect recorded it) and is still contacted.
func TestRiskB3_AzureAccountThenContainers(t *testing.T) {
	x := newRisk(t, "storage")
	x.names("www.example.com")
	x.host("www.example.com", "203.0.113.5")
	x.plain("203.0.113.5", 80, redirectTo(302, "https://acctred.blob.core.windows.net/media/x.png"))
	x.host("acctred.blob.core.windows.net", "203.0.113.31")
	az := x.serve("acctred.blob.core.windows.net", containerHandler(map[string]bucket{
		"$web":  {list: 200, keys: []string{"index.html"}},
		"media": {list: 403},
	}))
	x.mustRun("--storage-max-names", "1", "--crawl-pages", "0")

	if x.dns.Count("acctred.blob.core.windows.net", "A") == 0 {
		t.Error("the account was not looked up in DNS")
	}
	found := map[string]bool{}
	for _, r := range az.requestLog() {
		if r.Method == http.MethodGet {
			found[strings.SplitN(r.URI, "?", 2)[0]] = true
			if !strings.Contains(r.URI, "restype=container") || !strings.Contains(r.URI, "comp=list") || !strings.Contains(r.URI, "maxresults=1000") {
				t.Errorf("list request %s", r.URI)
			}
		}
	}
	for _, c := range []string{"/$web", "/$root", "/public", "/assets", "/static", "/media", "/images", "/files", "/uploads", "/backup", "/data", "/logs"} {
		if !found[c] {
			t.Errorf("container %s was not tried: %v", c, found)
		}
	}
	if len(found) != 12 {
		t.Errorf("containers tried = %v", found)
	}
	rows := x.rows("risk-storage.csv")
	byContainer := map[string]map[string]string{}
	for _, r := range current(rows) {
		byContainer[r["url"]] = r
	}
	if r := byContainer["https://acctred.blob.core.windows.net/$web"]; r == nil || r["severity"] != "high" || r["first_keys"] != "index.html" {
		t.Errorf("$web = %v\n%s", r, x.file(eng, "risk-storage.csv"))
	}
	if r := byContainer["https://acctred.blob.core.windows.net/media"]; r == nil || r["severity"] != "low" || r["listable"] != "false" {
		t.Errorf("media = %v", r)
	}
	if len(byContainer) != 2 {
		t.Errorf("only existing containers are findings: %v", col(current(rows), "url"))
	}
}

// B3: a newly referenced object adds one HEAD check, does not re-list the bucket,
// and leaves no stale "public".
func TestRiskB3_NewObjectReference(t *testing.T) {
	x := newRisk(t, "storage")
	x.names("www.example.com", "static.example.com")
	x.host("www.example.com", "203.0.113.5")
	x.dns.CNAME("static.example.com", "acme-assets.s3.amazonaws.com")
	x.host("acme-assets.s3.amazonaws.com", "203.0.113.30")
	var html atomic.Value
	html.Store(`<html><script src="https://s3.amazonaws.com/acme-assets/old.js"></script></html>`)
	x.plain("203.0.113.5", 80, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html.Load().(string)))
	})
	objs := map[string]int{"k1": 403, "old.js": 403, "new.png": 200}
	x.handle("s3.amazonaws.com", bucketHandler(map[string]bucket{"acme-assets": {list: 200, keys: []string{"k1"}, objs: objs}}))
	x.mustRun("--storage-max-names", "1")
	s3 := x.src["s3.amazonaws.com"]
	r := find(x.rows("risk-storage.csv"), "name", "acme-assets")
	if r == nil || r["public"] != "no" {
		t.Fatalf("first run: %v", r)
	}
	if got := heads(s3); !slices.Equal(got, []string{"/acme-assets/k1", "/acme-assets/old.js"}) {
		t.Errorf("HEADs = %v", got)
	}

	html.Store(`<html><script src="https://s3.amazonaws.com/acme-assets/old.js"></script><img src="https://acme-assets.s3.amazonaws.com/new.png"></html>`)
	x.mustRun("--storage-max-names", "1", "--redo", "crawl")
	if got := heads(s3); !slices.Equal(got, []string{"/acme-assets/k1", "/acme-assets/new.png", "/acme-assets/old.js"}) {
		t.Errorf("HEADs after the new reference = %v", got)
	}
	if n := s3.count("GET", "/acme-assets"); n != 1 {
		t.Errorf("the bucket was listed %d times", n)
	}
	if r = find(x.rows("risk-storage.csv"), "name", "acme-assets"); r == nil || r["public"] != "yes" || r["listable"] != "true" || r["exists"] != "true" {
		t.Errorf("second run: %v", r)
	}
}

// B4: guessed names are capped per root and per org, in priority order, and checked
// on all three providers, under --passive.
func TestRiskB4_GuessedNamesCappedAndPassive(t *testing.T) {
	x := newRisk(t, "storage")
	x.names()
	x.mustRun("--passive", "--storage-max-names", "4", "--org", "Acme Corp")
	want := []string{
		"azure-account|acmecorp", "azure-account|acmecorpbackup", "azure-account|acmecorpbackups",
		"azure-account|example", "azure-account|examplebackup", "azure-account|examplecom",
		"gcs|acme-corp", "gcs|acmecorp", "gcs|acmecorp-backup", "gcs|acmecorp-backups",
		"gcs|example", "gcs|example-backup", "gcs|example-com", "gcs|example.com",
		"s3|acme-corp", "s3|acmecorp", "s3|acmecorp-backup", "s3|acmecorp-backups",
		"s3|example", "s3|example-backup", "s3|example-com", "s3|example.com",
	}
	got := x.completedKeys("storage")
	if !slices.Equal(got, want) {
		t.Errorf("storage checks:\n got %v\nwant %v", got, want)
	}
	if st := x.state("storage"); st.str("state") == "not-configured" {
		t.Errorf("storage state = %v", st)
	}
	n := len(x.src["s3.amazonaws.com"].requestLog())

	// Raising the cap adds only the new checks.
	x.mustRun("--passive", "--storage-max-names", "5", "--org", "Acme Corp")
	got2 := x.completedKeys("storage")
	if len(got2) <= len(got) {
		t.Fatalf("no new checks: %v", got2)
	}
	for _, k := range got {
		if !slices.Contains(got2, k) {
			t.Errorf("lost check %s", k)
		}
	}
	if added := len(x.src["s3.amazonaws.com"].requestLog()) - n; added != 2 { // one new S3 name per root and per org
		t.Errorf("a wider cap sent %d new S3 requests, want 2", added)
	}
}

// B4: unattributed names appear in storage-unattributed.csv and never in risk-storage.csv;
// only public or listable ones are findings, and always low. A guessed name that is also
// referenced is attributed.
func TestRiskB4_Unattributed(t *testing.T) {
	x := newRisk(t, "storage")
	x.names("static.example.com")
	x.dns.CNAME("static.example.com", "example-backup.s3.amazonaws.com") // also a guess
	x.host("example-backup.s3.amazonaws.com", "203.0.113.30")
	x.handle("s3.amazonaws.com", bucketHandler(map[string]bucket{
		"example":        {list: 200, keys: []string{"a"}},
		"example-backup": {list: 200, keys: []string{"b"}},
		"example-com":    {list: 403},
	}))
	x.handle("storage.googleapis.com", bucketHandler(map[string]bucket{
		"example": {list: 403, objs: map[string]int{}},
	}))
	x.mustRun("--storage-max-names", "4")

	un := x.rows("storage-unattributed.csv")
	byKey := map[string]map[string]string{}
	for _, r := range un {
		byKey[r["provider"]+"|"+r["name"]] = r
	}
	if r := byKey["s3|example"]; r == nil || r["listable"] != "true" || r["severity"] != "low" || r["generated_from"] != "example.com" || r["url"] != "https://s3.amazonaws.com/example" {
		t.Errorf("s3|example = %v\n%s", r, x.file(eng, "storage-unattributed.csv"))
	}
	if r := byKey["s3|example-com"]; r == nil || r["listable"] != "false" || r["severity"] != "" {
		t.Errorf("a private guessed bucket is listed, but is not a finding: %v", r)
	}
	if r := byKey["gcs|example"]; r == nil || r["severity"] != "" {
		t.Errorf("gcs|example = %v", r)
	}
	if byKey["s3|example-backup"] != nil {
		t.Error("a guessed name that is also referenced must be attributed, not unattributed")
	}
	for _, r := range x.rows("risk-storage.csv") {
		if r["name"] != "example-backup" {
			t.Errorf("risk-storage.csv lists a non-attributed bucket: %v", r)
		}
	}
	if r := find(x.rows("risk-storage.csv"), "name", "example-backup"); r == nil || r["severity"] != "high" {
		t.Errorf("attributed bucket = %v", r)
	}
	// Unattributed findings are low, so the summary lists only the attributed one.
	if got := x.summaryTargets(); len(got) != 1 || !strings.HasSuffix(got[0], "=high") {
		t.Errorf("summary = %v", got)
	}
	db := x.h.openDB(eng)
	if rows := queryStrings(t, db, "SELECT key FROM records WHERE kind='finding' AND key LIKE 'storage-unattributed|%'"); len(rows) != 1 {
		t.Errorf("unattributed findings = %v, want only the listable s3|example", rows)
	}
}

// B1: an unattributed listable bucket is low and never reaches the summary's high/medium list.
func TestRiskB1_UnattributedNeverInSummary(t *testing.T) {
	x := newRisk(t, "storage")
	x.names()
	x.handle("storage.googleapis.com", bucketHandler(map[string]bucket{"example": {list: 200, keys: []string{"secrets.txt"}, objs: map[string]int{"secrets.txt": 200}}}))
	x.mustRun("--passive", "--storage-max-names", "1")
	db := x.h.openDB(eng)
	if got := queryStrings(t, db, "SELECT attrs FROM observations WHERE kind='finding'"); len(got) != 1 || !strings.Contains(got[0], `"severity":"low"`) || !strings.Contains(got[0], `"category":"storage-unattributed"`) {
		t.Errorf("findings = %v", got)
	}
	if got := x.summaryFindings(); len(got) != 0 {
		t.Errorf("summary = %v", got)
	}
	r := find(x.rows("storage-unattributed.csv"), "name", "example")
	if r == nil || r["public"] != "yes" || r["listable"] != "true" || r["severity"] != "low" {
		t.Errorf("row = %v", r)
	}
	if len(x.rows("risk-storage.csv")) != 0 {
		t.Errorf("risk-storage.csv = %s", x.file(eng, "risk-storage.csv"))
	}
}

// D16: a redirect to a path-style provider endpoint records it as a candidate
// hostname; the storage stage still contacts it, like an Azure account host.
func TestRiskB3_PathStyleEndpointCandidateIsContacted(t *testing.T) {
	x := newRisk(t, "storage")
	x.names("www.example.com")
	x.host("www.example.com", "203.0.113.5")
	x.plain("203.0.113.5", 80, redirectTo(302, "https://storage.googleapis.com/acme-gcs/x.png"))
	gcs := x.serve("storage.googleapis.com", bucketHandler(map[string]bucket{"acme-gcs": {list: 403}}))
	x.mustRun("--storage-max-names", "1", "--crawl-pages", "0")
	if gcs.count("GET", "/acme-gcs") != 1 {
		t.Errorf("GCS requests = %v", gcs.requestLog())
	}
	if r := find(x.rows("risk-storage.csv"), "name", "acme-gcs"); r == nil || r["exists"] != "true" {
		t.Errorf("row = %v\n%s", r, x.file(eng, "risk-storage.csv"))
	}
	if st := x.state("storage"); st.num("failed") != 0 {
		t.Errorf("state = %v", st)
	}
}

// D10: Azure answers an anonymous listing with 404 ResourceNotFound (private or
// missing) or 409 PublicAccessNotPermitted. Existence is unknown: the check
// completes, is not retried, and is neither a finding nor a takeover.
func TestRiskB3_AzureUnknownContainersComplete(t *testing.T) {
	x := newRisk(t, "storage")
	x.names("www.example.com")
	x.host("www.example.com", "203.0.113.5")
	x.plain("203.0.113.5", 80, redirectTo(302, "https://acctpriv.blob.core.windows.net/media/x.png"))
	x.host("acctpriv.blob.core.windows.net", "203.0.113.31")
	az := x.serve("acctpriv.blob.core.windows.net", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		if strings.HasPrefix(r.URL.Path, "/media") {
			w.WriteHeader(409)
			w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?><Error><Code>PublicAccessNotPermitted</Code></Error>`))
			return
		}
		w.WriteHeader(404)
		w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?><Error><Code>ResourceNotFound</Code></Error>`))
	})
	x.mustRun("--storage-max-names", "1", "--crawl-pages", "0")
	if st := x.state("storage"); st.num("failed") != 0 {
		t.Errorf("state = %v", st)
	}
	if got := current(x.rows("risk-storage.csv")); len(got) != 0 {
		t.Errorf("unknown containers are not findings: %v", got)
	}
	if got := current(x.rows("risk-takeover.csv")); len(got) != 0 {
		t.Errorf("unknown containers are not takeovers: %v", got)
	}
	n := len(listRequests(az))
	if n != 12 {
		t.Errorf("container listings = %d, want 12", n)
	}
	x.mustRun("--storage-max-names", "1", "--crawl-pages", "0")
	if again := len(listRequests(az)); again != n {
		t.Errorf("completed containers were listed again: %d requests", again-n)
	}
}

// D10: a 307 for a new bucket may name its region only in Location.
func TestRiskB3_RegionFromLocation(t *testing.T) {
	x := newRisk(t, "storage")
	x.names("static.example.com")
	x.dns.CNAME("static.example.com", "acme-new.s3.amazonaws.com")
	x.host("acme-new.s3.amazonaws.com", "203.0.113.30")
	x.handle("s3.amazonaws.com", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://acme-new.s3-eu-west-1.amazonaws.com/?list-type=2")
		w.WriteHeader(307)
		w.Write([]byte(`<Error><Code>TemporaryRedirect</Code><Endpoint>acme-new.s3-eu-west-1.amazonaws.com</Endpoint></Error>`))
	})
	eu := x.serve("s3.eu-west-1.amazonaws.com", bucketHandler(map[string]bucket{"acme-new": {list: 200, keys: []string{"a"}}}))
	x.mustRun("--storage-max-names", "1")
	if eu.count("GET", "/acme-new") != 1 {
		t.Errorf("regional requests = %v", eu.requestLog())
	}
	if r := find(x.rows("risk-storage.csv"), "name", "acme-new"); r == nil || r["listable"] != "true" {
		t.Errorf("row = %v", r)
	}
}
