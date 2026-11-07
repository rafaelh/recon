package cli_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"
)

// B2: a dangling CNAME into a provider marked claimable is a high takeover, from
// DNS evidence alone, so it works under --passive with no target request.
func TestRiskB2_DNSTakeoverPassive(t *testing.T) {
	x := newRisk(t, "storage", "takeover", "sensitive-paths")
	x.names("shop.example.com", "ok.example.com")
	x.dns.CNAME("shop.example.com", "gone.cloudapp.net") // the target does not exist: NXDOMAIN
	x.dns.CNAME("blog.example.com", "gone.cloudfront.net")
	x.names("shop.example.com", "ok.example.com", "blog.example.com")
	x.host("ok.example.com", "203.0.113.9")
	x.mustRun("--passive", "--storage-max-names", "1")

	rows := current(x.rows("risk-takeover.csv"))
	if len(rows) != 1 {
		t.Fatalf("risk-takeover.csv = %v", x.file(eng, "risk-takeover.csv"))
	}
	r := rows[0]
	if r["target"] != "shop.example.com" || r["type"] != "dns-nxdomain" || r["severity"] != "high" || r["cname"] != "gone.cloudapp.net" || r["service"] != "Cloud Services" {
		t.Errorf("row = %v", r)
	}
	if got := x.summaryTargets(); !slices.Equal(got, []string{"shop.example.com=high"}) {
		t.Errorf("summary = %v (a CloudFront CNAME that dangles is not a claimable provider)", got)
	}
	for _, name := range []string{"takeover", "sensitive-paths"} {
		st := x.state(name)
		if st.str("state") != "not-configured" || st.str("reason") != "passive-only" {
			t.Errorf("%s state = %v", name, st)
		}
	}
	if st := x.state("storage"); st.str("state") == "not-configured" {
		t.Errorf("storage checks run in passive-only mode: %v", st)
	}
}

// B2: a resolving provider host whose body matches the fingerprint is a takeover; a different body is not.
func TestRiskB2_HTTPTakeover(t *testing.T) {
	x := newRisk(t, "takeover")
	x.names("app.example.com", "ok.example.com")
	x.dns.CNAME("app.example.com", "acme.herokuapp.com")
	x.host("acme.herokuapp.com", "203.0.113.7")
	x.dns.CNAME("ok.example.com", "fine.herokuapp.com")
	x.host("fine.herokuapp.com", "203.0.113.8")
	unclaimed := x.plain("203.0.113.7", 80, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte("<html><title>No such app</title></html>"))
	})
	claimed := x.plain("203.0.113.8", 80, page("<html>Welcome to our product</html>"))
	x.mustRun("--crawl-pages", "0")

	rows := current(x.rows("risk-takeover.csv"))
	if len(rows) != 1 || rows[0]["target"] != "app.example.com" || rows[0]["type"] != "http-fingerprint" || rows[0]["severity"] != "high" {
		t.Fatalf("risk-takeover.csv:\n%s", x.file(eng, "risk-takeover.csv"))
	}
	if unclaimed.count("/") != 2 || claimed.count("/") != 2 { // the probe's request and the takeover check's
		t.Errorf("GET / counts: %d %d, want 2 and 2", unclaimed.count("/"), claimed.count("/"))
	}
	if !unclaimed.onlyGET() || len(unclaimed.uris()) != 1 {
		t.Errorf("takeover requested %v", unclaimed.uris())
	}
	// Each check is keyed by service and the matched entry's fingerprint.
	keys := x.completedKeys("takeover")
	if len(keys) != 2 {
		t.Fatalf("takeover checks = %v", keys)
	}
	for _, k := range keys {
		if !strings.Contains(k, "|fp=") || len(k[strings.Index(k, "|fp=")+4:]) != 8 {
			t.Errorf("check key %q lacks an 8-character fingerprint hash", k)
		}
	}
	// A second run asks nothing again.
	before := unclaimed.count("/")
	x.mustRun("--crawl-pages", "0")
	if unclaimed.count("/") != before {
		t.Error("a completed takeover check was repeated")
	}
	// A service not on a provider with a fingerprint is never requested by the stage.
	if st := x.state("takeover"); st.str("state") == "failed" {
		t.Errorf("takeover state = %v", st)
	}
}

// B2/D6: a CNAME to a missing S3 bucket gives exactly one finding listing both kinds of evidence.
func TestRiskB2_MissingS3BucketOneFinding(t *testing.T) {
	x := newRisk(t, "storage", "takeover")
	x.names("static.example.com")
	x.dns.CNAME("static.example.com", "lost-bucket.s3.amazonaws.com")
	x.host("lost-bucket.s3.amazonaws.com", "203.0.113.30")
	x.plain("203.0.113.30", 80, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(noSuchBucketXML))
	})
	x.mustRun("--crawl-pages", "0", "--storage-max-names", "1")

	rows := current(x.rows("risk-takeover.csv"))
	if len(rows) != 1 || rows[0]["target"] != "static.example.com" || rows[0]["type"] != "http-fingerprint;storage-missing" || rows[0]["severity"] != "high" {
		t.Fatalf("risk-takeover.csv:\n%s", x.file(eng, "risk-takeover.csv"))
	}
	if got := x.summaryTargets(); len(got) != 1 {
		t.Errorf("summary = %v, want the one finding", got)
	}
	if st := current(x.rows("risk-storage.csv")); len(st) != 0 {
		t.Errorf("a missing bucket is a takeover, not a storage finding: %v", st)
	}
}

// B2/D6: a dangling Azure account CNAME is one finding: NXDOMAIN and a missing account.
func TestRiskB2_DanglingAzureAccountOneFinding(t *testing.T) {
	x := newRisk(t, "storage", "takeover")
	x.names("files.example.com")
	x.dns.CNAME("files.example.com", "acctone.blob.core.windows.net")
	x.mustRun("--storage-max-names", "1")

	rows := current(x.rows("risk-takeover.csv"))
	if len(rows) != 1 || rows[0]["target"] != "files.example.com" || rows[0]["type"] != "dns-nxdomain;storage-missing" || rows[0]["severity"] != "high" {
		t.Fatalf("risk-takeover.csv:\n%s", x.file(eng, "risk-takeover.csv"))
	}
}

// B2/D2: a missing bucket in <script src> is high; one referenced only by <a href> is low.
func TestRiskB2_MissingBucketByKindOfReference(t *testing.T) {
	x := newRisk(t, "storage")
	x.names("www.example.com")
	x.host("www.example.com", "203.0.113.5")
	x.plain("203.0.113.5", 80, page(`<html><body>
<script src="https://s3.amazonaws.com/lost-a/x.js"></script>
<a href="https://s3.amazonaws.com/lost-b/doc.pdf">doc</a>
</body></html>`))
	x.mustRun("--storage-max-names", "1")

	byTarget := map[string]map[string]string{}
	for _, r := range current(x.rows("risk-takeover.csv")) {
		byTarget[r["target"]] = r
	}
	if r := byTarget["s3:lost-a"]; r == nil || r["severity"] != "high" || r["type"] != "storage-missing" {
		t.Errorf("script reference = %v", r)
	}
	if r := byTarget["s3:lost-b"]; r == nil || r["severity"] != "low" || r["type"] != "storage-missing-link" {
		t.Errorf("link reference = %v", r)
	}
	if got := x.summaryTargets(); !slices.Equal(got, []string{"s3:lost-a=high"}) {
		t.Errorf("summary = %v; the low link-only finding is not listed", got)
	}
}

// D1/B2: a finding that is no longer derived becomes not-current and keeps its first_seen.
func TestRiskDerivationKeepsFirstSeen(t *testing.T) {
	x := newRisk(t, "takeover")
	x.names("shop.example.com")
	x.dns.CNAME("shop.example.com", "gone.cloudapp.net")
	x.mustRun("--passive")
	first := find(x.rows("risk-takeover.csv"), "target", "shop.example.com")
	if first == nil || first["current"] != "true" || first["first_seen"] != "2026-11-01" {
		t.Fatalf("first run: %v", first)
	}

	// The target is claimed: it resolves now. Re-resolve it.
	x.h.now = x.h.now.AddDate(0, 0, 3)
	x.host("gone.cloudapp.net", "203.0.113.40")
	x.mustRun("--passive", "--redo", "resolve")
	r := find(x.rows("risk-takeover.csv"), "target", "shop.example.com")
	if r == nil || r["current"] != "false" || r["first_seen"] != "2026-11-01" {
		t.Errorf("fixed finding = %v", r)
	}
	if got := x.summaryTargets(); len(got) != 0 {
		t.Errorf("summary = %v after the fix", got)
	}
}
