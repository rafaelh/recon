package cli_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rafaelh/recon/internal/cli"
	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/findings"
	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/testkit"
)

// B7: a risky open port is medium; an exclusion added later makes it not-current
// in risk-ports.csv and removes it from the summary.
func TestRiskB7_RiskyPorts(t *testing.T) {
	x := newRisk(t)
	x.names()
	x.open("198.51.100.5:3389", "")
	x.open("198.51.100.5:8080", "")
	x.open("198.51.100.6:445", "")
	x.mustRun("--cidr", "198.51.100.0/24")

	rows := current(x.rows("risk-ports.csv"))
	if got := col(rows, "port"); !slices.Equal(got, []string{"3389", "445"}) {
		t.Fatalf("risk-ports.csv:\n%s", x.file(eng, "risk-ports.csv"))
	}
	for _, r := range rows {
		if r["severity"] != "medium" || r["banner"] != "" {
			t.Errorf("row = %v", r)
		}
	}
	if got := x.summaryTargets(); !slices.Equal(got, []string{"198.51.100.5:3389=medium", "198.51.100.6:445=medium"}) {
		t.Errorf("summary = %v", got)
	}

	x.mustRun("--cidr", "198.51.100.0/24", "-x", "198.51.100.5")
	all := x.rows("risk-ports.csv")
	r := find(all, "ip", "198.51.100.5")
	if len(all) != 2 || r == nil || r["current"] != "false" || r["first_seen"] != "2026-11-01" {
		t.Errorf("after the exclusion:\n%s", x.file(eng, "risk-ports.csv"))
	}
	if got := x.summaryTargets(); !slices.Equal(got, []string{"198.51.100.6:445=medium"}) {
		t.Errorf("summary after the exclusion = %v", got)
	}
}

// B7: a custom --risky-ports list replaces the default.
func TestRiskB7_RiskyPortsConfigurable(t *testing.T) {
	x := newRisk(t)
	x.names()
	x.open("198.51.100.5:3389", "")
	x.open("198.51.100.5:8080", "")
	x.mustRun("--cidr", "198.51.100.0/24", "--risky-ports", "8080")
	if got := col(current(x.rows("risk-ports.csv")), "port"); !slices.Equal(got, []string{"8080"}) {
		t.Errorf("risky ports flagged = %v", got)
	}
}

// B8: expired, expiring and self-signed certificates; the clock moves the findings with no new requests.
func TestRiskB8_Certificates(t *testing.T) {
	x := newRisk(t)
	x.names("old.example.com", "soon.example.com", "self.example.com", "fine.example.com")
	ca := newCA(t, "Test CA")
	sites := map[string]*site{}
	for name, spec := range map[string]struct {
		ip     string
		expiry time.Time
		self   bool
	}{
		"old":  {"203.0.113.21", time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC), false},
		"soon": {"203.0.113.22", time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC), false},
		"self": {"203.0.113.23", time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), true},
		"fine": {"203.0.113.24", farFuture, false},
	} {
		host := name + ".example.com"
		x.host(host, spec.ip)
		ls := leafSpec{cn: host, dns: []string{host}, notAfter: spec.expiry}
		cert := ca.issue(t, ls)
		if spec.self {
			cert = selfSigned(t, ls)
		}
		sites[name] = x.secure(spec.ip, 443, cert, page("hello"))
	}
	x.mustRun("--crawl-pages", "0")

	by := map[string]map[string]string{}
	for _, r := range current(x.rows("risk-certificates.csv")) {
		by[r["url"]] = r
	}
	if r := by["https://old.example.com"]; r == nil || r["type"] != "expired" || r["severity"] != "medium" || r["tls_expiry"] != "2026-10-15" || !strings.Contains(r["tls_issuer"], "Test CA") {
		t.Errorf("old = %v", r)
	}
	if r := by["https://soon.example.com"]; r == nil || r["type"] != "expiring" || r["severity"] != "low" {
		t.Errorf("soon = %v", r)
	}
	if r := by["https://self.example.com"]; r == nil || r["type"] != "self-signed" || r["severity"] != "low" {
		t.Errorf("self = %v", r)
	}
	if len(by) != 3 {
		t.Errorf("certificate findings = %v", col(current(x.rows("risk-certificates.csv")), "url"))
	}
	if got := x.summaryTargets(); !slices.Equal(got, []string{"https://old.example.com=medium"}) {
		t.Errorf("summary = %v (only medium and high are listed)", got)
	}
	hits := func() int {
		n := 0
		for _, s := range sites {
			n += s.hits()
		}
		return n
	}
	before := hits()

	// Thirty days on, with nothing new requested, the expiring certificate has expired.
	x.h.now = x.h.now.AddDate(0, 0, 30)
	x.mustRun("--crawl-pages", "0")
	if hits() != before {
		t.Errorf("advancing the clock sent %d requests", hits()-before)
	}
	by = map[string]map[string]string{}
	for _, r := range current(x.rows("risk-certificates.csv")) {
		by[r["url"]] = r
	}
	if r := by["https://soon.example.com"]; r == nil || r["type"] != "expired" || r["severity"] != "medium" {
		t.Errorf("soon after the clock moved = %v", r)
	}
	if got := x.summaryTargets(); !slices.Equal(got, []string{"https://old.example.com=medium", "https://soon.example.com=medium"}) {
		t.Errorf("summary = %v", got)
	}

	// --cert-expiry-days changes the window.
	x.h.now = x.h.now.AddDate(0, 0, -30)
	x.mustRun("--crawl-pages", "0", "--cert-expiry-days", "5")
	by = map[string]map[string]string{}
	for _, r := range current(x.rows("risk-certificates.csv")) {
		by[r["url"]] = r
	}
	if _, ok := by["https://soon.example.com"]; ok {
		t.Error("a 5-day window must not flag a certificate that expires in 19 days")
	}
	if hits() != before {
		t.Error("changing the window sent requests")
	}
}

// D8: the crawl records every storage URL in any link or asset, off-scope hosts included.
func TestRiskD8_CrawlRecordsStorageRefs(t *testing.T) {
	x := newWeb(t)
	x.names("www.example.com")
	x.host("www.example.com", "203.0.113.5")
	x.plain("203.0.113.5", 80, page(`<html><head>
<link rel="stylesheet" href="https://b-css.s3.amazonaws.com/s.css">
<script src="https://acctjs.blob.core.windows.net/media/app.js"></script></head><body>
<a href="https://s3.amazonaws.com/b-link/doc.pdf">doc</a>
<map><area href="https://storage.googleapis.com/b-area/x"></map>
<img src="https://b-img.s3.us-west-2.amazonaws.com/p.png">
<iframe src="https://storage.cloud.google.com/b-frame/f.html"></iframe>
<video><source src="https://b-src.storage.googleapis.com/v.mp4"></video>
<form action="https://s3.amazonaws.com/b-form/post" method="post"></form>
<a href="http://off.example.net/not-storage">off</a>
<a href="https://example.com/s3.amazonaws.com/nope">not storage</a>
</body></html>`))
	x.mustRun()
	want := map[string]string{
		"b-css": "asset", "acctjs": "asset", "b-link": "link", "b-area": "link", "b-img": "asset", "b-frame": "asset", "b-src": "asset", "b-form": "asset",
	}
	got := map[string]string{}
	for key, blob := range x.obsAttrs(eng, "storage_ref") {
		var a map[string]any
		if err := json.Unmarshal([]byte(blob), &a); err != nil {
			t.Fatal(err)
		}
		name, _ := a["name"].(string)
		got[name], _ = a["via"].(string)
		if a["page_host"] != "www.example.com" || a["page"] != "http://www.example.com/" || a["provider"] == "" {
			t.Errorf("%s = %v", key, a)
		}
	}
	if len(got) != len(want) {
		t.Errorf("references = %v, want %v", got, want)
	}
	for name, via := range want {
		if got[name] != via {
			t.Errorf("%s via %q, want %q", name, got[name], via)
		}
	}
	if len(x.obsAttrs(eng, "storage_ref")) != len(want) {
		t.Errorf("storage_ref observations = %d", len(x.obsAttrs(eng, "storage_ref")))
	}
}

// D8: a reference counts only while its page host is in scope.
func TestRiskD8_ReferenceFollowsPageScope(t *testing.T) {
	x := newRisk(t, "storage")
	x.names("www.example.com")
	x.host("www.example.com", "203.0.113.5")
	x.plain("203.0.113.5", 80, page(`<script src="https://s3.amazonaws.com/lost-a/x.js"></script>`))
	x.mustRun("--storage-max-names", "1")
	if got := col(current(x.rows("risk-takeover.csv")), "target"); !slices.Equal(got, []string{"s3:lost-a"}) {
		t.Fatalf("setup: %v", got)
	}
	x.mustRun("--storage-max-names", "1", "-x", "www.example.com")
	if got := col(current(x.rows("risk-takeover.csv")), "target"); len(got) != 0 {
		t.Errorf("the page host is excluded but the reference still counts: %v", got)
	}
	if got := x.summaryTargets(); len(got) != 0 {
		t.Errorf("summary = %v", got)
	}
}

// Plumbing: a file with no rows is not written; a spreadsheet formula in a cell is
// neutralised; rows are sorted.
func TestRiskPlumbing_FilesWrittenSortedAndSafe(t *testing.T) {
	x := newRisk(t, "sensitive-paths")
	x.names("a.example.com", "b.example.com")
	x.host("a.example.com", "203.0.113.5")
	x.host("b.example.com", "203.0.113.6")
	x.plain("203.0.113.5", 80, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("=SECRET")) })
	x.plain("203.0.113.6", 80, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("=SECRET")) })
	file := x.pathsFile("- path: /z\n  signature: '=SECRET'\n- path: /a\n  signature: '=SECRET'\n")
	x.mustRun("--crawl-pages", "0", "--sensitive-paths", file)
	for _, f := range []string{"storage-unattributed.csv", "risk-takeover.csv", "risk-storage.csv", "risk-ports.csv", "risk-certificates.csv"} {
		if _, err := os.Stat(filepath.Join(x.h.eng(eng), f)); !os.IsNotExist(err) {
			t.Errorf("%s has no rows but was written (err %v)", f, err)
		}
	}
	if !strings.HasPrefix(x.file(eng, "risk-sensitive-paths.csv"), "severity,url,path,status,size,signature,current,first_seen,last_seen\n") {
		t.Errorf("risk-sensitive-paths.csv = %q", x.file(eng, "risk-sensitive-paths.csv"))
	}
	rows := x.rows("risk-sensitive-paths.csv")
	if len(rows) != 4 {
		t.Fatalf("rows = %v", rows)
	}
	var urls []string
	for _, r := range rows {
		urls = append(urls, r["url"])
		if r["signature"] != "'=SECRET" {
			t.Errorf("a formula was not neutralised: %q", r["signature"])
		}
		if r["first_seen"] != "2026-11-01" || r["last_seen"] != "2026-11-01" {
			t.Errorf("not dated: %v", r)
		}
	}
	if !slices.IsSorted(urls) {
		t.Errorf("rows are not sorted: %v", urls)
	}
}

// D4: the registry order and each stage's contact.
func TestRiskD4_StageRegistry(t *testing.T) {
	var names []string
	contact := map[string]run.Contact{}
	for _, s := range cli.DefaultDeps().Stages {
		names = append(names, s.Name())
		contact[s.Name()] = s.Contact()
	}
	tail := names[slices.Index(names, "ipowner"):]
	if want := []string{"ipowner", "email", "httpprobe", "crawl", "storage", "takeover", "sensitive-paths", "ports"}; !slices.Equal(tail, want) {
		t.Errorf("stage order tail = %v, want %v", tail, want)
	}
	for name, want := range map[string]run.Contact{"email": run.ThirdParty, "storage": run.ThirdParty, "takeover": run.Target, "sensitive-paths": run.Target} {
		if contact[name] != want {
			t.Errorf("%s contact = %v", name, contact[name])
		}
	}
	// A pseudo-stage for findings is not a stage: --redo does not accept it.
	if slices.Contains(names, "findings") {
		t.Error("findings must not be a registered stage")
	}
}

// Plumbing: help shows the new settings and the severity table.
func TestRiskPlumbing_Help(t *testing.T) {
	h := newHarness(t, noop())
	if code := h.exec("--help"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	help := h.stdout.String()
	for _, w := range []string{"--storage-max-names", "50", "--cert-expiry-days", "30"} {
		if !strings.Contains(help, w) {
			t.Errorf("help lacks %q", w)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(findings.HelpTable()), "\n") {
		if !strings.Contains(help, strings.TrimSpace(line)) {
			t.Errorf("help lacks the severity table line %q", line)
		}
	}
}

// Plumbing: a found line is printed once per engagement, including for a finding
// derived on the interrupt path, and a resumed run does not print it again.
func TestRiskPlumbing_FoundOncePerEngagementAcrossInterrupt(t *testing.T) {
	var cancel context.CancelFunc
	var armed atomic.Bool
	armed.Store(true)
	seed := &testkit.Stage{StageName: "seed", Kind: run.ThirdParty,
		ChecksFn: func(run.View) []run.Check { return []run.Check{{Key: "c1"}, {Key: "c2"}} },
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			if c.Key == "c1" {
				return []run.Observation{obs("open_port", "198.51.100.5:3389", "ip", "198.51.100.5", "port", 3389, "banner", "")}, nil
			}
			if armed.CompareAndSwap(true, false) {
				cancel() // the interrupt arrives after c1 completed and before findings were derived
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return nil, nil
		}}
	h := newHarness(t, seed)
	ctx, c := context.WithCancel(context.Background())
	cancel = c
	defer c()
	code := h.execCtx(ctx, "--json", "--concurrency", "1", "-e", "risk", "--cidr", "198.51.100.0/24")
	if code != run.ExitInterrupted {
		t.Fatalf("exit %d\n%s", code, h.stdout.String())
	}
	foundFindings := func() []event {
		var out []event
		for _, e := range ofType(h.events(), "found") {
			if strings.HasPrefix(e.str("category"), "finding") {
				out = append(out, e)
			}
		}
		return out
	}
	if got := foundFindings(); len(got) != 1 || got[0].str("value") != "198.51.100.5:3389" || got[0].str("severity") != "medium" {
		t.Errorf("found lines on the interrupted run = %v", got)
	}
	rows := csvRows(t, h.readOut("risk", "risk-ports.csv"))
	if len(rows) != 2 {
		t.Errorf("risk-ports.csv was not written from the interrupt path: %v", rows)
	}

	if code := h.exec("--json", "--concurrency", "1", "-e", "risk"); code != 0 {
		t.Fatalf("resume exit %d\n%s", code, h.stdout.String())
	}
	if got := foundFindings(); len(got) != 0 {
		t.Errorf("the resumed run printed the finding again: %v", got)
	}
	if n := queryStrings(t, h.openDB("risk"), "SELECT key FROM records WHERE kind='finding' AND current=1"); len(n) != 1 {
		t.Errorf("findings = %v", n)
	}
}

// D1: findings are derived after every stage that did work, not only when the
// pass ends, so a later stage in the same pass (the hours-long port sweep) does
// not delay them.
func TestRiskD1_DerivedAfterEachStage(t *testing.T) {
	seed := &testkit.Stage{StageName: "seed", Kind: run.ThirdParty,
		ChecksFn: func(run.View) []run.Check { return []run.Check{{Key: "c1"}} },
		RunFn: func(context.Context, run.Check, egress.Clients) ([]run.Observation, error) {
			return []run.Observation{obs("open_port", "198.51.100.5:3389", "ip", "198.51.100.5", "port", 3389, "banner", "")}, nil
		}}
	var seen atomic.Int32
	seen.Store(-1)
	later := &testkit.Stage{StageName: "later", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check {
			if seen.Load() < 0 {
				seen.Store(int32(len(v.Records("finding"))))
			}
			return nil
		}}
	h := newHarness(t, seed, later)
	if code := h.exec("--json", "-e", "d1", "--cidr", "198.51.100.0/24"); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.stdout.String())
	}
	if n := seen.Load(); n != 1 {
		t.Errorf("findings visible to the next stage in the same pass = %d, want 1", n)
	}
}

// Plumbing: an interrupted run still lists exactly the current high and medium findings in no summary,
// and the run state shows the pseudo-stage `findings` is not a visible stage.
func TestRiskPlumbing_FindingsPseudoStageHidden(t *testing.T) {
	h := newHarness(t, noop())
	if code := h.exec("--json", "-e", "pseudo", "--cidr", "198.51.100.0/24"); code != 0 {
		t.Fatal(code)
	}
	for _, e := range ofType(h.events(), "stage") {
		if e.str("name") == "findings" {
			t.Errorf("findings appears as a stage: %v", e)
		}
	}
	if code := h.exec("--json", "-e", "pseudo", "--redo", "findings"); code != 2 {
		t.Errorf("--redo findings exit %d, want 2", code)
	}
}
