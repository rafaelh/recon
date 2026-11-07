package cli_test

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

const pathsYAML = `
- path: /.git/config
  signature: '\[core\]'
  severity: high
- path: /.env
  signature: '(?m)^SECRET_KEY='
- path: /backup.gz
  magic: 1f8b08
`

const secretBody = "SECRET_KEY=hunter2-do-not-store\nOTHER=1\n"

func (x *risk) pathsFile(body string) string {
	return writeFile(x.t, x.t.TempDir(), "paths.yaml", body)
}

// leaky serves the three sensitive files and an HTML catch-all for everything else.
func leaky(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.git/config":
		_, _ = w.Write([]byte("[core]\n\trepositoryformatversion = 0\n"))
	case "/.env":
		_, _ = w.Write([]byte(secretBody))
	case "/backup.gz":
		_, _ = w.Write([]byte{0x1f, 0x8b, 0x08, 0x00, 0x01, 0x02})
	default:
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>Welcome. Everything here returns 200.</html>"))
	}
}

// B5: each path once per live service, flagged by signature or magic, with the
// body never stored; a catch-all 200 is not flagged.
func TestRiskB5_RequestedOnceAndMatched(t *testing.T) {
	x := newRisk(t, "sensitive-paths")
	x.names("www.example.com", "plain.example.com")
	x.host("www.example.com", "203.0.113.5")
	x.host("plain.example.com", "203.0.113.6")
	www := x.plain("203.0.113.5", 80, leaky)
	plain := x.plain("203.0.113.6", 80, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>catch-all</html>")) // 200 for every path, matching nothing
	})
	x.mustRun("--crawl-pages", "0", "--sensitive-paths", x.pathsFile(pathsYAML))

	for _, p := range []string{"/.git/config", "/.env", "/backup.gz"} {
		if www.count(p) != 1 || plain.count(p) != 1 {
			t.Errorf("%s requested %d and %d times, want once per service", p, www.count(p), plain.count(p))
		}
	}
	if !www.onlyGET() {
		t.Error("non-GET request")
	}
	rows := current(x.rows("risk-sensitive-paths.csv"))
	if got := col(rows, "path"); !slices.Equal(got, []string{"/.env", "/.git/config", "/backup.gz"}) {
		t.Fatalf("paths flagged = %v\n%s", got, x.file(eng, "risk-sensitive-paths.csv"))
	}
	for _, r := range rows {
		if !strings.HasPrefix(r["url"], "http://www.example.com/") || r["status"] != "200" || r["size"] == "0" || r["signature"] == "" {
			t.Errorf("row = %v", r)
		}
	}
	if r := find(rows, "path", "/.git/config"); r["severity"] != "high" || r["size"] != strconv.Itoa(len("[core]\n\trepositoryformatversion = 0\n")) {
		t.Errorf(".git/config = %v", r)
	}
	if r := find(rows, "path", "/.env"); r["severity"] != "medium" || !strings.Contains(r["signature"], "SECRET_KEY") {
		t.Errorf(".env = %v", r)
	}
	if r := find(rows, "path", "/backup.gz"); r["signature"] != "magic:1f8b08" {
		t.Errorf("backup.gz = %v", r)
	}
	if got := x.summaryTargets(); len(got) != 3 || !slices.Contains(got, "http://www.example.com/.git/config=high") {
		t.Errorf("summary = %v", got)
	}
	// The body never reaches the store, a file or the console.
	if hits := x.anywhere(eng, "hunter2-do-not-store"); len(hits) != 0 {
		t.Errorf("a response body was stored: %v", hits)
	}

	// A second run asks nothing again.
	x.mustRun("--crawl-pages", "0", "--sensitive-paths", x.pathsFile(pathsYAML))
	if www.count("/.env") != 1 || plain.count("/.env") != 1 {
		t.Error("a second run repeated a completed check")
	}
	// A redone stage asks again.
	x.mustRun("--crawl-pages", "0", "--sensitive-paths", x.pathsFile(pathsYAML), "--redo", "sensitive-paths")
	if www.count("/.env") != 2 {
		t.Errorf("--redo sensitive-paths: /.env requested %d times", www.count("/.env"))
	}
}

// B5: a transient failure is retried on the next run; the rest are not repeated.
func TestRiskB5_TransientFailureRetried(t *testing.T) {
	x := newRisk(t, "sensitive-paths")
	x.names("www.example.com")
	x.host("www.example.com", "203.0.113.5")
	var broken atomic.Bool
	broken.Store(true)
	s := x.plain("203.0.113.5", 80, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" && broken.Load() {
			w.Header().Set("Content-Length", "100")
			_, _ = w.Write([]byte("SECRET_KEY=")) // the connection drops before the declared length
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler)
		}
		leaky(w, r)
	})
	file := x.pathsFile(pathsYAML)
	x.mustRun("--crawl-pages", "0", "--sensitive-paths", file)
	if st := x.state("sensitive-paths"); st.str("state") != "done" || st.num("failed") != 1 {
		t.Errorf("state = %v", st)
	}
	if got := col(current(x.rows("risk-sensitive-paths.csv")), "path"); !slices.Equal(got, []string{"/.git/config", "/backup.gz"}) {
		t.Errorf("flagged = %v", got)
	}
	broken.Store(false)
	x.mustRun("--crawl-pages", "0", "--sensitive-paths", file)
	if s.count("/.env") != 2 || s.count("/.git/config") != 1 || s.count("/backup.gz") != 1 {
		t.Errorf("counts after the retry: .env %d, .git/config %d, backup.gz %d", s.count("/.env"), s.count("/.git/config"), s.count("/backup.gz"))
	}
	if got := col(current(x.rows("risk-sensitive-paths.csv")), "path"); len(got) != 3 {
		t.Errorf("flagged = %v", got)
	}
}

// B5: company hosts behind CDNs, on PaaS and by IP literal are requested; hosts
// served by third-party SaaS (by CNAME, and an apex by address range) are not.
func TestRiskB5_WhichServicesAreRequested(t *testing.T) {
	x := newRisk(t, "sensitive-paths")
	x.names("cdn.example.com", "app.example.com", "help.example.com", "pages.example.com", "plain.example.com")
	x.dns.CNAME("cdn.example.com", "d1.cloudfront.net")
	x.host("d1.cloudfront.net", "203.0.113.11")
	x.dns.CNAME("app.example.com", "acme.herokuapp.com")
	x.host("acme.herokuapp.com", "203.0.113.12")
	x.dns.CNAME("help.example.com", "acme.zendesk.com")
	x.host("acme.zendesk.com", "203.0.113.13")
	x.host("pages.example.com", "185.199.108.153") // GitHub Pages by address, no CNAME
	x.host("plain.example.com", "203.0.113.15")
	sites := map[string]*site{}
	for name, ip := range map[string]string{"cdn": "203.0.113.11", "app": "203.0.113.12", "help": "203.0.113.13", "pages": "185.199.108.153", "plain": "203.0.113.15"} {
		sites[name] = x.plain(ip, 80, leaky)
	}
	ipSite := x.plain("198.51.100.7", 8080, leaky)
	x.open("198.51.100.7:8080", "")
	x.mustRun("--crawl-pages", "0", "--cidr", "198.51.100.0/24", "--sensitive-paths", x.pathsFile(pathsYAML))

	for _, name := range []string{"cdn", "app", "plain"} {
		if sites[name].count("/.env") != 1 {
			t.Errorf("%s: /.env requested %d times, want 1", name, sites[name].count("/.env"))
		}
	}
	for _, name := range []string{"help", "pages"} {
		if sites[name].count("/.env") != 0 {
			t.Errorf("%s is served by a SaaS platform and must not be requested", name)
		}
	}
	if ipSite.count("/.env") != 1 {
		t.Errorf("an IP-literal service was requested %d times", ipSite.count("/.env"))
	}
	hosts := col(current(x.rows("risk-sensitive-paths.csv")), "url")
	for _, h := range hosts {
		if strings.Contains(h, "help.example.com") || strings.Contains(h, "pages.example.com") {
			t.Errorf("finding on a SaaS host: %s", h)
		}
	}
}

// B5: invalid sensitive-path entries exit 2.
func TestRiskB5_InvalidEntriesExit2(t *testing.T) {
	x := newRisk(t, "sensitive-paths")
	for name, body := range map[string]string{
		"plain string": "- /admin\n", "no signature": "- path: /admin\n", "bad regex": "- path: /a\n  signature: '(['\n",
	} {
		if code := x.run("--sensitive-paths", x.pathsFile(body)); code != 2 {
			t.Errorf("%s: exit %d, want 2", name, code)
		}
		if !strings.Contains(x.h.stdout.String(), "sensitive_paths") {
			t.Errorf("%s: the error does not name sensitive_paths:\n%s", name, x.h.stdout.String())
		}
	}
}

// B5: a hit is a finding only while its service is current and visible.
func TestRiskB5_HitNeedsCurrentService(t *testing.T) {
	x := newRisk(t, "sensitive-paths")
	x.names("www.example.com")
	x.host("www.example.com", "203.0.113.5")
	x.plain("203.0.113.5", 80, leaky)
	file := x.pathsFile(pathsYAML)
	x.mustRun("--crawl-pages", "0", "--sensitive-paths", file)
	if len(current(x.rows("risk-sensitive-paths.csv"))) != 3 {
		t.Fatalf("setup: %s", x.file(eng, "risk-sensitive-paths.csv"))
	}
	x.mustRun("--crawl-pages", "0", "--sensitive-paths", file, "-x", "www.example.com")
	rows := x.rows("risk-sensitive-paths.csv")
	if len(rows) != 3 || len(current(rows)) != 0 {
		t.Errorf("after the exclusion: %s", x.file(eng, "risk-sensitive-paths.csv"))
	}
	if got := x.summaryTargets(); len(got) != 0 {
		t.Errorf("summary = %v", got)
	}
}

// D11: editing an entry's signature retires the old check, so its hit stops
// being current instead of staying a finding at its old evidence; the other
// entries are not requested again.
func TestRiskB5_EditedEntrySupersedesOldHit(t *testing.T) {
	x := newRisk(t, "sensitive-paths")
	x.names("www.example.com")
	x.host("www.example.com", "203.0.113.5")
	s := x.plain("203.0.113.5", 80, leaky)
	x.mustRun("--crawl-pages", "0", "--sensitive-paths", x.pathsFile(pathsYAML))
	if got := col(current(x.rows("risk-sensitive-paths.csv")), "path"); len(got) != 3 {
		t.Fatalf("flagged = %v", got)
	}
	edited := strings.Replace(pathsYAML, `'\[core\]'`, `'\[nothing-matches\]'`, 1)
	x.mustRun("--crawl-pages", "0", "--sensitive-paths", x.pathsFile(edited))
	if s.count("/.git/config") != 2 || s.count("/.env") != 1 || s.count("/backup.gz") != 1 {
		t.Errorf("requests: .git/config %d, .env %d, backup.gz %d", s.count("/.git/config"), s.count("/.env"), s.count("/backup.gz"))
	}
	if got := col(current(x.rows("risk-sensitive-paths.csv")), "path"); !slices.Equal(got, []string{"/.env", "/backup.gz"}) {
		t.Errorf("flagged after the edit = %v\n%s", got, x.file(eng, "risk-sensitive-paths.csv"))
	}
	if got := x.summaryTargets(); slices.Contains(got, "http://www.example.com/.git/config=high") {
		t.Errorf("the superseded hit is still in the summary: %v", got)
	}
	// Restoring the entry asks again, since the old check was forgotten.
	x.mustRun("--crawl-pages", "0", "--sensitive-paths", x.pathsFile(pathsYAML))
	if s.count("/.git/config") != 3 {
		t.Errorf("restored entry: .git/config requested %d times", s.count("/.git/config"))
	}
	if got := col(current(x.rows("risk-sensitive-paths.csv")), "path"); len(got) != 3 {
		t.Errorf("flagged after restoring = %v", got)
	}
}

// D11: a body larger than the 1 MiB read cap reports its Content-Length, or
// "1048576+" when the response does not declare one.
func TestRiskB5_LargeBodySize(t *testing.T) {
	x := newRisk(t, "sensitive-paths")
	x.names("www.example.com")
	x.host("www.example.com", "203.0.113.5")
	big := append([]byte{0x1f, 0x8b, 0x08}, make([]byte, 3<<20)...)
	x.plain("203.0.113.5", 80, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/backup.gz":
			w.Header().Set("Content-Length", strconv.Itoa(len(big)))
			_, _ = w.Write(big)
		case "/.git/config":
			_, _ = w.Write([]byte("[core]\n"))
			w.(http.Flusher).Flush() // chunked: no Content-Length
			_, _ = w.Write(make([]byte, 2<<20))
		default:
			leaky(w, r)
		}
	})
	x.mustRun("--crawl-pages", "0", "--sensitive-paths", x.pathsFile(pathsYAML))
	rows := current(x.rows("risk-sensitive-paths.csv"))
	if r := find(rows, "path", "/backup.gz"); r == nil || r["size"] != strconv.Itoa(len(big)) {
		t.Errorf("backup.gz = %v", r)
	}
	if r := find(rows, "path", "/.git/config"); r == nil || r["size"] != "1048576+" {
		t.Errorf(".git/config = %v", r)
	}
}
