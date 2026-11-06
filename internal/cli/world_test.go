package cli_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/rafaelh/recon/internal/cli"
	"github.com/rafaelh/recon/internal/dnsname"
	"github.com/rafaelh/recon/internal/egress/egresstest"
	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/testkit"
)

// Every third-party host pattern the Spec 2 stages declare.
var sourcePatterns = []string{
	"crt.sh", "web.archive.org", "index.commoncrawl.org", "www.virustotal.com", "api.securitytrails.com",
	"api.shodan.io", "reverse-whois.whoisxmlapi.com", "stat.ripe.net", "ip-ranges.amazonaws.com", "www.gstatic.com",
	// Spec 5's storage stage; their default answer is "no such bucket".
	"s3.amazonaws.com", "s3.*.amazonaws.com", "storage.googleapis.com", "*.blob.core.windows.net",
}

// riskStages are Spec 5's stages. Worlds leave them out unless a test asks for
// them: sensitive-paths alone sends a score of requests to every web service.
var riskStages = []string{"email", "storage", "takeover", "sensitive-paths"}

const noSuchBucketXML = `<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>`
const containerNotFoundXML = `<?xml version="1.0" encoding="utf-8"?><Error><Code>ContainerNotFound</Code><Message>The specified container does not exist.</Message></Error>`

func missingStorage(pattern string) http.HandlerFunc {
	body := noSuchBucketXML
	if strings.Contains(pattern, "blob.core.windows.net") {
		body = containerNotFoundXML
	}
	return func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/xml")
		rw.WriteHeader(404)
		if r.Method != http.MethodHead {
			rw.Write([]byte(body))
		}
	}
}

type loggedReq struct {
	Method, URI, Body string
	Header            http.Header
}

type source struct {
	mu   sync.Mutex
	h    http.HandlerFunc
	reqs []loggedReq
}

// world is a fake internet: a DNS server and one HTTP server per third-party source.
type world struct {
	t   *testing.T
	h   *harness
	dns *egresstest.DNS
	src map[string]*source

	probeMu    sync.Mutex
	probeNames []string
	provHosts  []string
	probe      *testkit.Stage
}

func newWorld(t *testing.T) *world { return newWorldWith(t) }

// newWorldWith is newWorld with the named Spec 5 stages kept in the stage list.
func newWorldWith(t *testing.T, keep ...string) *world {
	t.Helper()
	w := &world{t: t, src: map[string]*source{}}
	w.probe = &testkit.Stage{StageName: "probe", Kind: run.ThirdParty, ChecksFn: func(v run.View) []run.Check {
		w.probeMu.Lock()
		defer w.probeMu.Unlock()
		w.probeNames = v.ProbeHostnames()
		w.provHosts = nil
		for _, p := range v.ProviderHosts() {
			w.provHosts = append(w.provHosts, p.Hostname+"|"+p.Provider)
		}
		return nil
	}}
	// The real ports stage sweeps every eligible address on every listed port, and
	// only the Spec 4 tests map those connects to local listeners; the others
	// leave it out so nothing they run can reach the network.
	stages := slices.DeleteFunc(cli.DefaultDeps().Stages, func(s run.Stage) bool {
		return s.Name() == "ports" || slices.Contains(riskStages, s.Name()) && !slices.Contains(keep, s.Name())
	})
	w.h = newHarness(t, append(stages, w.probe)...)
	w.dns = egresstest.NewDNS(t)
	// The input root is resolved too, like any in-scope name; give it an address.
	w.dns.A("example.com", "203.0.113.250")
	w.owner("203.0.113.250", 64500, "ACME-NET")
	w.h.eopts.ResolverAddrs = []string{w.dns.Addr}
	w.h.eopts.SourceBaseURLs = map[string]string{}
	for _, p := range sourcePatterns {
		s := &source{h: func(rw http.ResponseWriter, r *http.Request) { http.NotFound(rw, r) }}
		if strings.Contains(p, "amazonaws.com") && !strings.HasPrefix(p, "ip-ranges") || strings.Contains(p, "googleapis.com") || strings.Contains(p, "blob.core.windows.net") {
			s.h = missingStorage(p)
		}
		srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			s.mu.Lock()
			s.reqs = append(s.reqs, loggedReq{Method: r.Method, URI: r.URL.RequestURI(), Body: string(body), Header: r.Header.Clone()})
			h := s.h
			s.mu.Unlock()
			r.Body = io.NopCloser(strings.NewReader(string(body)))
			h(rw, r)
		}))
		t.Cleanup(srv.Close)
		w.src[p] = s
		w.h.eopts.SourceBaseURLs[p] = srv.URL
	}
	return w
}

// serve starts a fake HTTP server for an exact source host (a storage region or
// an Azure account) and returns its request log.
func (w *world) serve(host string, h http.HandlerFunc) *source {
	s := &source{h: h}
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.reqs = append(s.reqs, loggedReq{Method: r.Method, URI: r.URL.RequestURI(), Header: r.Header.Clone()})
		h := s.h
		s.mu.Unlock()
		h(rw, r)
	}))
	w.t.Cleanup(srv.Close)
	w.src[host] = s
	w.h.eopts.SourceBaseURLs[host] = srv.URL
	return s
}

func (s *source) requestLog() []loggedReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]loggedReq(nil), s.reqs...)
}

// count is the number of requests with the method and request path (no query).
func (s *source) count(method, path string) int {
	n := 0
	for _, r := range s.requestLog() {
		if r.Method == method && strings.SplitN(r.URI, "?", 2)[0] == path {
			n++
		}
	}
	return n
}

// handle sets the handler of a source.
func (w *world) handle(pattern string, h http.HandlerFunc) {
	s := w.src[pattern]
	s.mu.Lock()
	s.h = h
	s.mu.Unlock()
}

// requests returns the requests a source received.
func (w *world) requests(pattern string) []loggedReq {
	s := w.src[pattern]
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]loggedReq(nil), s.reqs...)
}

// run executes recon in JSON mode with rates high enough for tests.
func (w *world) run(args ...string) int {
	w.t.Helper()
	full := append([]string{"--json", "--rate-per-source", "1000", "--rate-dns", "100000"}, args...)
	return w.h.exec(full...)
}

func (w *world) probed() []string {
	w.probeMu.Lock()
	defer w.probeMu.Unlock()
	return append([]string(nil), w.probeNames...)
}

func (w *world) providerHosts() []string {
	w.probeMu.Lock()
	defer w.probeMu.Unlock()
	return append([]string(nil), w.provHosts...)
}

// owner scripts Team Cymru's answers for an address.
func (w *world) owner(addr string, asn int, holder string) {
	w.dns.TXT(dnsname.CymruOrigin(mustAddr(addr)), fmt.Sprintf("%d | 203.0.0.0/8 | US | arin | 2000-01-01", asn))
	w.dns.TXT(fmt.Sprintf("as%d.asn.cymru.com", asn), fmt.Sprintf("%d | US | arin | 2000-01-01 | %s, US", asn, holder))
}

func jsonBody(s string) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) { rw.Write([]byte(s)) }
}

func status(code int) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) { http.Error(rw, "no", code) }
}

// crtsh serves certificate-transparency name lists by root and by organisation.
func (w *world) crtsh(byRoot, byOrg map[string][]string) {
	w.handle("crt.sh", func(rw http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		var names []string
		if org := q.Get("O"); org != "" {
			names = byOrg[org]
		} else {
			names = byRoot[strings.TrimPrefix(q.Get("q"), "%.")]
		}
		type row struct {
			CommonName string `json:"common_name"`
			NameValue  string `json:"name_value"`
		}
		var rows []row
		for _, n := range names {
			if org := q.Get("O"); org != "" {
				// Live crt.sh answers an O= search with the organisation in name_value and the names in common_name.
				rows = append(rows, row{CommonName: n, NameValue: org})
			} else {
				rows = append(rows, row{NameValue: n})
			}
		}
		json.NewEncoder(rw).Encode(rows)
	})
}

// waybackURLs serves Wayback CDX results, two URLs per page.
func (w *world) waybackURLs(urls ...string) {
	w.handle("web.archive.org", func(rw http.ResponseWriter, r *http.Request) {
		pages := (len(urls) + 1) / 2
		q := r.URL.Query()
		if q.Get("showNumPages") == "true" {
			fmt.Fprintf(rw, "%d\n", pages)
			return
		}
		var p int
		fmt.Sscan(q.Get("page"), &p)
		out := [][]string{{"original"}}
		for i := p * 2; i < len(urls) && i < p*2+2; i++ {
			out = append(out, []string{urls[i]})
		}
		json.NewEncoder(rw).Encode(out)
	})
}

// commonCrawl serves one index (id) with the given URLs on a single page.
func (w *world) commonCrawl(id string, urls ...string) {
	w.handle("index.commoncrawl.org", func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "collinfo.json"):
			fmt.Fprintf(rw, `[{"id":%q,"cdx-api":"https://index.commoncrawl.org/%s-index"}]`, id, id)
		case r.URL.Query().Get("showNumPages") == "true":
			rw.Write([]byte(`{"pages":1,"pageSize":5,"blocks":1}`))
		default:
			for _, u := range urls {
				fmt.Fprintf(rw, "{\"url\":%q}\n", u)
			}
		}
	})
}

// --- reading results ---

func (w *world) file(eng, name string) string { return w.h.readOut(eng, name) }

func (w *world) lines(eng, name string) []string {
	s := strings.TrimSpace(w.file(eng, name))
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// table parses a CSV file into rows keyed by column name.
func (w *world) table(eng, name string) []map[string]string {
	w.t.Helper()
	recs := csvRows(w.t, w.file(eng, name))
	if len(recs) == 0 {
		return nil
	}
	var out []map[string]string
	for _, r := range recs[1:] {
		m := map[string]string{}
		for i, c := range recs[0] {
			m[c] = r[i]
		}
		out = append(out, m)
	}
	return out
}

func find(rows []map[string]string, col, val string) map[string]string {
	for _, r := range rows {
		if r[col] == val {
			return r
		}
	}
	return nil
}

// obsAttrs returns key -> attrs JSON for the observations of a kind.
func (w *world) obsAttrs(eng, kind string) map[string]string {
	w.t.Helper()
	db := w.h.openDB(eng)
	rows, err := db.Query("SELECT key, attrs FROM observations WHERE kind=?", kind)
	if err != nil {
		w.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, a string
		rows.Scan(&k, &a)
		out[k] = a
	}
	return out
}

// anywhere reports every file under the engagement and the captured output that contains s.
func (w *world) anywhere(eng, s string) []string {
	var hits []string
	filepath.WalkDir(w.h.eng(eng), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if b, _ := os.ReadFile(p); strings.Contains(string(b), s) {
				hits = append(hits, p)
			}
		}
		return nil
	})
	if strings.Contains(w.h.stdout.String(), s) {
		hits = append(hits, "stdout")
	}
	if strings.Contains(w.h.stderr.String(), s) {
		hits = append(hits, "stderr")
	}
	return hits
}
