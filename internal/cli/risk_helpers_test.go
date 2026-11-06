package cli_test

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
)

// risk is a web world with some of Spec 5's stages in the stage list.
type risk struct{ *web }

func newRisk(t *testing.T, stages ...string) *risk {
	t.Helper()
	return &risk{newWebWith(t, stages...)}
}

// rows is a risk-*.csv or other CSV of the engagement, by column name.
func (x *risk) rows(file string) []map[string]string { return x.table(eng, file) }

// current keeps the rows that are current.
func current(rows []map[string]string) []map[string]string {
	var out []map[string]string
	for _, r := range rows {
		if r["current"] == "true" {
			out = append(out, r)
		}
	}
	return out
}

// col is the sorted values of a column.
func col(rows []map[string]string, name string) []string {
	var out []string
	for _, r := range rows {
		out = append(out, r[name])
	}
	sort.Strings(out)
	return out
}

// summaryFindings are the findings of the run's summary event.
func (x *risk) summaryFindings() []map[string]any {
	x.t.Helper()
	sums := ofType(x.h.events(), "summary")
	if len(sums) != 1 {
		x.t.Fatalf("want one summary event, got %d\n%s", len(sums), x.h.stdout.String())
	}
	var out []map[string]any
	list, _ := sums[0]["findings"].([]any)
	for _, f := range list {
		out = append(out, f.(map[string]any))
	}
	return out
}

func (x *risk) summaryTargets() []string {
	var out []string
	for _, f := range x.summaryFindings() {
		out = append(out, fmt.Sprintf("%v=%v", f["target"], f["severity"]))
	}
	sort.Strings(out)
	return out
}

func (x *risk) state(stage string) event { return lastState(x.h.events(), stage) }

// --- fake storage services ---

// bucket scripts a bucket or container: what an anonymous listing does, and
// what a HEAD of each object does.
type bucket struct {
	list      int      // listing status: 200 lists keys, 403 is private, 0 or 404 does not exist
	keys      []string // returned when list is 200
	truncated bool     // the listing says there are more
	objs      map[string]int
	redirect  string // answer the listing with a 301 naming this region
}

func xmlList(keys []string, truncated bool) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>b</Name>`)
	fmt.Fprintf(&b, "<KeyCount>%d</KeyCount><IsTruncated>%v</IsTruncated>", len(keys), truncated)
	for _, k := range keys {
		fmt.Fprintf(&b, "<Contents><Key>%s</Key><Size>1</Size></Contents>", k)
	}
	b.WriteString("</ListBucketResult>")
	return b.String()
}

func azureList(keys []string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?><EnumerationResults><Blobs>`)
	for _, k := range keys {
		fmt.Fprintf(&b, "<Blob><Name>%s</Name></Blob>", k)
	}
	b.WriteString("</Blobs><NextMarker /></EnumerationResults>")
	return b.String()
}

func numberedKeys(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("k%04d", i)
	}
	return out
}

// bucketHandler serves S3- and GCS-style path-style requests for the buckets.
func bucketHandler(bs map[string]bucket) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
		b, ok := bs[parts[0]]
		if !ok || (b.list == 0 && len(parts) == 1) {
			missingStorage("amazonaws.com")(w, r)
			return
		}
		if len(parts) == 2 && parts[1] != "" {
			code := b.objs[parts[1]]
			if code == 0 {
				code = 403
			}
			w.WriteHeader(code)
			return
		}
		if b.redirect != "" {
			w.Header().Set("x-amz-bucket-region", b.redirect)
			w.WriteHeader(301)
			w.Write([]byte(`<Error><Code>PermanentRedirect</Code></Error>`))
			return
		}
		switch b.list {
		case 200:
			w.Header().Set("Content-Type", "application/xml")
			w.Write([]byte(xmlList(b.keys, b.truncated)))
		default:
			w.WriteHeader(b.list)
			w.Write([]byte(`<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`))
		}
	}
}

// containerHandler serves Azure container requests: /<container>?restype=container&comp=list
// and HEAD /<container>/<blob>.
func containerHandler(cs map[string]bucket) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
		c, ok := cs[parts[0]]
		if !ok || (c.list == 0 && len(parts) == 1) {
			missingStorage("blob.core.windows.net")(w, r)
			return
		}
		if len(parts) == 2 && parts[1] != "" {
			code := c.objs[parts[1]]
			if code == 0 {
				code = 404
			}
			w.WriteHeader(code)
			return
		}
		if c.list == 200 {
			w.Header().Set("Content-Type", "application/xml")
			w.Write([]byte(azureList(c.keys)))
			return
		}
		w.WriteHeader(c.list)
		w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?><Error><Code>PublicAccessNotPermitted</Code></Error>`))
	}
}

// listRequests are the listing GETs a fake received (any request with a query).
func listRequests(s *source) []string {
	var out []string
	for _, r := range s.requestLog() {
		if r.Method == http.MethodGet {
			out = append(out, r.URI)
		}
	}
	return out
}

func heads(s *source) []string {
	var out []string
	for _, r := range s.requestLog() {
		if r.Method == http.MethodHead {
			out = append(out, r.URI)
		}
	}
	sort.Strings(out)
	return out
}
