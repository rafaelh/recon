package cli_test

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
)

func TestWebPlumbing_FilesAreSortedSafeDatedAndCounted(t *testing.T) {
	x := newWeb(t)
	x.names("b.example.com", "a.example.com")
	x.host("a.example.com", "203.0.113.5")
	x.host("b.example.com", "203.0.113.6")
	x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<title>=HYPERLINK("http://evil/","x")</title><a href="/z">z</a><a href="/a">a</a>`)
		},
		"/z": page("z"), "/a": page("a"),
	}))
	x.plain("203.0.113.6", 80, page("<title>plain</title>"))
	x.mustRun()

	if hdr := strings.SplitN(x.file(eng, "web-services.csv"), "\n", 2)[0]; hdr !=
		"url,host,port,scheme,status,title,server,technologies,redirect,final_url,tls_subject,tls_sans,tls_issuer,tls_expiry,tls_error,tls_self_signed,hsts,insecure_cookies,directory_listing,version_disclosure,current,first_seen,last_seen" {
		t.Errorf("web-services.csv header = %q", hdr)
	}
	if hdr := strings.SplitN(x.file(eng, "urls.csv"), "\n", 2)[0]; hdr != "url,host,status,found_by,current,first_seen,last_seen" {
		t.Errorf("urls.csv header = %q", hdr)
	}
	for _, f := range []string{"web-services.csv", "urls.csv"} {
		var urls []string
		for _, r := range x.table(eng, f) {
			urls = append(urls, r["url"])
			if r["first_seen"] != "2026-11-01" || r["last_seen"] != "2026-11-01" || r["current"] != "true" {
				t.Errorf("%s dates: %v", f, r)
			}
		}
		if len(urls) == 0 || !sort.StringsAreSorted(urls) {
			t.Errorf("%s must be non-empty and sorted: %v", f, urls)
		}
	}
	if raw := x.file(eng, "web-services.csv"); strings.Contains(raw, ",=HYPERLINK") || !strings.Contains(raw, `'=HYPERLINK`) {
		t.Errorf("a title starting with = must be neutralised:\n%s", raw)
	}

	// web_service is printed, url is only counted, http_port is neither.
	evs := x.h.events()
	var printed []string
	for _, e := range ofType(evs, "found") {
		switch c := e.str("category"); {
		case c == "web service":
			printed = append(printed, e.str("value"))
		case c == "url" || strings.Contains(c, "http"):
			t.Errorf("unexpected found line: %v", e)
		}
	}
	sort.Strings(printed)
	if strings.Join(printed, ",") != "http://a.example.com,http://b.example.com" {
		t.Errorf("printed web services = %v", printed)
	}
	for _, cat := range []string{"web services", "urls"} {
		file := map[string]string{"web services": "web-services.csv", "urls": "urls.csv"}[cat]
		rows := 0
		for _, r := range x.table(eng, file) {
			if r["current"] == "true" {
				rows++
			}
		}
		if got := x.summaryTotal(cat); got != rows || rows == 0 {
			t.Errorf("summary %s = %d, %s has %d current rows", cat, got, file, rows)
		}
	}
	sums := ofType(evs, "summary")
	for k := range sums[len(sums)-1]["totals"].(map[string]any) {
		if strings.Contains(k, "http") {
			t.Errorf("summary counts the internal kind: %q", k)
		}
	}

	// An idle re-run changes nothing.
	before := map[string]string{}
	for _, f := range []string{"web-services.csv", "urls.csv", "subdomains.txt"} {
		before[f] = x.file(eng, f)
	}
	x.mustRun()
	for f, b := range before {
		if after := x.file(eng, f); after != b {
			t.Errorf("%s changed on an idle re-run", f)
		}
	}
}
