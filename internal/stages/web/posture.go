package web

import (
	"maps"
	"slices"
	"strings"

	"golang.org/x/net/html"

	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/sanitize"
)

// hop is one response of a probe's redirect chain, reduced to what posture
// reads. Its page is parsed at most once, however many readers ask: the probe
// takes the title from the same parse the directory-listing check uses.
type hop struct {
	https  bool
	origin string              // scheme://host[:port], in Origin's form
	header map[string][]string // canonical keys, as a real response has them
	body   []byte
	isHTML bool

	pg     page
	pgOK   bool
	parsed bool
}

func newHop(r egress.Response) *hop {
	return hopAt(r.URL(), r.ContentType(), r.Header, r.Body)
}

// hopAt is a hop for a response to the request for url, with the given media type.
func hopAt(url, contentType string, header map[string][]string, body []byte) *hop {
	return &hop{https: strings.HasPrefix(url, "https://"), origin: originOf(url), header: header, body: body, isHTML: contentType == "text/html"}
}

// page is the parsed body of an HTML response.
func (h *hop) page() (page, bool) {
	if !h.isHTML {
		return page{}, false
	}
	if !h.parsed {
		h.pg, h.pgOK = parsePage(h.body)
		h.parsed = true
	}
	return h.pg, h.pgOK
}

// posture reads the web-configuration evidence out of the responses a probe
// received, in order: chain[0] is the service's first response and the rest are
// the redirects it followed. It reads only what those responses already carry.
//
//   - HSTS and version banners come from the first response. HSTS is judged only
//     for a service answering over HTTPS.
//   - Cookies come from every response in the chain. A cookie lacks HttpOnly
//     whatever the scheme, and lacks Secure only if its response arrived over
//     HTTPS. Only names are kept, never values.
//   - A directory listing is read from the last page of the chain that the
//     service's own origin served, not one a redirect led to elsewhere.
func posture(host string, chain []*hop) kinds.WebPostureAttrs {
	first := chain[0]
	a := kinds.WebPostureAttrs{Host: host}
	if first.https {
		has := strings.TrimSpace(strings.Join(first.header["Strict-Transport-Security"], "")) != ""
		a.HSTS = &has
	}
	noSecure, noHTTPOnly := map[string]bool{}, map[string]bool{}
	for _, h := range chain {
		for _, line := range h.header["Set-Cookie"] {
			name, secure, httpOnly, ok := parseSetCookie(line)
			if !ok {
				continue
			}
			if !secure && h.https {
				noSecure[name] = true
			}
			if !httpOnly {
				noHTTPOnly[name] = true
			}
		}
	}
	a.CookiesNoSecure = strings.Join(slices.Sorted(maps.Keys(noSecure)), ";")
	a.CookiesNoHTTPOnly = strings.Join(slices.Sorted(maps.Keys(noHTTPOnly)), ";")
	a.DirectoryListing = lastSameOrigin(chain).isDirectoryListing()
	a.VersionDisclosure = versionHeaders(first)
	return a
}

// parseSetCookie reads a Set-Cookie line: the cookie's sanitised name (never
// its value) and whether its attributes include Secure and HttpOnly. A line
// with no name=value pair is not a cookie.
func parseSetCookie(line string) (name string, secure, httpOnly, ok bool) {
	pair, attrs, _ := strings.Cut(line, ";")
	name, _, hasValue := strings.Cut(pair, "=")
	name = strings.TrimSpace(sanitize.Text(name))
	if !hasValue || name == "" {
		return "", false, false, false
	}
	for attr := range strings.SplitSeq(attrs, ";") {
		key, _, _ := strings.Cut(attr, "=")
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "secure":
			secure = true
		case "httponly":
			httpOnly = true
		}
	}
	return name, secure, httpOnly, true
}

// lastSameOrigin is the last response of the chain served by the origin the
// chain began at.
func lastSameOrigin(chain []*hop) *hop {
	for i := len(chain) - 1; i > 0; i-- {
		if chain[i].origin == chain[0].origin {
			return chain[i]
		}
	}
	return chain[0]
}

const listingPrefix = "Index of /"

// isDirectoryListing reports whether the response is an HTML page whose title,
// or first heading, begins "Index of /", as the automatic listing of a web server does.
func (h *hop) isDirectoryListing() bool {
	pg, ok := h.page()
	if !ok {
		return false
	}
	isHeading := func(n *html.Node) bool {
		return len(n.Data) == 2 && n.Data[0] == 'h' && n.Data[1] >= '1' && n.Data[1] <= '6'
	}
	return strings.HasPrefix(pg.title(), listingPrefix) || strings.HasPrefix(pg.firstText(isHeading), listingPrefix)
}

// versionHeaders are the Server and X-Powered-By values of the response that
// carry a version, ";"-joined: a "/" followed by a digit ("Apache/2.4.41";
// "nginx" and "ASP.NET" carry none).
func versionHeaders(h *hop) string {
	var out []string
	for _, name := range []string{"Server", "X-Powered-By"} {
		for _, v := range h.header[name] {
			if v = strings.TrimSpace(sanitize.Text(v)); hasVersion(v) && !slices.Contains(out, v) {
				out = append(out, v)
			}
		}
	}
	return strings.Join(out, ";")
}

func hasVersion(v string) bool {
	for i := 0; i+1 < len(v); i++ {
		if v[i] == '/' && v[i+1] >= '0' && v[i+1] <= '9' {
			return true
		}
	}
	return false
}
