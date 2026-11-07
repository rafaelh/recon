// Package web has the stages that find web services and the URLs behind them:
// httpprobe (what answers HTTP or HTTPS) and crawl (a light same-host crawl).
// It never touches the network itself; every request goes through egress.
package web

import (
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/input"
)

// NormaliseURL returns the canonical form of an absolute http or https URL
// (Spec 3 D15): lower-case scheme and host, an IP literal in its canonical
// form (IPv6 bracketed), a decimal port with the default omitted, no fragment,
// no userinfo, the query kept, and "/" for an empty path. ok is false for
// anything else.
func NormaliseURL(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if (scheme != "http" && scheme != "https") || host == "" {
		return "", false
	}
	if a, ok := input.IPLiteral(host); ok {
		host = a.String()
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", false
		}
		port = strconv.Itoa(n)
	}
	out := url.URL{Scheme: scheme, Host: egress.HostPort(scheme, host, port), Path: u.Path, RawPath: u.RawPath, RawQuery: u.RawQuery}
	if out.Path == "" {
		out.Path = "/"
	}
	if u.ForceQuery && out.RawQuery == "" {
		out.ForceQuery = true
	}
	return out.String(), true
}

// Origin is the key of a web service: scheme://host[:port] with the default
// port omitted ("https://a.example.com", "http://[2001:db8::1]:8080").
func Origin(scheme, host string, port int) string {
	return scheme + "://" + egress.HostPort(scheme, host, strconv.Itoa(port))
}

// HostOfURL is the lower-case host (no brackets, no port) of a URL.
func HostOfURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

var staticExt = map[string]bool{}

func init() {
	for _, e := range strings.Fields(`
		png jpg jpeg gif svg ico webp bmp tif tiff avif apng heic
		css
		woff woff2 ttf otf eot
		mp3 mp4 m4a m4v webm ogg ogv oga wav avi mov mkv flac aac wmv mpg mpeg
		pdf
		zip gz tgz tar bz2 xz 7z rar iso dmg exe msi apk`) {
		staticExt[e] = true
	}
}

// IsStaticAsset reports whether a URL path ends in an image, stylesheet, font,
// media, PDF or archive extension. The crawl records such links but never
// fetches them, and archived URLs of this kind are dropped.
func IsStaticAsset(p string) bool {
	ext := strings.ToLower(strings.TrimPrefix(path.Ext(p), "."))
	return ext != "" && staticExt[ext]
}
