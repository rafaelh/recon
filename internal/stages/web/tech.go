package web

import (
	"maps"
	"slices"
	"strings"
	"sync"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// fingerprints loads wappalyzergo's fingerprints once per process. httpprobe
// warns while they fail to load, and technologies is then empty.
var fingerprints = sync.OnceValues(wappalyzer.New)

// technologies identifies technologies from a response's headers (Set-Cookie
// carries cookies, X-Powered-By is a header) and body, as sorted names joined
// with ";". A name carries its version when one is detected ("Nginx:1.25.3").
func technologies(header map[string][]string, body []byte) string {
	w, err := fingerprints()
	if err != nil {
		return ""
	}
	return strings.Join(slices.Sorted(maps.Keys(w.Fingerprint(header, body))), ";")
}
