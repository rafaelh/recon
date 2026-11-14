package findings

import (
	"fmt"
	"strings"

	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/kinds"
)

// webPosture derives the low web-posture findings from the web_posture
// evidence: one per service and condition. Services addressed by an IP literal
// and services a SaaS platform serves have none: the first is not the target's
// name to fix, and the second is not the target's configuration. A missing
// HttpOnly flag is evidence only, and HTTP services have no HSTS or Secure
// findings.
func (d *deriver) webPosture() []Finding {
	var out []Finding
	for _, r := range d.current(kinds.WebPosture) {
		if !d.vis.Shown(kinds.WebPosture, r) {
			continue
		}
		a := kinds.WebPosture.Attrs(r)
		if _, isIP := input.IPLiteral(a.Host); isIP || d.in.Inv.SaaSServed(a.Host) {
			continue
		}
		url := r.Key
		add := func(typ, detail string) {
			out = append(out, newFinding(WebPosture, typ, Severity(WebPosture, typ), url, detail, map[string]any{"url": url}))
		}
		https := strings.HasPrefix(url, "https://")
		if a.HSTS != nil && !*a.HSTS { // unset for an HTTP service
			add("missing-hsts", url+" does not send Strict-Transport-Security")
		}
		if https && a.CookiesNoSecure != "" {
			add("insecure-cookie", "cookies set over HTTPS without Secure: "+a.CookiesNoSecure)
		}
		if a.DirectoryListing {
			add("directory-listing", url+" serves a directory listing")
		}
		if a.VersionDisclosure != "" {
			add("version-disclosure", fmt.Sprintf("%s discloses a version: %s", url, a.VersionDisclosure))
		}
	}
	return out
}
