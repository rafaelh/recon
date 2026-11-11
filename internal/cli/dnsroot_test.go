package cli_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/testkit"
)

// runRoot runs a passive engagement for example.com.
func runRoot(t *testing.T, w *world, extra ...string) {
	t.Helper()
	args := append([]string{"--passive"}, extra...)
	if !slices.Contains(extra, "-e") { // a run of an existing engagement takes no inputs
		args = append(args, "example.com")
	}
	if code := w.run(args...); code != 0 {
		t.Fatalf("exit %d\n%s", code, w.h.stdout.String())
	}
}

func resolutionRow(w *world, name, typ string) map[string]string {
	for _, r := range w.table(eng, "resolutions.csv") {
		if r["name"] == name && r["type"] == typ {
			return r
		}
	}
	return nil
}

// NS, SOA, TXT and CAA answers are resolutions.csv rows in the stated formats.
func TestDNSRoot_RecordFormats(t *testing.T) {
	w := newWorld(t)
	w.dns.NS("example.com", "ns1.dns-host.test")
	w.dns.SOA("example.com", "ns1.dns-host.test", `john\.doe.example.com`)
	w.dns.TXT("example.com", "some=text")
	w.dns.CAA("example.com", 0, "issue", "letsencrypt.org")
	w.dns.CAA("example.com", 128, "iodef", "mailto:security@example.com")
	runRoot(t, w)

	rows := w.table(eng, "resolutions.csv")
	got := map[string]bool{}
	for _, r := range rows {
		if r["name"] == "example.com" && r["source"] == "resolve" {
			got[r["type"]+"|"+r["value"]] = true
		}
	}
	for _, want := range []string{
		"NS|ns1.dns-host.test",
		"SOA|ns1.dns-host.test john.doe@example.com",
		"TXT|some=text",
		`CAA|0 issue "letsencrypt.org"`,
		`CAA|128 iodef "mailto:security@example.com"`,
	} {
		if !got[want] {
			t.Errorf("resolutions.csv lacks %q:\n%s", want, w.file(eng, "resolutions.csv"))
		}
	}
}

// The first unescaped dot of the mailbox is the @; only that one.
func TestDNSRoot_SOAMailbox(t *testing.T) {
	for _, c := range []struct{ rname, want string }{
		{"hostmaster.example.com", "hostmaster@example.com"},
		{`a\.b\.c.dept.example.com`, "a.b.c@dept.example.com"},
	} {
		w := newWorld(t)
		w.dns.SOA("example.com", "ns1.dns-host.test", c.rname)
		runRoot(t, w)
		r := resolutionRow(w, "example.com", "SOA")
		if r == nil || r["value"] != "ns1.dns-host.test "+c.want {
			t.Errorf("SOA mailbox %q: row %v, want %q", c.rname, r, c.want)
		}
	}
}

// An in-scope name server becomes a hostname and is resolved and probed like
// any other; one outside scope is a third party, never a candidate.
func TestDNSRoot_NameServers(t *testing.T) {
	w := newWorld(t)
	w.dns.NS("example.com", "ns1.example.com")
	w.dns.NS("example.com", "ns1.cloudflare.com")
	w.dns.NS("example.com", "ns1.unknown-dns.test")
	w.dns.SOA("example.com", "ns2.example.com", "hostmaster.example.com")
	w.dns.A("ns1.example.com", "203.0.113.11")
	w.dns.A("ns2.example.com", "203.0.113.12")
	w.owner("203.0.113.11", 64500, "ACME-NET")
	w.owner("203.0.113.12", 64500, "ACME-NET")
	w.dns.A("ns1.cloudflare.com", "203.0.113.99")
	runRoot(t, w)

	subs := w.lines(eng, "subdomains.txt")
	for _, h := range []string{"ns1.example.com", "ns2.example.com"} {
		if !slices.Contains(subs, h) {
			t.Errorf("in-scope target %s is not a hostname: %v", h, subs)
		}
		if !slices.Contains(w.probed(), h) {
			t.Errorf("%s was not offered for probing: %v", h, w.probed())
		}
		if r := resolutionRow(w, h, "A"); r == nil {
			t.Errorf("%s was not resolved", h)
		}
	}
	if ip := find(w.table(eng, "ips.csv"), "ip", "203.0.113.11"); ip == nil || ip["port_eligible"] != "true" {
		t.Errorf("an in-scope name server's address is port-checked like any other: %v", ip)
	}

	tp := w.table(eng, "third-parties.csv")
	if len(tp) != 2 {
		t.Fatalf("third-parties.csv = %s", w.file(eng, "third-parties.csv"))
	}
	cf := find(tp, "domain", "cloudflare.com")
	if cf == nil || cf["mechanism"] != "ns" || cf["provider"] != "Cloudflare" || cf["root"] != "example.com" || cf["depth"] != "0" {
		t.Errorf("cloudflare row = %v", cf)
	}
	unk := find(tp, "domain", "unknown-dns.test")
	if unk == nil || unk["mechanism"] != "ns" || unk["provider"] != "" {
		t.Errorf("a name server of unknown provider is recorded by domain: %v", unk)
	}
	for _, r := range w.table(eng, "candidates.csv") {
		if strings.Contains(r["value"], "cloudflare") || strings.Contains(r["value"], "unknown-dns") {
			t.Errorf("an out-of-scope name server became a candidate: %v", r)
		}
	}
	for _, n := range []string{"ns1.cloudflare.com", "ns1.unknown-dns.test"} {
		if c := w.dns.Count(n, "A") + w.dns.Count(n, "AAAA"); c != 0 {
			t.Errorf("out-of-scope %s was resolved (%d queries)", n, c)
		}
	}
	// A SOA primary outside scope is not a third party: only name servers are.
	w2 := newWorld(t)
	w2.dns.SOA("example.com", "ns.elsewhere.test", "hostmaster.example.com")
	runRoot(t, w2)
	if got := w2.file(eng, "third-parties.csv"); got != "" {
		t.Errorf("an out-of-scope SOA primary is a third party: %s", got)
	}
}

// Every listed prefix, in any case, is one row per platform and root, without the token.
func TestDNSRoot_VerificationPlatforms(t *testing.T) {
	cases := []struct{ txt, platform string }{
		{"google-site-verification=g0ogleTOKEN", "Google"},
		{"MS=ms12345678", "Microsoft 365"},
		{"atlassian-domain-verification=atlTOKEN", "Atlassian"},
		{"docusign=docTOKEN", "DocuSign"},
		{"facebook-domain-verification=fbTOKEN", "Facebook"},
		{"apple-domain-verification=appleTOKEN", "Apple"},
		{"stripe-verification=stripeTOKEN", "Stripe"},
		{"adobe-idp-site-verification=adobeTOKEN", "Adobe"},
		{"hubspot-developer-verification=hubTOKEN", "HubSpot"},
		{"zoom-domain-verification=zoomTOKEN", "Zoom"},
		{"dropbox-domain-verification=dropTOKEN", "Dropbox"},
		{"salesforce-domain-verification=sfTOKEN", "Salesforce"},
		{"have-i-been-pwned-verification=hibpTOKEN", "Have I Been Pwned"},
		{"webexdomainverification.AB12=webexTOKEN", "Cisco Webex"},
	}
	// The fake DNS server answers over UDP only, so a root's TXT records are
	// served a few at a time to stay inside one datagram.
	for _, upper := range []bool{false, true} {
		for chunk := range slices.Chunk(cases, 5) {
			w := newWorld(t)
			for _, c := range chunk {
				txt := c.txt
				if upper {
					txt = strings.ToUpper(txt)
				}
				w.dns.TXT("example.com", txt)
			}
			if chunk[0].platform == "Google" { // two tokens of one platform are one row
				w.dns.TXT("example.com", "google-site-verification=second")
			}
			runRoot(t, w)

			tp := w.table(eng, "third-parties.csv")
			if len(tp) != len(chunk) {
				t.Errorf("upper=%v: %d rows, want one per platform (%d):\n%s", upper, len(tp), len(chunk), w.file(eng, "third-parties.csv"))
			}
			for _, c := range chunk {
				r := find(tp, "provider", c.platform)
				if r == nil || r["mechanism"] != "txt-verification" || r["root"] != "example.com" || r["domain"] != "" {
					t.Errorf("upper=%v: platform %s row = %v", upper, c.platform, r)
				}
				token := strings.ToLower(c.txt[strings.IndexAny(c.txt, "=.")+1:])
				if strings.Contains(strings.ToLower(w.file(eng, "third-parties.csv")), token) {
					t.Errorf("the token of %s reached third-parties.csv:\n%s", c.platform, w.file(eng, "third-parties.csv"))
				}
				if !strings.Contains(strings.ToLower(w.file(eng, "resolutions.csv")), token) {
					t.Errorf("upper=%v: the token of %s is public DNS and belongs in resolutions.csv", upper, c.platform)
				}
			}
		}
	}
}

// A TXT record that matches nothing is only a resolutions.csv row.
func TestDNSRoot_UnmatchedTXT(t *testing.T) {
	w := newWorld(t)
	w.dns.TXT("example.com", "v=spf1 -all")
	w.dns.TXT("example.com", "not-a-google-site-verification=abc")
	w.dns.TXT("example.com", "something else")
	runRoot(t, w)
	for _, v := range []string{"v=spf1 -all", "not-a-google-site-verification=abc", "something else"} {
		found := false
		for _, r := range w.table(eng, "resolutions.csv") {
			found = found || r["type"] == "TXT" && r["value"] == v
		}
		if !found {
			t.Errorf("TXT %q is not in resolutions.csv", v)
		}
	}
	if got := w.file(eng, "third-parties.csv"); got != "" {
		t.Errorf("an unmatched TXT inferred a third party:\n%s", got)
	}
}

// third-parties.csv ends with the standard columns and is not written when empty.
func TestDNSRoot_FileColumns(t *testing.T) {
	w := newWorld(t)
	runRoot(t, w)
	if got := w.file(eng, "third-parties.csv"); got != "" {
		t.Errorf("an empty third-parties.csv was written:\n%s", got)
	}
	w.dns.TXT("example.com", "MS=ms99")
	runRoot(t, w, "--redo", "dnsroot", "-e", eng)
	header := csvRows(t, w.file(eng, "third-parties.csv"))[0]
	want := []string{"root", "mechanism", "domain", "provider", "depth", "current", "first_seen", "last_seen"}
	if !slices.Equal(header, want) {
		t.Errorf("header = %v, want %v", header, want)
	}
	r := w.table(eng, "third-parties.csv")[0]
	if r["current"] != "true" || r["first_seen"] != "2026-11-01" || r["last_seen"] != "2026-11-01" {
		t.Errorf("row = %v", r)
	}
}

// --redo dnsroot marks a record the root no longer has as not current.
func TestDNSRoot_RedoMarksVanishedRecords(t *testing.T) {
	w := newWorld(t)
	w.dns.TXT("example.com", "google-site-verification=abc")
	w.dns.NS("example.com", "ns1.cloudflare.com")
	runRoot(t, w)
	if rows := w.table(eng, "third-parties.csv"); len(rows) != 2 || rows[0]["current"] != "true" {
		t.Fatalf("first run:\n%s", w.file(eng, "third-parties.csv"))
	}
	w.dns.ClearRoot("example.com")
	w.dns.TXT("example.com", "MS=ms1")
	runRoot(t, w, "--redo", "dnsroot", "-e", eng)

	tp := w.table(eng, "third-parties.csv")
	if r := find(tp, "provider", "Google"); r == nil || r["current"] != "false" {
		t.Errorf("a vanished verification is not marked not current: %v", r)
	}
	if r := find(tp, "domain", "cloudflare.com"); r == nil || r["current"] != "false" {
		t.Errorf("a vanished name server is not marked not current: %v", r)
	}
	if r := find(tp, "provider", "Microsoft 365"); r == nil || r["current"] != "true" {
		t.Errorf("a new verification is current: %v", r)
	}
	if r := find(w.table(eng, "resolutions.csv"), "value", "google-site-verification=abc"); r == nil || r["current"] != "false" {
		t.Errorf("the vanished TXT row is not marked not current: %v", r)
	}
}

// One check per root and type, run under --passive; the checks are in the
// state database and no transfer is attempted.
func TestDNSRoot_ChecksAndPassive(t *testing.T) {
	w := newWorld(t)
	w.dns.TXT("example.com", "MS=ms1")
	runRoot(t, w)
	if st, reason := stateOf(w, "dnsroot"); st != "done" {
		t.Errorf("dnsroot under --passive = %s (%s)", st, reason)
	}
	want := []string{"example.com|CAA", "example.com|NS", "example.com|SOA", "example.com|TXT"}
	if got := w.h.completed(eng, "dnsroot"); !slices.Equal(got, want) {
		t.Errorf("checks = %v, want %v", got, want)
	}
	for _, ty := range []string{"NS", "SOA", "TXT", "CAA"} {
		if n := w.dns.Count("example.com", ty); n != 1 {
			t.Errorf("%s queried %d times, want once", ty, n)
		}
	}
	if len(w.dns.Queried("AXFR"))+len(w.dns.Queried("IXFR")) != 0 {
		t.Error("a zone transfer was attempted")
	}
	// A second run repeats nothing.
	runRoot(t, w, "-e", eng)
	if n := w.dns.Count("example.com", "NS"); n != 1 {
		t.Errorf("NS queried %d times after a second run", n)
	}
}

// A root that is an alias has no name servers or SOA of its own, so its alias
// target's are not recorded as the root's.
func TestDNSRoot_AliasRootTakesNoTargetNameServers(t *testing.T) {
	w := newWorld(t)
	w.dns.CNAME("example.com", "edge.cdn-host.test")
	w.dns.A("edge.cdn-host.test", "203.0.113.50")
	w.dns.NS("edge.cdn-host.test", "ns1.cdn-dns.test")
	w.dns.SOA("edge.cdn-host.test", "ns1.cdn-dns.test", "hostmaster.cdn-host.test")
	runRoot(t, w)
	for _, ty := range []string{"NS", "SOA"} {
		if r := resolutionRow(w, "example.com", ty); r != nil {
			t.Errorf("the alias target's %s is recorded as the root's: %v", ty, r)
		}
	}
	if tp := w.table(eng, "third-parties.csv"); len(tp) != 0 {
		t.Errorf("third-parties.csv = %v", tp)
	}
}

// Only roots that are in scope are queried.
func TestDNSRoot_ExcludedRootNotQueried(t *testing.T) {
	w := newWorld(t)
	w.dns.NS("other.test", "ns1.dns-host.test")
	if code := w.run("--passive", "--exclude", "other.test", "example.com", "other.test"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, ty := range []string{"NS", "SOA", "TXT", "CAA"} {
		if n := w.dns.Count("other.test", ty); n != 0 {
			t.Errorf("excluded root queried for %s %d times", ty, n)
		}
	}
	if n := w.dns.Count("example.com", "NS"); n != 1 {
		t.Errorf("in-scope root NS queried %d times", n)
	}
}

// NODATA and NXDOMAIN complete a type's check with no rows; SERVFAIL fails
// only that type, and only it is retried.
func TestDNSRoot_Outcomes(t *testing.T) {
	w := newWorld(t)
	w.dns.NS("example.com", "ns1.dns-host.test") // SOA, TXT and CAA are NODATA
	w.dns.RcodeType("example.com", "TXT", egress.RCodeServFail)
	if code := w.run("--passive", "example.com", "gone.example.org"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	done := w.h.completed(eng, "dnsroot")
	for _, k := range []string{"example.com|NS", "example.com|SOA", "example.com|CAA",
		"gone.example.org|NS", "gone.example.org|SOA", "gone.example.org|TXT", "gone.example.org|CAA"} {
		if !slices.Contains(done, k) {
			t.Errorf("check %s did not complete (NODATA and NXDOMAIN are results): %v", k, done)
		}
	}
	if slices.Contains(done, "example.com|TXT") {
		t.Errorf("a SERVFAIL completed its check: %v", done)
	}
	if e := lastState(w.h.events(), "dnsroot"); e.num("failed") != 1 {
		t.Errorf("dnsroot state = %v, want exactly the TXT check failed", e)
	}
	if resolutionRow(w, "example.com", "NS") == nil {
		t.Errorf("the other types still recorded their rows:\n%s", w.file(eng, "resolutions.csv"))
	}
	if resolutionRow(w, "gone.example.org", "NS") != nil {
		t.Error("NXDOMAIN produced a row")
	}

	w.dns.ClearRcodeType("example.com", "TXT")
	w.dns.TXT("example.com", "MS=ms7")
	if code := w.run("--passive", "-e", eng); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !slices.Contains(w.h.completed(eng, "dnsroot"), "example.com|TXT") {
		t.Error("the failed TXT check was not retried")
	}
	if n := w.dns.Count("example.com", "NS"); n != 1 {
		t.Errorf("completed checks were repeated: NS queried %d times", n)
	}
	if find(w.table(eng, "third-parties.csv"), "provider", "Microsoft 365") == nil {
		t.Errorf("the retried check found nothing:\n%s", w.file(eng, "third-parties.csv"))
	}
}

// The console and --json announce a new third party.
func TestDNSRoot_FoundLine(t *testing.T) {
	w := newWorld(t)
	w.dns.TXT("example.com", "google-site-verification=abc")
	w.dns.NS("example.com", "ns1.cloudflare.com")
	if code := w.h.exec("--passive", "--rate-dns", "100000", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	out := w.h.stdout.String()
	for _, want := range []string{
		"+ third-party Google via txt-verification on example.com",
		"+ third-party Cloudflare via ns on example.com",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("console lacks %q:\n%s", want, out)
		}
	}

	w2 := newWorld(t)
	w2.dns.TXT("example.com", "google-site-verification=abc")
	runRoot(t, w2)
	var found []event
	for _, e := range ofType(w2.h.events(), "found") {
		if e.str("platform") != "" {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		t.Fatalf("found events with a platform = %v", found)
	}
	if e := found[0]; e.str("platform") != "Google" || e.str("mechanism") != "txt-verification" || e.str("root") != "example.com" {
		t.Errorf("found event = %v", e)
	}
	// Re-running announces nothing new.
	runRoot(t, w2, "-e", eng)
	for _, e := range ofType(w2.h.events(), "found") {
		if e.str("platform") != "" {
			t.Errorf("a known third party was announced again: %v", e)
		}
	}
}

// The summary counts third parties.
func TestDNSRoot_SummaryCount(t *testing.T) {
	w := newWorld(t)
	w.dns.TXT("example.com", "google-site-verification=abc")
	w.dns.NS("example.com", "ns1.cloudflare.com")
	runRoot(t, w)
	evs := ofType(w.h.events(), "summary")
	totals, _ := evs[len(evs)-1]["totals"].(map[string]any)
	if n, _ := totals["third parties"].(float64); n != 2 {
		t.Errorf("totals = %v, want 2 third parties", totals)
	}
}

// A root added later that covers a third party's domain hides the row without a re-run.
func TestDNSRoot_DomainInScopeHidesRow(t *testing.T) {
	w := newWorld(t)
	w.dns.NS("example.com", "ns1.dns-host.test")
	runRoot(t, w)
	if find(w.table(eng, "third-parties.csv"), "domain", "dns-host.test") == nil {
		t.Fatalf("no row:\n%s", w.file(eng, "third-parties.csv"))
	}
	if code := w.run("--passive", "--skip", "dnsroot", "-e", eng, "dns-host.test"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got := w.table(eng, "third-parties.csv"); find(got, "domain", "dns-host.test") != nil {
		t.Errorf("a domain now in scope is still a third party:\n%s", w.file(eng, "third-parties.csv"))
	}
}

// A name server row that is no longer current is also hidden once a root
// covers its domain, though the store keeps no attributes for it.
func TestDNSRoot_DomainInScopeHidesNotCurrentRow(t *testing.T) {
	w := newWorld(t)
	w.dns.NS("example.com", "ns1.dns-host.test")
	runRoot(t, w)
	w.dns.ClearRoot("example.com")
	runRoot(t, w, "--redo", "dnsroot", "-e", eng)
	if r := find(w.table(eng, "third-parties.csv"), "domain", "dns-host.test"); r == nil || r["current"] != "false" {
		t.Fatalf("the vanished name server is not listed as not current:\n%s", w.file(eng, "third-parties.csv"))
	}
	if code := w.run("--passive", "--skip", "dnsroot", "-e", eng, "dns-host.test"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got := w.file(eng, "third-parties.csv"); got != "" {
		t.Errorf("a not-current name server whose domain is now in scope is still listed:\n%s", got)
	}
}

// Rows of the new types do not create wildcard checks: only A, AAAA and CNAME
// rows name zones.
func TestDNSRoot_RowsCreateNoWildcardChecks(t *testing.T) {
	w := newWorld(t)
	feed := &testkit.Stage{StageName: "feed", Kind: run.ThirdParty,
		ChecksFn: func(run.View) []run.Check { return []run.Check{{Key: "x"}} },
		RunFn: func(context.Context, run.Check, egress.Clients) ([]run.Observation, error) {
			var obs []run.Observation
			for _, ty := range []string{"NS", "SOA", "TXT", "CAA"} {
				obs = append(obs, resolutionObs("_a."+strings.ToLower(ty)+".example.com", ty, "v"))
			}
			// A control: the same shape as a CNAME does name a zone.
			return append(obs, resolutionObs("_c._ctl.example.com", "CNAME", "target.example.net")), nil
		}}
	w.h.stages = append(w.h.stages, feed)
	runRoot(t, w)
	done := w.h.completed(eng, "wildcard")
	if !slices.Contains(done, "_ctl.example.com") {
		t.Fatalf("control: a CNAME row's parent was not checked: %v", done)
	}
	for _, ty := range []string{"ns", "soa", "txt", "caa"} {
		if slices.Contains(done, ty+".example.com") {
			t.Errorf("a %s row created a wildcard check for %s.example.com: %v", ty, ty, done)
		}
	}
}

func resolutionObs(name, typ, value string) run.Observation {
	return kinds.Resolution.Obs(name+"|"+typ+"|"+value, kinds.ResolutionAttrs{Name: name, Type: typ, Value: value})
}
