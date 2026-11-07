package risk

import (
	"context"
	"fmt"
	"iter"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/rafaelh/recon/internal/config"
	"github.com/rafaelh/recon/internal/dnsname"
	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/scope"
)

// Email reads MX, SPF, DMARC and common DKIM selectors for each in-scope input
// root (Spec 5 D12). It only asks public DNS, so it runs under --passive.
type Email struct{}

// NewEmail returns the email stage.
func NewEmail() *Email { return &Email{} }

func (*Email) Name() string                      { return "email" }
func (*Email) Contact() run.Contact              { return run.ThirdParty }
func (*Email) Sources() []string                 { return nil }
func (*Email) Configured(run.Env) (bool, string) { return true, "" }

// RetiresUnlistedChecks: a check for a changed selector list supersedes the old one's evidence.
func (*Email) RetiresUnlistedChecks() {}

// Checks yields one check per in-scope input root; a changed selector list creates new checks.
func (*Email) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		for _, root := range slices.Sorted(slices.Values(v.Inputs().Roots)) {
			if v.Scope().ClassifyHost(root).Class != scope.InScope {
				continue
			}
			if !yield(run.Check{Key: root + "|dkim=" + config.DKIMSelectorHash(), Input: root}, nil) {
				return
			}
		}
	}
}

// txt returns the TXT strings at name. A timeout or SERVFAIL is an error; NXDOMAIN and NODATA are no records.
func txt(ctx context.Context, e egress.Clients, name string) ([]string, error) {
	res, err := e.DNS.Query(ctx, name, egress.TypeTXT)
	if err != nil {
		return nil, err
	}
	if res.RCode == egress.RCodeServFail {
		return nil, fmt.Errorf("%s: SERVFAIL", name)
	}
	var out []string
	for _, a := range res.Answers {
		if a.Type == "TXT" {
			out = append(out, a.Value)
		}
	}
	return out, nil
}

// withPrefix returns the records that start with prefix (case-insensitively)
// followed by the end or a space.
func withPrefix(records []string, prefix string) []string {
	var out []string
	for _, r := range records {
		t := strings.TrimSpace(r)
		if len(t) >= len(prefix) && strings.EqualFold(t[:len(prefix)], prefix) && (len(t) == len(prefix) || t[len(prefix)] == ' ' || t[len(prefix)] == ';') {
			out = append(out, t)
		}
	}
	return out
}

// Run reads the posture. A timeout or SERVFAIL on MX, the root's TXT, an SPF
// include or redirect, or the DMARC names fails the check (it is retried next
// run); one on a DKIM selector is recorded in dkim_errors. An include that does
// not exist or has no single SPF record makes the SPF invalid.
func (*Email) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	root := c.Input.(string)
	var attrs kinds.EmailPostureAttrs

	mx, err := e.DNS.Query(ctx, root, egress.TypeMX)
	if err != nil {
		return nil, err
	}
	if mx.RCode == egress.RCodeServFail {
		return nil, fmt.Errorf("%s MX: SERVFAIL", root)
	}
	var hosts []string
	for _, a := range mx.Answers {
		if a.Type != "MX" {
			continue
		}
		if _, host, ok := strings.Cut(a.Value, " "); ok && host != "." && host != "" {
			hosts = append(hosts, host)
		}
	}
	slices.Sort(hosts)
	attrs.MX = strings.Join(hosts, ";")

	rootTXT, err := txt(ctx, e, root)
	if err != nil {
		return nil, err
	}
	spfs := withPrefix(rootTXT, "v=spf1")
	attrs.SPFRecords = len(spfs)
	if len(spfs) > 0 {
		attrs.SPF = spfs[0]
	}
	switch {
	case len(spfs) > 1:
		attrs.SPFError = fmt.Sprintf("%d v=spf1 records", len(spfs))
	case len(spfs) == 1:
		ev := &spfEval{ctx: ctx, e: e}
		all := ev.walk(spfs[0], map[string]bool{root: true})
		if ev.tempErr != nil {
			return nil, ev.tempErr
		}
		attrs.SPFAll, attrs.SPFLookups, attrs.SPFError = all, ev.lookups, ev.err
	}

	// DMARC: the root's own record, else the organisational domain's.
	rec, err := dmarc(ctx, e, "_dmarc."+root)
	if err != nil {
		return nil, err
	}
	source, sub := "root", false
	if org, ok := dnsname.ETLDPlusOne(root); ok && org != root {
		sub = true
		if rec == "" {
			if rec, err = dmarc(ctx, e, "_dmarc."+org); err != nil {
				return nil, err
			}
			source = "org"
		}
	}
	if rec != "" {
		tags := dmarcTags(rec)
		policy := tags["p"]
		if sub && source == "org" && tags["sp"] != "" {
			policy = tags["sp"]
		}
		attrs.DMARC, attrs.DMARCPolicy, attrs.DMARCSource = rec, strings.ToLower(policy), source
	}

	// The selectors are independent lookups, so they are asked at once (egress
	// still rate-limits them); the results keep the selectors' order.
	sels := config.DKIMSelectors()
	type dkim struct {
		recs []string
		err  error
	}
	res := make([]dkim, len(sels))
	var wg sync.WaitGroup
	for i, sel := range sels {
		wg.Go(func() {
			res[i].recs, res[i].err = txt(ctx, e, sel+"._domainkey."+root)
		})
	}
	wg.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	var found, failed []string
	for i, sel := range sels {
		if res[i].err != nil {
			failed = append(failed, sel)
			continue
		}
		if slices.ContainsFunc(res[i].recs, isDKIMKey) {
			found = append(found, sel)
		}
	}
	attrs.DKIMSelectors, attrs.DKIMErrors = strings.Join(found, ";"), strings.Join(failed, ";")
	return []run.Observation{kinds.EmailPosture.Obs(root, attrs)}, nil
}

func dmarc(ctx context.Context, e egress.Clients, name string) (string, error) {
	recs, err := txt(ctx, e, name)
	if err != nil {
		return "", err
	}
	if m := withPrefix(recs, "v=DMARC1"); len(m) > 0 {
		return m[0], nil
	}
	return "", nil
}

// isDKIMKey reports whether a TXT record is a usable DKIM key (RFC 6376 3.6.1):
// a v= tag, if present, is DKIM1 and the p= tag is non-empty. A revoked key
// (empty p=) and an unrelated record a wildcard returns are not.
func isDKIMKey(rec string) bool {
	t := dmarcTags(rec)
	if v, ok := t["v"]; ok && !strings.EqualFold(v, "DKIM1") {
		return false
	}
	return strings.Join(strings.Fields(t["p"]), "") != ""
}

// dmarcTags parses a tag=value list (DMARC, DKIM), lower-casing the tag names.
func dmarcTags(rec string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(rec, ";") {
		if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok {
			tags[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	return tags
}

// spfEval counts the DNS-querying terms of an SPF record and its includes and
// redirects (RFC 7208 4.6.4), following them with loop detection and a hard stop.
// err is a permanent error (the SPF is invalid); tempErr is a timeout or
// SERVFAIL on an include or redirect, which fails the check so it is retried
// (an RFC 7208 temperror, not a permerror).
type spfEval struct {
	ctx     context.Context
	e       egress.Clients
	lookups int
	queries int
	err     string
	tempErr error
}

const spfMaxQueries = 30 // a hard stop on what one record may make us ask

func (s *spfEval) fail(msg string) {
	if s.err == "" {
		s.err = msg
	}
}

// walk evaluates one record and returns its "all" mechanism with qualifier ("" if none).
func (s *spfEval) walk(record string, path map[string]bool) string {
	all, redirect := "", ""
	for _, term := range strings.Fields(record)[1:] {
		q := byte('+')
		if strings.ContainsRune("+-~?", rune(term[0])) {
			q, term = term[0], term[1:]
		}
		name, arg, _ := strings.Cut(term, ":")
		if n, a, ok := strings.Cut(term, "="); ok && strings.EqualFold(n, "redirect") {
			name, arg = "redirect", a
		}
		name = strings.ToLower(strings.SplitN(name, "/", 2)[0])
		switch name {
		case "all":
			all = string(q) + "all"
		case "include":
			s.lookups++
			s.follow(arg, path)
		case "redirect":
			redirect = arg
		case "a", "mx", "ptr", "exists":
			s.lookups++
		}
	}
	// A redirect is ignored, and never queried, when the record has an "all" (RFC 7208 6.1).
	if redirect != "" && all == "" {
		s.lookups++
		return s.follow(redirect, path)
	}
	return all
}

// spfDomain matches a domain that can be looked up: dot-separated labels of
// letters, digits, "-" and "_".
var spfDomain = regexp.MustCompile(`^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)+$`)

// follow fetches and evaluates the SPF record of an included or redirected domain.
func (s *spfEval) follow(domain string, path map[string]bool) string {
	domain = dnsname.Normalise(domain)
	switch {
	case s.tempErr != nil:
		return ""
	case domain == "":
		s.fail("include with no domain")
		return ""
	case strings.Contains(domain, "%"):
		return "" // a macro expands per message, so it cannot be followed here
	case len(domain) > 253 || !spfDomain.MatchString(domain):
		s.fail(fmt.Sprintf("include %q is not a domain name", domain))
		return ""
	case path[domain]:
		s.fail("include loop at " + domain)
		return ""
	case s.queries >= spfMaxQueries:
		s.fail("too many includes")
		return ""
	}
	s.queries++
	recs, err := txt(s.ctx, s.e, domain)
	if err != nil {
		s.tempErr = fmt.Errorf("SPF include %s: %w", domain, err)
		return ""
	}
	spfs := withPrefix(recs, "v=spf1")
	if len(spfs) != 1 {
		s.fail(fmt.Sprintf("include %s: %d SPF records", domain, len(spfs)))
		return ""
	}
	path[domain] = true
	defer delete(path, domain)
	return s.walk(spfs[0], path)
}
