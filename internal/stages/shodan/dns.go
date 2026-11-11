package shodan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net/url"
	"strconv"
	"strings"

	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/scope"
	"github.com/rafaelh/recon/internal/stages/httpsrc"
)

// DNS is the shodan-dns stage: the subdomains Shodan lists for each in-scope
// input root, and the A, AAAA, CNAME, MX and NS records it holds for them.
//
// The names become hostnames, and so do in-scope CNAME, MX and NS targets. The
// records themselves are stored as dns_claim, never as resolution and with no ip
// record: what a third party says a name points at is shown, but nothing reads
// it to decide what to resolve, contact, port-check or probe.
type DNS struct{}

// NewDNS returns the shodan-dns stage.
func NewDNS() *DNS { return &DNS{} }

func (*DNS) Name() string         { return "shodan-dns" }
func (*DNS) Contact() run.Contact { return run.ThirdParty }
func (*DNS) Sources() []string    { return []string{"api.shodan.io"} }

// Configured: it uses the key of the shodan stage.
func (*DNS) Configured(e run.Env) (bool, string) { return httpsrc.Configured(e, "shodan", true) }

// dnsInput is the Check.Input. The scope travels in it so that Run can tell an
// in-scope CNAME target from one that is not.
type dnsInput struct {
	root  string
	pages int
	sc    *scope.Scope
}

// Checks yields one check per in-scope input root, keyed "<root>|pages=<n>" so
// raising shodan_dns.max_pages repeats them.
func (*DNS) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		pages := v.Settings().ShodanDNS.MaxPages
		for _, r := range v.Inputs().Roots {
			if v.Scope().ClassifyHost(r).Class != scope.InScope {
				continue
			}
			if !yield(run.Check{Key: fmt.Sprintf("%s|pages=%d", r, pages), Input: dnsInput{root: r, pages: pages, sc: v.Scope()}}, nil) {
				return
			}
		}
	}
}

type dnsAnswer struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
	Data       []struct {
		Subdomain string `json:"subdomain"`
		Type      string `json:"type"`
		Value     string `json:"value"`
	} `json:"data"`
	More bool `json:"more"`
}

// Run reads the root's result pages, in.pages at most (each costs one query
// credit). A 404 is a root Shodan knows nothing about.
func (*DNS) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	in := c.Input.(dnsInput)
	out := &dnsObs{in: in, seen: map[string]bool{}}
	for page := 1; ; page++ {
		q := url.Values{"page": {strconv.Itoa(page)}}
		body, err := httpsrc.Get(ctx, e, egress.ThirdPartyRequest{
			Method: "GET", URL: "https://api.shodan.io/dns/domain/" + url.PathEscape(in.root) + "?" + q.Encode(), KeySource: "shodan", KeyParam: "key",
		})
		if errors.Is(err, httpsrc.ErrNotFound) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("shodan-dns %s: %w", in.root, err)
		}
		var r dnsAnswer
		if err := json.Unmarshal(body, &r); err != nil || r.Domain == "" && r.Subdomains == nil && r.Data == nil {
			return nil, fmt.Errorf("shodan-dns %s: unreadable response", in.root)
		}
		for _, n := range httpsrc.JoinLabels(in.root, r.Subdomains) {
			if n = httpsrc.CleanName(n); n != "" {
				out.hostname(n)
			}
		}
		for _, d := range r.Data {
			out.record(d.Subdomain, d.Type, d.Value)
		}
		if !r.More {
			break
		}
		if page == in.pages {
			run.Warnf(ctx, "shodan-dns %s: result truncated after %d pages; raise shodan_dns.max_pages to read more (each page costs one Shodan query credit)", in.root, in.pages)
			break
		}
	}
	return out.obs, nil
}

// dnsObs accumulates a check's observations without repeating any.
type dnsObs struct {
	in   dnsInput
	seen map[string]bool
	obs  []run.Observation
}

// hostname records a name already in canonical form (httpsrc.CleanName).
func (o *dnsObs) hostname(name string) {
	if !o.seen["h|"+name] {
		o.seen["h|"+name] = true
		o.obs = append(o.obs, kinds.Hostname.Obs(name, kinds.HostnameAttrs{}))
	}
}

// record stores one DNS record of a name under the root; the name is a hostname
// whatever the record's type. Types other than A, AAAA, CNAME, MX and NS,
// wildcard names and unreadable values store no record.
func (o *dnsObs) record(sub, typ, value string) {
	typ = strings.ToUpper(typ)
	if strings.Contains(sub, "*") {
		return
	}
	name := o.in.root
	if sub != "" {
		name = sub + "." + o.in.root
	}
	if name = httpsrc.CleanName(name); name == "" {
		return
	}
	o.hostname(name)
	var target string
	switch typ {
	case "A", "AAAA":
		a, ok := input.IPLiteral(strings.TrimSpace(value))
		if !ok {
			return
		}
		// The type follows the address, as resolve's does, so that the keys of
		// one record agree whatever type Shodan labelled it with.
		typ, value = "AAAA", a.String()
		if a.Is4() {
			typ = "A"
		}
	case "CNAME", "MX", "NS":
		if f := strings.Fields(value); len(f) > 0 {
			value = f[len(f)-1] // an MX value may begin with its preference
		}
		if value = httpsrc.CleanName(value); value == "" {
			return
		}
		target = value
	default:
		return
	}
	if target != "" && o.in.sc.ClassifyHost(target).Class == scope.InScope {
		o.hostname(target)
	}
	if key := name + "|" + typ + "|" + value; !o.seen[key] {
		o.seen[key] = true
		o.obs = append(o.obs, kinds.DNSClaim.Obs(key, kinds.DNSClaimAttrs{Name: name, Type: typ, Value: value, Source: "shodan"}))
	}
}
