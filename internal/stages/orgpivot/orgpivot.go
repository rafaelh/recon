// Package orgpivot turns organisation names into new root domains and netblocks.
// Everything it finds is a candidate: scope classifies the results, and
// candidates are recorded, never enumerated.
package orgpivot

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/url"
	"regexp"
	"strings"

	"github.com/rafaelh/recon/internal/dnsname"
	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/stages/httpsrc"
)

// maxASNsPerOrg caps the autonomous systems taken for one organisation. The
// value is a reasonable guess, not a source limit.
const maxASNsPerOrg = 10

// orgStage is the part every organisation stage shares: one check per input organisation.
type orgStage struct {
	name    string
	sources []string
	keyed   bool
}

func (s orgStage) Name() string                        { return s.name }
func (orgStage) Contact() run.Contact                  { return run.ThirdParty }
func (s orgStage) Sources() []string                   { return s.sources }
func (s orgStage) Configured(e run.Env) (bool, string) { return httpsrc.Configured(e, s.name, s.keyed) }

func (orgStage) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		for _, o := range v.Inputs().Orgs {
			if !yield(run.Check{Key: o, Input: o}, nil) {
				return
			}
		}
	}
}

func rootObs(names []string) []run.Observation {
	seen := map[string]bool{}
	var obs []run.Observation
	for _, n := range names {
		n = input.NormaliseHost(strings.TrimPrefix(strings.TrimSpace(n), "*."))
		if n == "" || strings.ContainsAny(n, "*@/: ") {
			continue
		}
		root, ok := dnsname.ETLDPlusOne(n)
		if !ok || seen[root] {
			continue
		}
		seen[root] = true
		obs = append(obs, kinds.Root.Obs(root))
	}
	return obs
}

// --- ct-org ---

// CTOrg finds roots from the organisation field of certificates in CT logs.
type CTOrg struct{ orgStage }

// NewCTOrg returns the ct-org stage.
func NewCTOrg() *CTOrg { return &CTOrg{orgStage{name: "ct-org", sources: []string{"crt.sh"}}} }

// Run searches crt.sh by organisation (O=) and reduces the names to registrable domains.
func (*CTOrg) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	body, err := httpsrc.Crtsh(ctx, e, url.Values{"O": {c.Key}})
	if err != nil {
		return nil, fmt.Errorf("ct-org %s: %w", c.Key, err)
	}
	// For an O= search crt.sh puts the matched organisation in name_value; the
	// certificate's names are in common_name.
	var rows []struct {
		CommonName string `json:"common_name"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("ct-org %s: unreadable crt.sh response: %v", c.Key, err)
	}
	var names []string
	for _, r := range rows {
		names = append(names, r.CommonName)
	}
	return rootObs(names), nil
}

// --- whoisxml ---

// WhoisXML finds roots by reverse WHOIS on the organisation name (keyed). The
// check is remembered, so each organisation costs one credit per engagement.
type WhoisXML struct{ orgStage }

// NewWhoisXML returns the whoisxml stage.
func NewWhoisXML() *WhoisXML {
	return &WhoisXML{orgStage{name: "whoisxml", sources: []string{"reverse-whois.whoisxmlapi.com"}, keyed: true}}
}

// Run buys the reverse WHOIS result for the organisation. The client puts the key in the body.
func (*WhoisXML) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	body, _ := json.Marshal(map[string]any{
		"mode":             "purchase",
		"basicSearchTerms": map[string]any{"include": []string{c.Key}},
	})
	out, err := httpsrc.Get(ctx, e, egress.ThirdPartyRequest{
		Method: "POST", URL: "https://reverse-whois.whoisxmlapi.com/api/v2", Body: body, ContentType: "application/json",
		KeySource: "whoisxml", KeyBodyField: "apiKey",
	})
	if err != nil {
		return nil, fmt.Errorf("whoisxml %s: %w", c.Key, err)
	}
	var r struct {
		DomainsList []string `json:"domainsList"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, fmt.Errorf("whoisxml %s: unreadable response: %v", c.Key, err)
	}
	return rootObs(r.DomainsList), nil
}

// --- org-asn ---

// OrgASN finds netblocks for an organisation through RIPEstat. Netblocks it
// records are candidates: only the asn stage's netblocks for input ASNs are in scope.
type OrgASN struct{ orgStage }

// NewOrgASN returns the org-asn stage.
func NewOrgASN() *OrgASN {
	return &OrgASN{orgStage{name: "org-asn", sources: []string{"stat.ripe.net"}}}
}

var legalSuffix = map[string]bool{
	"inc": true, "llc": true, "ltd": true, "limited": true, "corp": true, "corporation": true, "co": true,
	"company": true, "plc": true, "gmbh": true, "sa": true, "ag": true, "pty": true, "pte": true, "bv": true, "nv": true,
}

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// tokens are the lower-case words of an organisation name without legal suffixes.
func tokens(org string) []string {
	var out []string
	for _, t := range nonAlnum.Split(strings.ToLower(org), -1) {
		if t != "" && !legalSuffix[t] {
			out = append(out, t)
		}
	}
	return out
}

// Run finds the organisation's ASNs and their announced prefixes. An ASN is
// kept only if its holder name contains every token of the organisation name.
func (*OrgASN) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	want := tokens(c.Key)
	if len(want) == 0 {
		return nil, nil
	}
	q := url.Values{"resource": {c.Key}, "limit": {"50"}, "sourceapp": {"recon"}}
	body, err := httpsrc.Get(ctx, e, egress.ThirdPartyRequest{Method: "GET", URL: "https://stat.ripe.net/data/searchcomplete/data.json?" + q.Encode()})
	if err != nil {
		return nil, fmt.Errorf("org-asn %s: %w", c.Key, err)
	}
	var sc struct {
		Status string `json:"status"`
		Data   struct {
			Categories []struct {
				Category    string `json:"category"`
				Suggestions []struct {
					Value, Description string
				} `json:"suggestions"`
			} `json:"categories"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &sc); err != nil || sc.Status != "ok" {
		return nil, fmt.Errorf("org-asn %s: unreadable RIPEstat response", c.Key)
	}
	var asns []string
	for _, cat := range sc.Data.Categories {
		if cat.Category != "ASNs" {
			continue
		}
		for _, s := range cat.Suggestions {
			holder := strings.ToLower(s.Description)
			ok := true
			for _, t := range want {
				ok = ok && strings.Contains(holder, t)
			}
			if ok && len(asns) < maxASNsPerOrg {
				asns = append(asns, strings.ToUpper(s.Value))
			}
		}
	}
	var obs []run.Observation
	for _, asn := range asns {
		pq := url.Values{"resource": {asn}, "sourceapp": {"recon"}}
		body, err := httpsrc.Get(ctx, e, egress.ThirdPartyRequest{Method: "GET", URL: "https://stat.ripe.net/data/announced-prefixes/data.json?" + pq.Encode()})
		if err != nil {
			return nil, fmt.Errorf("org-asn %s %s: %w", c.Key, asn, err)
		}
		var ap struct {
			Status string `json:"status"`
			Data   struct {
				Prefixes []struct{ Prefix string } `json:"prefixes"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &ap); err != nil || ap.Status != "ok" {
			return nil, fmt.Errorf("org-asn %s %s: unreadable RIPEstat response", c.Key, asn)
		}
		for _, p := range ap.Data.Prefixes {
			if p.Prefix = strings.TrimSpace(p.Prefix); p.Prefix != "" {
				obs = append(obs, kinds.Netblock.Obs(p.Prefix, kinds.NetblockAttrs{ASN: asn, Org: c.Key}))
			}
		}
	}
	return obs, nil
}
