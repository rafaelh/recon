package dns

import (
	"context"
	"fmt"
	"iter"
	"strings"

	"github.com/rafaelh/recon/internal/dnsname"
	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/provider"
	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/scope"
)

// DNSRoot records the NS, SOA, TXT and CAA records of each in-scope input
// root, so later pivots can use them, and from them the third parties the root
// depends on: its name servers' operators, and the SaaS platforms its TXT
// records show domain ownership was verified with. It asks the same public
// resolvers as resolve and never attempts a zone transfer.
type DNSRoot struct{ base }

// NewDNSRoot returns the dnsroot stage.
func NewDNSRoot() *DNSRoot { return &DNSRoot{base{"dnsroot"}} }

// rootTypes are the record types asked of each root, one check each, so a type
// that keeps failing never blocks the others.
type rootType struct {
	name string
	code uint16
}

var rootTypes = []rootType{
	{"NS", egress.TypeNS}, {"SOA", egress.TypeSOA}, {"TXT", egress.TypeTXT}, {"CAA", egress.TypeCAA},
}

type rootInput struct {
	root string
	t    rootType
	sc   *scope.Scope
}

// Checks yields one check per input root that is in scope and per record type,
// keyed "<root>|<TYPE>".
func (*DNSRoot) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		for _, root := range v.Inputs().Roots { // canonical and unique
			if v.Scope().ClassifyHost(root).Class != scope.InScope {
				continue
			}
			for _, t := range rootTypes {
				c := run.Check{Key: root + "|" + t.name, Input: rootInput{root, t, v.Scope()}}
				if !yield(c, nil) {
					return
				}
			}
		}
	}
}

// Run queries one type of one root. NODATA and NXDOMAIN complete the check with
// no observations; SERVFAIL is a transient failure of this type only.
func (*DNSRoot) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	in := c.Input.(rootInput)
	res, err := lookup(ctx, e, in.root, in.t.code)
	if err != nil {
		return nil, err
	}
	if res.RCode == egress.RCodeServFail {
		return nil, fmt.Errorf("%s %s: resolver answered SERVFAIL", in.root, in.t.name)
	}
	var obs []run.Observation
	for _, a := range res.Answers {
		if a.Type != in.t.name || a.Value == "" {
			continue
		}
		// A root that is an alias has no name servers or SOA of its own: an
		// answer for its alias target's zone says nothing about the root.
		if (in.t.name == "NS" || in.t.name == "SOA") && a.Name != in.root {
			continue
		}
		obs = append(obs, kinds.Resolution.Obs(in.root+"|"+in.t.name+"|"+a.Value,
			kinds.ResolutionAttrs{Name: in.root, Type: in.t.name, Value: a.Value}))
		switch in.t.name {
		case "NS", "SOA":
			target, _, _ := strings.Cut(a.Value, " ") // an SOA value starts with its primary
			obs = append(obs, nameServer(in, target)...)
		case "TXT":
			if platform, ok := provider.Default().Verification(a.Value); ok {
				obs = append(obs, kinds.ThirdParty.Obs(in.root+"|"+kinds.MechanismTXTVerification+"|"+platform,
					kinds.ThirdPartyAttrs{Root: in.root, Mechanism: kinds.MechanismTXTVerification, Provider: platform}))
			}
		}
	}
	return obs, nil
}

// nameServer is what a name server (an NS target, or an SOA primary) adds: an
// in-scope name is a hostname, resolved and probed like any other. Any other NS
// target is a third party, recorded by its registrable domain and never as a
// candidate; an SOA primary outside the scope adds nothing.
func nameServer(in rootInput, host string) []run.Observation {
	if host == "" {
		return nil
	}
	if in.sc.ClassifyHost(host).Class == scope.InScope {
		return []run.Observation{kinds.Hostname.Obs(host, kinds.HostnameAttrs{})}
	}
	if in.t.name != "NS" {
		return nil
	}
	domain, ok := dnsname.ETLDPlusOne(host)
	if !ok {
		domain = host
	}
	owner, _ := provider.Default().DomainOwner(domain)
	return []run.Observation{kinds.ThirdParty.Obs(in.root+"|"+kinds.MechanismNS+"|"+domain,
		kinds.ThirdPartyAttrs{Root: in.root, Mechanism: kinds.MechanismNS, Domain: domain, Provider: owner})}
}
