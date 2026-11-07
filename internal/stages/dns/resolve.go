package dns

import (
	"context"
	"iter"
	"net/netip"

	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/run"
)

// Resolve looks up A and AAAA for each in-scope or excluded hostname and for
// the input roots. Addresses are keyed to the queried name, never to the
// answer's owner name, which after a CNAME is the chain target.
type Resolve struct{ base }

// NewResolve returns the resolve stage.
func NewResolve() *Resolve { return &Resolve{base{"resolve"}} }

// Checks yields one check per resolvable hostname.
func (*Resolve) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		for _, h := range v.ResolvableHostnames() {
			if !yield(run.Check{Key: h, Input: h}, nil) {
				return
			}
		}
	}
}

// Run resolves the name. NXDOMAIN, NODATA and SERVFAIL are results recorded as
// kind unresolved; a timeout is an error.
func (*Resolve) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	name := c.Key
	a, err := lookup(ctx, e, name, egress.TypeA)
	if err != nil {
		return nil, err
	}
	aaaa, err := lookup(ctx, e, name, egress.TypeAAAA)
	if err != nil {
		return nil, err
	}
	var obs []run.Observation
	links := map[egress.CNAME]bool{}
	for _, res := range []egress.DNSResult{a, aaaa} {
		for _, l := range res.CNAMEs {
			if !links[l] {
				links[l] = true
				obs = append(obs, kinds.Resolution.Obs(l.Name+"|CNAME|"+l.Target,
					kinds.ResolutionAttrs{Name: l.Name, Type: "CNAME", Value: l.Target}))
			}
		}
	}
	seen := map[netip.Addr]bool{}
	for _, res := range []egress.DNSResult{a, aaaa} {
		for _, addr := range addrsOf(res) {
			if seen[addr] {
				continue
			}
			seen[addr] = true
			typ := "AAAA"
			if addr.Is4() {
				typ = "A"
			}
			obs = append(obs,
				kinds.Resolution.Obs(name+"|"+typ+"|"+addr.String(), kinds.ResolutionAttrs{Name: name, Type: typ, Value: addr.String()}),
				kinds.IP.Obs(addr.String()))
		}
	}
	if len(seen) == 0 {
		obs = append(obs, kinds.Unresolved.Obs(name, kinds.UnresolvedAttrs{RCode: rcodeName(a, aaaa)}))
	}
	return obs, nil
}

// rcodeName explains why a name has no address: NXDOMAIN if the name does not
// exist, SERVFAIL if either query failed at the resolver, otherwise NODATA.
func rcodeName(a, aaaa egress.DNSResult) string {
	switch {
	case a.RCode == egress.RCodeNXDomain:
		return "NXDOMAIN"
	case a.RCode == egress.RCodeServFail || aaaa.RCode == egress.RCodeServFail:
		return "SERVFAIL"
	}
	return "NODATA"
}
