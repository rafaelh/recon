package dns

import (
	"context"
	"iter"
	"net/netip"

	"github.com/rafaelh/recon/internal/dnsname"
	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/run"
)

// RDNS looks up PTR records for every address of an in-scope IPv4 netblock
// (the full sweep, already limited by the runner's netblock guard) and for every
// found address inside an in-scope netblock, which is how IPv6 is covered.
type RDNS struct{ base }

// NewRDNS returns the rdns stage.
func NewRDNS() *RDNS { return &RDNS{base{"rdns"}} }

// Checks yields one check per address.
func (*RDNS) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		sc := v.Scope()
		for a := range sc.IPv4Addrs() {
			if !yield(run.Check{Key: a.String(), Input: a}, nil) {
				return
			}
		}
		// IPv4 netblock addresses were all yielded above.
		for _, a := range v.IPs(func(a netip.Addr) bool { return !a.Is4() && sc.InScopeIP(a) }) {
			if !yield(run.Check{Key: a.String(), Input: a}, nil) {
				return
			}
		}
	}
}

// Run queries the PTR record. No answer is a completed check.
func (*RDNS) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	addr := c.Input.(netip.Addr)
	res, err := lookup(ctx, e, dnsname.ReverseName(addr), egress.TypePTR)
	if err != nil {
		return nil, err
	}
	var obs []run.Observation
	seen := map[string]bool{}
	for _, a := range res.Answers {
		if a.Type != "PTR" {
			continue
		}
		host := input.NormaliseHost(a.Value)
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		obs = append(obs,
			kinds.Hostname.Obs(host, kinds.HostnameAttrs{}),
			kinds.IP.Obs(addr.String()),
			kinds.IPHostname.Obs(addr.String()+"|"+host, kinds.IPHostnameAttrs{IP: addr.String(), Hostname: host, Source: "rdns"}))
	}
	return obs, nil
}
