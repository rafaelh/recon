package dns

import (
	"context"
	"iter"
	"net/netip"
	"sort"

	"github.com/rafaelh/recon/internal/dnsname"
	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/input"
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
		var found []string
		for _, rec := range v.Records("ip") {
			if a, err := netip.ParseAddr(rec.Key); err == nil && !a.Unmap().Is4() && sc.InScopeIP(a) {
				found = append(found, a.String())
			}
		}
		sort.Strings(found)
		for _, s := range found {
			if !yield(run.Check{Key: s, Input: netip.MustParseAddr(s)}, nil) {
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
			run.Observation{Kind: "hostname", Key: host},
			run.Observation{Kind: "ip", Key: addr.String()},
			run.Observation{Kind: "ip_hostname", Key: addr.String() + "|" + host,
				Attrs: map[string]any{"ip": addr.String(), "hostname": host, "source": "rdns"}})
	}
	return obs, nil
}
