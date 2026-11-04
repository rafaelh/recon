// Package dns has the stages that talk DNS through the public resolvers:
// resolve, wildcard, permutations, rdns and ipowner. All are ThirdParty
// stages, so all run under --passive.
package dns

import (
	"context"
	"fmt"
	"net/netip"
	"slices"

	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/run"
)

// base is the contract shared by the DNS stages: no third-party hosts, always configured.
type base struct{ name string }

func (b base) Name() string                    { return b.name }
func (base) Contact() run.Contact              { return run.ThirdParty }
func (base) Sources() []string                 { return nil }
func (base) Configured(run.Env) (bool, string) { return true, "" }

// lookup runs one query. Anything that is not a DNS answer is an error: a
// timeout is a transient failure, never a result.
func lookup(ctx context.Context, e egress.Clients, name string, qtype uint16) (egress.DNSResult, error) {
	res, err := e.DNS.Query(ctx, name, qtype)
	if err != nil {
		return res, fmt.Errorf("%s: %w", name, err)
	}
	return res, nil
}

func addrsOf(res egress.DNSResult) []netip.Addr {
	var out []netip.Addr
	for _, a := range res.Answers {
		if a.Type != "A" && a.Type != "AAAA" {
			continue
		}
		if addr, err := netip.ParseAddr(a.Value); err == nil {
			out = append(out, addr.Unmap())
		}
	}
	return out
}

func sortedStrings(addrs []netip.Addr) []string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}
	slices.Sort(out)
	return slices.Compact(out)
}
