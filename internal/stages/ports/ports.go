// Package ports is the ports stage: it finds which of the configured TCP ports
// the target's own addresses accept connections on, connecting only as any
// client would (Spec 4).
package ports

import (
	"context"
	"fmt"
	"iter"
	"net/netip"
	"slices"
	"strconv"

	"github.com/rafaelh/recon/internal/config"
	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/run"
)

// Ports completes a TCP handshake to every port-eligible address on every
// configured port and records the open ones with any banner sent unprompted.
type Ports struct{}

// New returns the ports stage.
func New() *Ports { return &Ports{} }

func (*Ports) Name() string         { return "ports" }
func (*Ports) Contact() run.Contact { return run.Target }
func (*Ports) Sources() []string    { return nil }

// Configured is false with no ports to check. Passive mode and the
// authorisation are gated by the runner for every Target stage.
func (*Ports) Configured(e run.Env) (bool, string) {
	if len(e.Settings.Ports) == 0 {
		return false, "no ports"
	}
	return true, ""
}

// Workers is --port-concurrency: a silent port costs the whole connect
// timeout, so the sweep needs far more workers than other stages (Spec 4 D8).
func (*Ports) Workers(s config.Settings) int { return s.PortConcurrency }

// Checks yields one check per eligible address and port, port by port. The
// transport rate-limits each address, so the order keeps every worker off the
// same host (D4).
func (*Ports) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		addrs := eligible(ctx, v)
		for _, port := range v.Settings().Ports {
			for _, a := range addrs {
				if ctx.Err() != nil {
					return
				}
				ap := netip.AddrPortFrom(a, uint16(port))
				if !yield(run.Check{Key: ap.String(), Input: ap}, nil) {
					return
				}
			}
		}
	}
}

// eligible lists the addresses to check, built once per Checks call (D2): every
// distinct address of the in-scope IPv4 netblocks, then the other found
// addresses (hostname-resolved, or IPv6 inside an in-scope netblock), keeping
// those the single eligibility decision allows.
func eligible(ctx context.Context, v run.View) []netip.Addr {
	sc := v.Scope()
	var out []netip.Addr
	for a := range sc.IPv4Addrs() {
		if ctx.Err() != nil {
			return nil
		}
		if v.PortEligible(a) {
			out = append(out, a)
		}
	}
	var found []netip.Addr
	for _, rec := range v.Records(kinds.IP) {
		a, err := netip.ParseAddr(rec.Key)
		if err != nil {
			continue
		}
		// IPv4 netblock addresses were all decided above.
		if a = a.Unmap(); !a.Is4() || !sc.InScopeIP(a) {
			found = append(found, a)
		}
	}
	slices.SortFunc(found, netip.Addr.Compare)
	found = slices.Compact(found)
	unknown := 0
	for _, a := range found {
		switch {
		case v.PortEligible(a):
			out = append(out, a)
		case !v.OwnerKnown(a):
			// Held back, not refused, if it would be eligible with a known,
			// dedicated owner: it is checked once its owner is known.
			if ok, _, _ := sc.PortEligible(a, func(netip.Addr) (bool, bool) { return false, true }); ok {
				unknown++
			}
		}
	}
	if unknown > 0 {
		v.Warn("ports: %d address(es) skipped because their owner is unknown", unknown)
	}
	return out
}

// Run connects. Open is an open_port observation; Closed and Filtered are
// completed checks with nothing found. Refused cannot happen for a check the
// stage yielded (the policy is built from the same scope and inventory), so it
// is a failure rather than a result that would permanently skip an address that
// later becomes eligible (D5).
func (*Ports) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	ap := c.Input.(netip.AddrPort)
	res, err := e.TCP.Connect(ctx, ap.Addr(), int(ap.Port()))
	if err != nil {
		return nil, err
	}
	switch r := res.(type) {
	case egress.Open:
		return []run.Observation{kinds.OpenPort.Obs(c.Key, kinds.OpenPortAttrs{
			IP: ap.Addr().String(), Port: int(ap.Port()), Banner: encodeBanner(r.Banner),
		})}, nil
	case egress.Closed, egress.Filtered:
		return nil, nil
	case egress.Refused:
		return nil, fmt.Errorf("%s refused: %s", c.Key, r.Reason)
	}
	return nil, fmt.Errorf("%s: unexpected result %T", c.Key, res)
}

// encodeBanner escapes the banner so it is lossless for binary greetings and
// invalid UTF-8, and readable for text. strconv.Unquote reverses it when the
// text is wrapped in double quotes again (D6).
func encodeBanner(b []byte) string {
	q := strconv.Quote(string(b))
	return q[1 : len(q)-1]
}
