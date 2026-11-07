package dns

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"iter"
	"maps"
	"net/netip"
	"slices"

	"github.com/rafaelh/recon/internal/dnsname"
	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/scope"
)

// Wildcard probes each parent zone with two random labels. It records the zone's
// answers; whether a name is wildcard-only is computed on read (inventory).
type Wildcard struct {
	base
	label func() string
}

// NewWildcard returns the wildcard stage. label supplies the probe labels
// (default: 16 random hex characters), injectable for tests.
func NewWildcard(label func() string) *Wildcard {
	if label == nil {
		label = randomLabel
	}
	return &Wildcard{base{"wildcard"}, label}
}

func randomLabel() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

// Checks yields one check per zone: every input root and every parent of a
// resolved in-scope name, down to its registrable domain.
func (*Wildcard) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		zones := map[string]bool{}
		for _, r := range v.Inputs().Roots {
			zones[input.NormaliseHost(r)] = true
		}
		for _, rec := range v.Records(kinds.Resolution) {
			name := input.NormaliseHost(kinds.Resolution.Attrs(rec).Name)
			if v.Scope().ClassifyHost(name).Class != scope.InScope {
				continue
			}
			for _, p := range dnsname.Parents(name) {
				zones[p] = true
			}
		}
		// A sub-root's parents are not ours to probe.
		maps.DeleteFunc(zones, func(z string, _ bool) bool { return v.Scope().ClassifyHost(z).Class != scope.InScope })
		for _, z := range slices.Sorted(maps.Keys(zones)) {
			if !yield(run.Check{Key: z, Input: z}, nil) {
				return
			}
		}
	}
}

// Run queries two random labels under the zone, for A and AAAA. If any answer,
// it records the zone's addresses and the first CNAME target.
func (w *Wildcard) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	zone := c.Key
	var addrs []netip.Addr
	cname := ""
	answered := false
	var servfail error
	l1, l2 := w.label(), w.label()
	for l2 == l1 {
		l2 = w.label()
	}
	for _, label := range []string{l1, l2} {
		for _, qt := range []uint16{egress.TypeA, egress.TypeAAAA} {
			res, err := lookup(ctx, e, label+"."+zone, qt)
			if err != nil {
				return nil, err
			}
			if res.RCode == egress.RCodeServFail && servfail == nil {
				servfail = fmt.Errorf("%s.%s: resolver answered SERVFAIL", label, zone)
			}
			if len(res.CNAMEs) > 0 || len(res.Answers) > 0 {
				answered = true
			}
			if len(res.CNAMEs) > 0 && cname == "" {
				cname = res.CNAMEs[0].Target
			}
			addrs = append(addrs, addrsOf(res)...)
		}
	}
	// A failed probe proves nothing: recording "no wildcard" would let every
	// name under a real wildcard through, so unless another probe answered, the
	// check fails and is retried next run.
	if !answered {
		return nil, servfail
	}
	return []run.Observation{kinds.Wildcard.Obs(zone, kinds.WildcardAttrs{Addrs: sortedStrings(addrs), CNAME: cname})}, nil
}
