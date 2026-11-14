package dns

import (
	"context"
	"fmt"
	"iter"
	"slices"
	"strings"

	"github.com/rafaelh/recon/internal/config"
	"github.com/rafaelh/recon/internal/dnsname"
	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/run"
)

// Permutations resolves permutations of the labels found by other stages plus a
// wordlist. Only names that exist are emitted; resolve then does A/AAAA.
// It never generates from its own output: see inventory.Seeds.
type Permutations struct{ base }

// NewPermutations returns the permutations stage.
func NewPermutations() *Permutations { return &Permutations{base{"permutations"}} }

// Configured is false when permutations are turned off.
func (*Permutations) Configured(e run.Env) (bool, string) {
	if !e.Settings.Permutations.Enabled {
		return false, "disabled"
	}
	return true, ""
}

// Budget is the most names the stage generates in one run.
func (*Permutations) Budget(s config.Settings) int { return s.Permutations.MaxNames }

// Checks yields a root check per input root and then a seed check per seed, each
// in name order, so the budget reaches every root before any seed. A check costs
// the names it will query. Both keys include the wordlist hash, and seed keys the
// cap, so changing either redoes the work. A root, or a seed whose parent, is a
// zone already known to be a wildcard is not yielded: every name under it exists.
// For the same reason a seed check leaves out each generated name directly under
// a wildcard zone (the seed may be one itself, or a join may land under one).
func (p *Permutations) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		s := v.Settings()
		hash := s.WordlistHash
		words := make([]string, len(s.WordlistWords))
		for i, w := range s.WordlistWords {
			words[i] = strings.ToLower(w)
		}
		// A word that is not a valid label gives no name under any root.
		valid := slices.DeleteFunc(slices.Clone(words), func(w string) bool { return !dnsname.ValidLabel(w) })
		for _, root := range slices.Sorted(slices.Values(v.Inputs().Roots)) {
			if v.WildcardZone(dnsname.Normalise(root)) {
				continue
			}
			names := rootNames(root, valid)
			if !yield(run.Check{Key: fmt.Sprintf("root|%s|wl=%s", root, hash), Input: names, Cost: len(names)}, nil) {
				return
			}
		}
		// Seeds are never directly under a wildcard zone: the view leaves them out.
		for _, seed := range v.Seeds(p.Name()) {
			names := slices.DeleteFunc(seedNames(seed, words, s.Permutations.MaxPerSeed), func(n string) bool {
				_, parent, _ := strings.Cut(n, ".")
				return v.WildcardZone(parent)
			})
			c := run.Check{Key: fmt.Sprintf("seed|%s|wl=%s|max=%d", seed, hash, s.Permutations.MaxPerSeed), Input: names, Cost: len(names)}
			if !yield(c, nil) {
				return
			}
		}
	}
}

// Run queries each of the check's names once for A. A CNAME means
// the name exists even if its chain dangles (NXDOMAIN), which is a takeover
// candidate. Otherwise anything but NXDOMAIN means the name exists, except
// SERVFAIL, which proves nothing. A timeout fails the whole check, which is
// redone on the next run.
func (p *Permutations) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	var obs []run.Observation
	for _, n := range c.Input.([]string) {
		res, err := lookup(ctx, e, n, egress.TypeA)
		if err != nil {
			return nil, err
		}
		if len(res.CNAMEs) == 0 && (res.RCode == egress.RCodeNXDomain || res.RCode == egress.RCodeServFail) {
			continue
		}
		obs = append(obs, kinds.Hostname.Obs(n, kinds.HostnameAttrs{}))
	}
	return obs, nil
}

// rootNames are the names a root check queries: each word directly under the root.
func rootNames(root string, words []string) []string {
	out := make([]string, len(words))
	for i, w := range words {
		out[i] = w + "." + root
	}
	return out
}

// seedNames are the names a seed check queries: the permutations of the seed's
// label under its parent. Checks prices the check with their number, and Run
// queries them, so the cost is exact.
func seedNames(seed string, words []string, max int) []string {
	label, parent, _ := strings.Cut(seed, ".")
	var out []string
	for _, v := range dnsname.Permute(label, words, max) {
		out = append(out, v+"."+parent)
	}
	return out
}
