package dns

import (
	"context"
	"fmt"
	"iter"
	"strings"

	"github.com/rafaelh/recon/internal/dnsname"
	"github.com/rafaelh/recon/internal/egress"
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

// Checks yields a root check per input root and a seed check per seed. Both keys
// include the wordlist hash, and seed keys the cap, so changing either redoes the work.
func (p *Permutations) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		s := v.Settings()
		hash := s.WordlistHash
		words := make([]string, len(s.WordlistWords))
		for i, w := range s.WordlistWords {
			words[i] = strings.ToLower(w)
		}
		for _, root := range v.Inputs().Roots {
			if !yield(run.Check{Key: fmt.Sprintf("root|%s|wl=%s", root, hash), Input: permInput{kind: "root", name: root, words: words}}, nil) {
				return
			}
		}
		for _, seed := range v.Seeds(p.Name()) {
			c := run.Check{Key: fmt.Sprintf("seed|%s|wl=%s|max=%d", seed, hash, s.Permutations.MaxPerSeed),
				Input: permInput{kind: "seed", name: seed, words: words, max: s.Permutations.MaxPerSeed}}
			if !yield(c, nil) {
				return
			}
		}
	}
}

type permInput struct {
	kind, name string
	words      []string
	max        int
}

// Run generates the check's names and queries each once for A. A CNAME means
// the name exists even if its chain dangles (NXDOMAIN), which is a takeover
// candidate. Otherwise anything but NXDOMAIN means the name exists, except
// SERVFAIL, which proves nothing. A timeout fails the whole check, which is
// redone on the next run.
func (p *Permutations) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	in := c.Input.(permInput)
	var names []string
	switch in.kind {
	case "root":
		names = rootNames(in)
	case "seed":
		label, parent, _ := strings.Cut(in.name, ".")
		for _, v := range dnsname.Permute(label, in.words, in.max) {
			names = append(names, v+"."+parent)
		}
	}
	var obs []run.Observation
	for _, n := range names {
		res, err := lookup(ctx, e, n, egress.TypeA)
		if err != nil {
			return nil, err
		}
		if len(res.CNAMEs) == 0 && (res.RCode == egress.RCodeNXDomain || res.RCode == egress.RCodeServFail) {
			continue
		}
		obs = append(obs, run.Observation{Kind: "hostname", Key: n})
	}
	return obs, nil
}

func rootNames(in permInput) []string {
	var out []string
	for _, w := range in.words {
		if dnsname.ValidLabel(w) {
			out = append(out, w+"."+in.name)
		}
	}
	return out
}
