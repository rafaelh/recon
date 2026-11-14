package run

import (
	"fmt"
	"strings"

	"github.com/rafaelh/recon/internal/candidates"
	"github.com/rafaelh/recon/internal/config"
	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/inventory"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/scope"
	"github.com/rafaelh/recon/internal/store"
)

// DeriveInput is what a deriver reads: the current Scope and Inventory, the
// settings, the engagement's inputs, the date, and the store through the
// records of a kind (current or not) and the completed checks observing them.
type DeriveInput struct {
	Scope     *scope.Scope
	Inv       *inventory.Inventory
	Settings  config.Settings
	Inputs    input.Parsed
	Today     string
	Records   func(kinds.Named) []store.Record
	Observers func(kinds.Named) map[string][]store.Observer
}

// deriver computes records from other records, like the findings are, and
// stores them as the observations of a single check "derived" of the
// pseudo-stage name. A record it no longer emits loses its only observation, so
// it stops being current. It runs after every stage that did work and before
// every render, and is skipped while the version of each kind in reads, the
// inputs and the date are unchanged. A deriver must read nothing else, and
// writes only records of its kind writes, which the findings never read.
type deriver struct {
	name   string
	reads  []kinds.Named
	writes kinds.Named
	derive func(DeriveInput) []store.Obs

	sig, stored string // what it was last derived from, and the date and records last stored
}

// derivers are the derived records other than the findings (which depend on
// every evidence kind, and whose derivation also returns the storage
// attribution the render needs; see deriveFindings).
func (r *Runner) newDerivers() []*deriver {
	return []*deriver{
		{name: "candidate-rank", reads: scopeKinds, writes: kinds.CandidateRank, derive: r.rankCandidates},
	}
}

// derive derives the findings and then the other derived records. Every place
// that derives calls it, so that a new derivation cannot be missed at one of them.
func (r *Runner) derive() error {
	if err := r.deriveFindings(); err != nil {
		return err
	}
	return r.deriveRecords()
}

// deriveRecords runs the derivers whose inputs have changed.
func (r *Runner) deriveRecords() error {
	sc, inv := r.sc.Load(), r.inv.Load()
	if sc == nil || inv == nil {
		return nil
	}
	for _, d := range r.derivers {
		var b strings.Builder
		for _, k := range d.reads {
			fmt.Fprintf(&b, "%s=%d;", k.Name(), r.st.KindVersion(k.Name()))
		}
		fmt.Fprintf(&b, "%s;%v", r.today(), r.inputs)
		sig := b.String()
		if sig == d.sig {
			continue
		}
		var readErr error
		note := func(err error) {
			if err != nil && readErr == nil {
				readErr = err
			}
		}
		obs := d.derive(DeriveInput{Scope: sc, Inv: inv, Settings: r.cfg.Settings, Inputs: r.inputs, Today: r.today(),
			Records: func(k kinds.Named) []store.Record {
				recs, err := r.records(k.Name())
				note(err)
				return recs
			},
			Observers: func(k kinds.Named) map[string][]store.Observer {
				m, err := r.st.Observers(k.Name())
				note(err)
				return m
			}})
		if readErr != nil {
			return readErr
		}
		// Storing the same records again on the same day changes nothing.
		stored := fmt.Sprint(r.today(), obs)
		if stored != d.stored {
			r.st.Complete(d.name, "derived", obs)
			if err := r.st.Flush(); err != nil {
				return err
			}
			d.stored = stored
		}
		d.sig = sig
	}
	return nil
}

// evidence is what one completed check contributes to a candidate it observes:
// the stage's own account of its source and item if it gives one (Evidencer),
// else the stage and the check key.
func (r *Runner) evidence(stage, check string) candidates.Evidence {
	if e, ok := r.evidencers[stage]; ok {
		source, item := e.Evidence(check)
		return candidates.Evidence{Source: source, Item: item}
	}
	return candidates.Evidence{Source: stage, Item: check}
}

// rankCandidates ranks every candidate from the completed checks that observe
// it. A candidate root also counts the evidence of the candidate hostnames
// under it, so that stages that report roots and stages that report hostnames
// can corroborate each other; the hostnames keep their own rank. A candidate
// that is no longer current, or whose only support awaits a redo, keeps the
// rank it last had.
func (r *Runner) rankCandidates(in DeriveInput) []store.Obs {
	vis := kinds.NewVisibility(in.Scope, in.Inv)
	last := map[string]kinds.CandidateRankAttrs{} // by rank key
	for _, rec := range in.Records(kinds.CandidateRank) {
		if rec.Current {
			last[rec.Key] = kinds.CandidateRank.Attrs(rec)
		}
	}

	type candidate struct {
		typ, value string
		current    bool
		evidence   []candidates.Evidence
		own        int // the evidence of its own completed checks, before any roll-up
	}
	var all []*candidate
	roots := map[string]*candidate{} // current candidate roots, by value
	var hostnames []*candidate
	for _, kind := range kinds.CandidateKinds {
		observers := in.Observers(kind)
		for _, rec := range in.Records(kind) {
			if vis.Category(kind, rec) != kinds.Candidates {
				continue
			}
			c := &candidate{typ: kind.Name(), value: rec.Key, current: rec.Current}
			for _, o := range observers[rec.Key] {
				c.evidence = append(c.evidence, r.evidence(o.Stage, o.CheckKey))
			}
			c.own = len(c.evidence)
			all = append(all, c)
			if !c.current {
				continue
			}
			switch kind.Name() {
			case kinds.Root.Name():
				roots[rec.Key] = c
			case kinds.Hostname.Name():
				hostnames = append(hostnames, c)
			}
		}
	}
	// A hostname's evidence counts for every candidate root above it (or equal to it).
	for _, h := range hostnames {
		for name := h.value; ; {
			if c, ok := roots[name]; ok {
				c.evidence = append(c.evidence, h.evidence...)
			}
			_, rest, found := strings.Cut(name, ".")
			if !found {
				break
			}
			name = rest
		}
	}

	var obs []store.Obs
	for _, c := range all {
		key := kinds.CandidateRankKey(c.typ, c.value)
		attrs, ok := last[key]
		// A current candidate with no evidence of its own is observed only by
		// checks a redo has forgotten and that have not run again (evidence
		// rolled up from hostnames does not make a root current): it keeps its
		// last rank until they do, so that a candidate they no longer find
		// shows the rank it had while supported.
		if c.current && (c.own > 0 || !ok) {
			rank := candidates.Score(c.evidence, in.Inputs.Orgs)
			attrs = kinds.CandidateRankAttrs{Type: c.typ, Value: c.value, Sources: strings.Join(rank.Sources, ";"),
				EvidenceCount: rank.Count, Confidence: string(rank.Confidence), Current: true}
		} else if !ok {
			continue // never ranked, and there is nothing to keep
		}
		attrs.Current = c.current
		obs = append(obs, kinds.CandidateRank.Obs(key, attrs))
	}
	return obs
}
