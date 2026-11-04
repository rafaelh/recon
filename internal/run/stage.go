package run

import (
	"context"
	"errors"
	"iter"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/rafaelh/recon/internal/config"
	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/inventory"
	"github.com/rafaelh/recon/internal/scope"
	"github.com/rafaelh/recon/internal/store"
)

// Contact says whom a stage talks to. It is single-valued: a stage with mixed
// behaviour is split into separate stages (egress.Clients only carries Target
// clients to stages whose Contact is Target).
type Contact int

const (
	ThirdParty Contact = iota
	Target
)

// Check is one unit of work. Key must encode every input and setting that
// changes the work done (for example "203.0.113.5:8080", or
// "https://a.example.com|depth=2|pages=100"), so changing such a setting
// creates new checks instead of silently reusing old results.
type Check struct {
	Key   string
	Input any
}

// Observation is a fact a check found. Discovered entities are observations of
// kind hostname, root or netblock; scope classifies them (in scope, candidate
// or excluded), so stages never implement candidate or exclusion handling.
type Observation struct {
	Kind, Key string
	Attrs     map[string]any
}

// ErrAbortStage, wrapped in a check's error, fails that check and every
// remaining check of the stage for this run without sending them.
var ErrAbortStage = errors.New("abort stage")

// Env is what a stage sees when deciding whether it can run.
type Env struct {
	Settings   config.Settings
	Passive    bool
	Authorised bool
}

// Key returns the configured API key for a source.
func (e Env) Key(source string) (config.Secret, bool) {
	k, ok := e.Settings.Keys[strings.ToLower(source)]
	return k, ok && k.Reveal() != ""
}

// Stage is one discovery stage.
//
// Run reports negative results (closed port, NXDOMAIN, no HTTP service, a
// policy refusal) as observations or as no observations: they are completed
// checks. A returned error means a transient failure (timeout, rate limit,
// source unavailable): the check is not recorded, is not retried in the same
// run, is retried on every later run, and is counted as failed.
type Stage interface {
	Name() string // listed in --help, accepted by --redo
	Contact() Contact
	Sources() []string // third-party host patterns, e.g. "stat.ripe.net", "*.s3.amazonaws.com"
	Configured(Env) (ok bool, reason string)
	Checks(ctx context.Context, v View) iter.Seq2[Check, error]
	Run(ctx context.Context, c Check, e egress.Clients) ([]Observation, error)
}

// recordCache holds the records a View has read, for one stage pass (D28).
type recordCache struct {
	mu sync.Mutex
	m  map[string][]store.Record
}

// View gives a stage read access to the store and the current Scope. It
// caches the records it reads for its lifetime, one stage pass, so callers must
// not modify the returned slices.
type View struct {
	r     *Runner
	sc    *scope.Scope
	inv   *inventory.Inventory
	cache *recordCache
}

// Scope is the Scope built at the start of the current pass.
func (v View) Scope() *scope.Scope { return v.sc }

// Settings are the run's settings.
func (v View) Settings() config.Settings { return v.r.cfg.Settings }

// Inputs are the engagement's stored scope inputs and exclusions.
func (v View) Inputs() input.Parsed { return v.r.inputs }

// Records returns the current records of a kind.
func (v View) Records(kind string) []store.Record {
	if v.cache != nil {
		v.cache.mu.Lock()
		defer v.cache.mu.Unlock()
		if recs, ok := v.cache.m[kind]; ok {
			return recs
		}
	}
	out, err := v.r.currentRecords(kind)
	if err != nil {
		v.r.warn("reading %s records: %v", kind, err)
		return nil
	}
	if v.cache != nil {
		v.cache.m[kind] = out
	}
	return out
}

// InScopeHostnames returns the current in-scope hostname records, sorted. It is
// not wildcard-aware: use ProbeHostnames for anything that contacts a name.
func (v View) InScopeHostnames() []string {
	var out []string
	for _, rec := range v.Records("hostname") {
		if v.sc.ClassifyHost(rec.Key).Class == scope.InScope {
			out = append(out, rec.Key)
		}
	}
	return out
}

// ResolvableHostnames are the names the resolve stage looks up: in-scope and
// excluded hostnames (exclusion by resolved address needs their addresses) and
// the input roots, never candidates. Sorted.
func (v View) ResolvableHostnames() []string {
	set := map[string]bool{}
	add := func(h string) {
		if v.sc.ClassifyHost(h).Class != scope.Candidate {
			set[input.NormaliseHost(h)] = true
		}
	}
	for _, rec := range v.Records("hostname") {
		add(rec.Key)
	}
	for _, root := range v.Inputs().Roots {
		add(root)
	}
	return slices.Sorted(maps.Keys(set))
}

// ProbeHostnames are the names later stages may probe over HTTP: resolved,
// in-scope, not excluded, not wildcard-only, plus one representative for each
// wildcard zone. InScopeHostnames is not wildcard-aware; web stages must use this.
func (v View) ProbeHostnames() []string { return v.inv.ProbeHostnames(v.sc) }

// ProviderHosts are the in-scope names on shared provider infrastructure, with
// Resolves=false for chains that dangle. Spec 5's takeover checks read it.
func (v View) ProviderHosts() []inventory.ProviderHost { return v.inv.ProviderHosts(v.sc) }

// Seeds are the hostnames the generator stage derives names from (D14): never
// names only the generator itself observed.
func (v View) Seeds(generator string) []string { return v.inv.Seeds(v.sc, generator) }
