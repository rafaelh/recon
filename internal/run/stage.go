package run

import (
	"context"
	"errors"
	"iter"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/rafaelh/recon/internal/cloudstorage"
	"github.com/rafaelh/recon/internal/config"
	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/findings"
	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/inventory"
	"github.com/rafaelh/recon/internal/kinds"
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

// Observation is a fact a check found, made with a kind's handle (for example
// kinds.Resolution.Obs). Discovered entities are observations of kind
// hostname, root or netblock; scope classifies them (in scope, candidate or
// excluded), so stages never implement candidate or exclusion handling.
type Observation = store.Obs

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

// WorkerCounter is implemented by a stage that needs a different number of
// workers from Settings.Concurrency (the ports stage, whose checks are slow).
type WorkerCounter interface {
	Workers(config.Settings) int
}

// CandidateExempt is implemented by a stage whose third-party sources include
// provider endpoints that a redirect may have recorded as candidate hostnames
// (Azure storage accounts). Hosts matching these source patterns skip only the
// refusal of candidates; an in-scope or excluded host is still refused.
type CandidateExempt interface {
	CandidateExemptSources() []string
}

// Retiring is implemented by a stage whose check keys carry a hash of the
// entry a check applies (a fingerprint, a sensitive-path signature, the DKIM
// selector list). After every pass that enumerated cleanly, the runner retires
// its completed checks that it no longer yields (Store.Retire): evidence from a
// superseded check stops being current instead of outliving the edit.
type Retiring interface {
	RetiresUnlistedChecks()
}

// recordCache holds the records a View has read, for one stage pass (D28).
type recordCache struct {
	mu    sync.Mutex
	m     map[string][]store.Record
	hosts map[netip.Addr][]string // address -> probe hostnames, built on first use
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

// Warn reports a problem that does not fail a check, such as a stage running
// with reduced capability. It is shown only with --verbose, like other warnings.
func (v View) Warn(format string, a ...any) { v.r.warn(format, a...) }

// Settings are the run's settings.
func (v View) Settings() config.Settings { return v.r.cfg.Settings }

// Inputs are the engagement's stored scope inputs and exclusions.
func (v View) Inputs() input.Parsed { return v.r.inputs }

// Records returns the current records of a kind; decode them with its handle.
func (v View) Records(k kinds.Named) []store.Record {
	kind := k.Name()
	if v.cache != nil {
		v.cache.mu.Lock()
		defer v.cache.mu.Unlock()
		if recs, ok := v.cache.m[kind]; ok {
			return recs
		}
	}
	out, err := v.r.currentRecords(k)
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
	for _, rec := range v.Records(kinds.Hostname) {
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
	for _, rec := range v.Records(kinds.Hostname) {
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

// SaaSServed reports whether a host (a name or an IP literal) is served by a
// third-party SaaS platform, by CNAME chain, address ASN or address range.
func (v View) SaaSServed(host string) bool { return v.inv.SaaSServed(host) }

// StorageRefs are the buckets and containers in-scope names and pages point at,
// sorted. A bucket with a reference is attributed.
func (v View) StorageRefs() []cloudstorage.Reference {
	return findings.References(findings.Input{Scope: v.sc, Inv: v.inv, Records: v.Records})
}

// Seeds are the hostnames the generator stage derives names from (D14): never
// names only the generator itself observed.
func (v View) Seeds(generator string) []string { return v.inv.Seeds(v.sc, generator) }

// OpenPort is a current open_port record: Spec 4's port stage emits one per
// open port, keyed by netip.AddrPort.String(), with an unprompted banner if any.
type OpenPort struct {
	Addr   netip.AddrPort
	Banner string
}

// OpenPorts returns the current open_port records, sorted by address and port.
// A record whose key is not an address and port is skipped.
func (v View) OpenPorts() []OpenPort {
	var out []OpenPort
	for _, rec := range v.Records(kinds.OpenPort) {
		if ap, err := netip.ParseAddrPort(rec.Key); err == nil {
			out = append(out, OpenPort{Addr: netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), Banner: rec.Str("banner")})
		}
	}
	slices.SortFunc(out, func(a, b OpenPort) int { return strings.Compare(a.Addr.String(), b.Addr.String()) })
	return out
}

// PortEligible reports whether the address may be port-checked: the decision
// egress enforces and ips.csv reports.
func (v View) PortEligible(a netip.Addr) bool { return v.inv.PortEligible(a, v.sc) }

// OwnerKnown reports whether anything is known about who owns the address.
func (v View) OwnerKnown(a netip.Addr) bool { return v.inv.OwnerKnown(a, v.sc) }

// HostsFor returns the ProbeHostnames that resolve to the address, sorted.
func (v View) HostsFor(a netip.Addr) []string {
	build := func() map[netip.Addr][]string {
		idx := map[netip.Addr][]string{}
		for _, name := range v.ProbeHostnames() {
			for _, addr := range v.inv.Addrs()[name] {
				if l := idx[addr]; len(l) == 0 || l[len(l)-1] != name {
					idx[addr] = append(l, name)
				}
			}
		}
		return idx
	}
	if v.cache == nil {
		return build()[a.Unmap()]
	}
	v.cache.mu.Lock()
	defer v.cache.mu.Unlock()
	if v.cache.hosts == nil {
		v.cache.hosts = build()
	}
	return v.cache.hosts[a.Unmap()]
}
