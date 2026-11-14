// Package run executes stages over an engagement: repeated passes in registry
// order, a worker pool per stage, gating, the netblock guard, redo and the
// stage states shown on the console.
package run

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rafaelh/recon/internal/candidates"
	"github.com/rafaelh/recon/internal/config"
	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/engagement"
	"github.com/rafaelh/recon/internal/fault"
	"github.com/rafaelh/recon/internal/findings"
	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/inventory"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/output"
	"github.com/rafaelh/recon/internal/provider"
	"github.com/rafaelh/recon/internal/report"
	"github.com/rafaelh/recon/internal/scope"
	"github.com/rafaelh/recon/internal/store"
)

// Exit codes.
const (
	ExitOK          = 0
	ExitFatal       = 1
	ExitInvalid     = 2
	ExitNetblock    = 3
	ExitInterrupted = 130
)

// NetblockLimitError is returned when in-scope IPv4 netblocks exceed the limit.
type NetblockLimitError struct{ Count, Limit uint64 }

func (e *NetblockLimitError) Error() string {
	return fmt.Sprintf("in-scope IPv4 netblocks cover %d addresses, over the limit of %d; nothing in them was contacted. Re-run with --allow-large-netblocks to proceed", e.Count, e.Limit)
}

// Config is everything a Runner needs.
type Config struct {
	Engagement          *engagement.Engagement
	Settings            config.Settings
	Stages              []Stage
	Egress              *egress.Egress
	Emitter             report.Emitter
	Files               []output.File
	Clock               func() time.Time
	Passive             bool
	AllowLargeNetblocks bool
	Verbose             bool
	Redo                string
}

// Runner runs the stages.
type Runner struct {
	cfg   Config
	st    *store.Store
	order []string

	inputs input.Parsed
	sc     atomic.Pointer[scope.Scope]
	inv    atomic.Pointer[inventory.Inventory]
	vis    atomic.Pointer[kinds.Visibility] // of sc and inv, for the found lines

	// ranges caches the indexed provider_range records (thousands of rows) as
	// of store KindVersion rangesVer; buildScope runs after every stage.
	ranges    *provider.Ranges
	rangesVer uint64
	scopeSig  string // what the Scope was last built from (see buildScope)

	recMu sync.Mutex
	recs  map[string]recordsCache // the records of each kind read so far (see records)

	mu      sync.Mutex
	failed  map[string]map[string]bool // stage -> check key, failed this run
	stats   map[string]*stageStats
	last    map[string]string // last printed state signature
	counts  map[string]int    // last emitted category counts
	lastTot map[string]int    // category counts computed by the last emitCounts
	aborted map[string]bool

	guarded sync.Map // value+"\x00"+reason already sent to the guard pseudo-stage

	derivedSig     string                          // what the findings were last derived from (see deriveFindings)
	attribution    map[string]findings.StorageAttr // the storage attribution of that derivation
	storedFindings string                          // the date and findings last stored (see deriveFindings)

	derivers   []*deriver           // the derived records other than findings (see deriveRecords)
	evidencers map[string]Evidencer // the stages that account for their own candidate evidence
}

// recordsCache holds the records of a kind, and the current ones among them,
// as of store KindVersion ver.
type recordsCache struct {
	ver       uint64
	all, curr []store.Record
}

// stageStats are a stage's counters. spent is the budget the checks sent this
// run have used (see Budgeted) and deferred the cost of the checks its last
// pass deferred.
type stageStats struct{ attempted, failed, spent, deferred int }

// New creates a Runner.
func New(cfg Config) *Runner {
	r := &Runner{
		cfg: cfg, st: cfg.Engagement.Store(),
		failed: map[string]map[string]bool{}, stats: map[string]*stageStats{},
		last: map[string]string{}, counts: map[string]int{}, aborted: map[string]bool{},
		recs: map[string]recordsCache{},
	}
	r.evidencers = map[string]Evidencer{}
	for _, s := range cfg.Stages {
		r.order = append(r.order, s.Name())
		if e, ok := s.(Evidencer); ok {
			r.evidencers[s.Name()] = e
		}
	}
	r.derivers = r.newDerivers()
	if cfg.Clock == nil {
		r.cfg.Clock = time.Now
	}
	return r
}

func (r *Runner) emit(typ string, fields map[string]any) {
	r.cfg.Emitter.Emit(report.Event{Type: typ, Fields: fields})
}

func (r *Runner) warn(format string, a ...any) {
	if r.cfg.Verbose {
		r.emit("warning", map[string]any{"message": fmt.Sprintf(format, a...)})
	}
}

func (r *Runner) today() string { return r.cfg.Clock().UTC().Format(time.DateOnly) }

// Run executes the engagement and returns the exit code. An error describes a
// fatal condition (exit code 1 or 3) to show the user.
func (r *Runner) Run(ctx context.Context) (int, error) {
	eng := r.cfg.Engagement
	if r.cfg.Redo != "" {
		if err := r.st.Redo(r.cfg.Redo); err != nil {
			return ExitFatal, err
		}
	}
	if err := output.Sweep(eng.Dir()); err != nil {
		return ExitFatal, err
	}
	r.st.OnNew(r.onNewRecord)

	var err error
	if r.inputs, err = eng.Inputs(); err != nil {
		return ExitFatal, err
	}
	r.emit("run_start", map[string]any{
		"engagement": filepath.Base(eng.Dir()),
		"scope": fmt.Sprintf("%d roots, %d orgs, %d asns, %d cidrs, %d exclusions",
			len(r.inputs.Roots), len(r.inputs.Orgs), len(r.inputs.ASNs), len(r.inputs.CIDRs), len(r.inputs.Exclusions)),
		"passive": r.cfg.Passive, "authorised": eng.Acked(),
	})

	code, err := r.passes(ctx)
	if err == nil && code == ExitOK {
		// The final pass has just rendered and counted; nothing has changed since.
		r.emitSummary()
		return code, nil
	}
	if _, rerr := r.render(); rerr != nil && err == nil {
		code, err = ExitFatal, rerr
	}
	return code, err
}

func (r *Runner) passes(ctx context.Context) (int, error) {
	for pass := 1; ; pass++ {
		if err := r.buildScope(); err != nil {
			return exitFor(err), err
		}
		executed := 0
		for _, s := range r.cfg.Stages {
			if ctx.Err() != nil {
				return ExitInterrupted, nil
			}
			n, err := r.runStage(ctx, s, pass == 1)
			if err != nil {
				return ExitFatal, err
			}
			executed += n
			if ctx.Err() != nil {
				return ExitInterrupted, nil
			}
			if n > 0 {
				if err := r.st.Flush(); err != nil {
					return ExitFatal, err
				}
				if err := r.buildScope(); err != nil {
					return exitFor(err), err
				}
				// Findings follow every stage that did work, so a finding's
				// found line is printed as soon as its evidence is stored.
				if err := r.derive(); err != nil {
					return ExitFatal, err
				}
			}
		}
		rendered, err := r.render()
		if err != nil {
			return ExitFatal, err
		}
		r.emitCounts(rendered)
		if ctx.Err() != nil {
			return ExitInterrupted, nil
		}
		if executed == 0 {
			return ExitOK, nil
		}
	}
}

func exitFor(err error) int {
	var nl *NetblockLimitError
	if errors.As(err, &nl) {
		return ExitNetblock
	}
	return ExitFatal
}

// scopeKinds are the kinds buildScope reads.
var scopeKinds = []kinds.Named{kinds.Hostname, kinds.Root, kinds.Netblock, kinds.Resolution, kinds.Wildcard,
	kinds.IP, kinds.IPOwner, kinds.IPHostname, kinds.ProviderRange}

// buildScope builds the Scope and the egress Policy from stored inputs and
// observations, then applies the netblock guard. It does nothing when
// none of them has changed since the last build.
func (r *Runner) buildScope() error {
	eng := r.cfg.Engagement
	in, err := eng.Inputs()
	if err != nil {
		return err
	}
	r.inputs = in
	var b strings.Builder
	for _, k := range scopeKinds {
		fmt.Fprintf(&b, "%s=%d;", k.Name(), r.st.KindVersion(k.Name()))
	}
	fmt.Fprintf(&b, "%v;%v", eng.Acked(), in)
	sig := b.String()
	if sig == r.scopeSig {
		return nil
	}
	var excl []input.Exclusion
	for _, e := range in.Exclusions {
		x, err := input.ParseExclusion(e)
		if err != nil {
			return err
		}
		excl = append(excl, x)
	}
	var blocks []netip.Prefix
	for _, c := range in.CIDRs {
		p, err := input.ParseCIDR(c)
		if err != nil {
			return err
		}
		blocks = append(blocks, p)
	}
	asnBlocks, err := r.asnNetblocks(in)
	if err != nil {
		return err
	}
	for k := range asnBlocks {
		if p, err := netip.ParsePrefix(k); err == nil {
			blocks = append(blocks, p.Masked())
		}
	}
	data, err := r.inventoryData()
	if err != nil {
		return err
	}
	inv := inventory.New(data, provider.Default())
	res := inv.Addrs()
	sc := scope.New(scope.Config{Roots: in.Roots, Netblocks: blocks, Exclusions: excl, Resolutions: res, WildcardOnly: inv.WildcardOnly()})
	r.sc.Store(sc)
	r.inv.Store(inv)
	r.vis.Store(kinds.NewVisibility(sc, inv))

	cands := map[string]bool{}
	roots, err := r.currentRecords(kinds.Root)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(data.Hosts)+len(roots))
	for _, h := range data.Hosts {
		names = append(names, h.Name)
	}
	for _, rec := range roots {
		names = append(names, input.NormaliseHost(rec.Key))
	}
	for _, n := range names {
		if sc.ClassifyHost(n).Class == scope.Candidate {
			cands[n] = true
		}
	}
	var sensitivePaths []string // egress addresses an entry by its index
	for _, e := range r.cfg.Settings.SensitivePathEntries {
		sensitivePaths = append(sensitivePaths, e.Path)
	}
	r.cfg.Egress.SetPolicy(&egress.Policy{
		Scope: sc, Ack: eng.Acked(), Passive: r.cfg.Passive,
		Ports: r.cfg.Settings.Ports, SensitivePaths: sensitivePaths,
		Resolutions: res, Candidates: cands,
		Shared:       inv.Shared,
		OwnerUnknown: func(a netip.Addr) bool { return !inv.OwnerKnown(a, sc) },
		Excluded:     r.guard,
	})

	count := sc.IPv4AddressCount()
	limit := uint64(r.cfg.Settings.NetblockLimit)
	if approved := uint64(eng.NetblockApproved()); approved > limit {
		limit = approved
	}
	if count > limit {
		if !r.cfg.AllowLargeNetblocks {
			return &NetblockLimitError{Count: count, Limit: limit}
		}
		if err := eng.SetNetblockApproved(int(count)); err != nil {
			return err
		}
	}
	r.scopeSig = sig
	return nil
}

// guard records an address that triggered an exclusion at dial time, once per
// distinct value and reason per run.
func (r *Runner) guard(value, reason string) {
	if _, seen := r.guarded.LoadOrStore(value+"\x00"+reason, struct{}{}); seen {
		return
	}
	r.st.Complete("guard", value, []store.Obs{kinds.ExcludedKind.Obs(value, kinds.ExcludedAttrs{Reason: reason})})
}

// asnNetblocks maps each current netblock observed by the asn stage under a
// check for an input ASN to that ASN. It never depends on a mutable attribute.
func (r *Runner) asnNetblocks(in input.Parsed) (map[string]string, error) {
	rows, err := r.st.Observations(kinds.Netblock.Name(), "asn")
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, a := range in.ASNs {
		want[a] = true
	}
	out := map[string]string{}
	for _, row := range rows {
		if want[row.CheckKey] {
			out[row.Key] = row.CheckKey
		}
	}
	return out, nil
}

func (r *Runner) failedSet(stage string) map[string]bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failedLocked(stage)
}

func (r *Runner) failedLocked(stage string) map[string]bool {
	if r.failed[stage] == nil {
		r.failed[stage] = map[string]bool{}
	}
	return r.failed[stage]
}

func (r *Runner) stat(stage string) *stageStats {
	if r.stats[stage] == nil {
		r.stats[stage] = &stageStats{}
	}
	return r.stats[stage]
}

func (r *Runner) gate(s Stage) (bool, string) {
	eng := r.cfg.Engagement
	// Skipped comes before every other reason: it is the operator's choice, and
	// it must not depend on a key, --passive or the authorisation.
	if slices.Contains(r.cfg.Settings.Skip, s.Name()) {
		return false, "skipped"
	}
	if s.Contact() == Target {
		if r.cfg.Passive {
			return false, "passive-only"
		}
		if !eng.Acked() {
			return false, "no authorisation"
		}
	}
	return s.Configured(Env{Settings: r.cfg.Settings, Passive: r.cfg.Passive, Authorised: eng.Acked()})
}

func (r *Runner) setState(name, state, reason string, checks, failed int) {
	sig := fmt.Sprintf("%s|%s|%d|%d", state, reason, checks, failed)
	r.mu.Lock()
	if r.last[name] == sig {
		r.mu.Unlock()
		return
	}
	r.last[name] = sig
	r.mu.Unlock()
	f := map[string]any{"name": name, "state": state}
	if reason != "" {
		f["reason"] = reason
	}
	if state == "done" || state == "failed" {
		f["checks"], f["failed"] = checks, failed
	}
	r.emit("stage", f)
}

// runStage performs one pass of one stage and returns the number of checks attempted.
func (r *Runner) runStage(ctx context.Context, s Stage, first bool) (int, error) {
	name := s.Name()
	if ok, reason := r.gate(s); !ok {
		r.setState(name, "not-configured", reason, 0, 0)
		return 0, nil
	}
	if r.isAborted(name) {
		return 0, nil
	}
	done, err := r.st.Completed(name)
	if err != nil {
		return 0, err
	}
	pend, _ := r.st.PendingRedo()
	redoPending := slices.Contains(pend, name)
	failedSet := r.failedSet(name)
	var exempt []string
	if ce, ok := s.(CandidateExempt); ok {
		exempt = ce.CandidateExemptSources()
	}
	clients := r.cfg.Egress.ClientsWith(name, s.Contact() == Target, s.Sources(), exempt)
	view := View{r: r, sc: r.sc.Load(), inv: r.inv.Load(), cache: &recordCache{m: map[string][]store.Record{}}}

	workers := r.cfg.Settings.Concurrency
	if wc, ok := s.(WorkerCounter); ok {
		workers = wc.Workers(r.cfg.Settings)
	}
	// With no workers the first send on work would block forever.
	workers = max(workers, 1)
	work := make(chan Check)
	var wg sync.WaitGroup
	var attempted, aborted atomic.Int64 // aborted: checks failed by the stage's abort
	runCtx := withWarner(ctx, r.warn)
	// abortFail fails a check because its stage aborted. The stage warns once for
	// all of them (below), not once per check.
	abortFail := func(key, msg string) {
		r.recordFailure(name, key, msg)
		aborted.Add(1)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range work {
				if ctx.Err() != nil {
					continue
				}
				if r.isAborted(name) {
					abortFail(c.Key, "stage aborted earlier in this run")
					attempted.Add(1)
					continue
				}
				fault.PointDetail("in-flight", c.Key)
				obs, err := s.Run(runCtx, c, clients)
				if ctx.Err() != nil {
					continue // in-flight checks are abandoned and redone next run
				}
				attempted.Add(1)
				if errors.Is(err, ErrAbortStage) {
					r.mu.Lock()
					r.aborted[name] = true
					r.mu.Unlock()
					abortFail(c.Key, err.Error())
					continue
				}
				if err != nil {
					r.failCheck(name, c.Key, err.Error())
					continue
				}
				r.st.Complete(name, c.Key, obs)
			}
		}()
	}

	// all holds the keys yielded, in stored (redacted) form like done, to skip a
	// key a stage yields more than once. Only a redo or a retire needs every
	// key; otherwise a completed key is skipped by done and is not kept.
	_, retiring := s.(Retiring)
	keepAll := redoPending || retiring
	all := map[string]struct{}{}
	// A budgeted stage spends its budget on the pending checks in the order it
	// yields them. The first one that would pass it, and every pending one after
	// it, is deferred: not sent, not failed, not attempted. The check is already
	// in all, so a redo or a retire still counts it as valid and its earlier
	// evidence stays current. The first pending check of the run is always taken.
	budget := 0 // 0: the stage is not budgeted
	if b, ok := s.(Budgeted); ok {
		budget = max(b.Budget(r.cfg.Settings), 1)
	}
	r.mu.Lock()
	spent := r.stat(name).spent
	r.mu.Unlock()
	deferredCost := 0
	enumFailed := false
	running := false // whether the stage has been shown as running
produce:
	for c, cerr := range s.Checks(ctx, view) {
		if cerr != nil {
			enumFailed = true
			const enumKey = "(enumeration)"
			r.mu.Lock()
			again := failedSet[enumKey]
			r.mu.Unlock()
			if !again { // counted once per run, like any failed check, so passes still terminate
				r.failCheck(name, enumKey, cerr.Error())
				attempted.Add(1)
			}
			continue
		}
		stored := r.st.CheckKey(c.Key)
		if _, dup := all[stored]; dup { // a stage may yield a key more than once
			continue
		}
		if _, ok := done[stored]; ok {
			if keepAll {
				all[stored] = struct{}{}
			}
			continue
		}
		all[stored] = struct{}{}
		r.mu.Lock()
		skip := failedSet[c.Key]
		r.mu.Unlock()
		if skip {
			continue
		}
		if r.isAborted(name) {
			running = true
			attempted.Add(1)
			abortFail(c.Key, "stage aborted earlier in this run")
			continue
		}
		if budget > 0 {
			cost := max(c.Cost, 1)
			if deferredCost > 0 || (spent > 0 && spent+cost > budget) {
				deferredCost += cost
				continue
			}
			spent += cost
		}
		if !running {
			r.setState(name, "running", "", 0, 0)
			running = true
		}
		select {
		case work <- c:
		case <-ctx.Done():
			break produce
		}
	}
	close(work)
	wg.Wait()
	if ctx.Err() != nil {
		return int(attempted.Load()), nil
	}
	if n := aborted.Load(); n > 0 {
		r.warn("%s: quota spent or key rejected; %d checks will be retried next run", name, n)
	}

	n := int(attempted.Load())
	r.mu.Lock()
	ss := r.stat(name)
	ss.attempted += n
	ss.spent, ss.deferred = spent, deferredCost
	total, failed := ss.attempted, ss.failed
	r.mu.Unlock()
	switch {
	case total > 0 && failed == total:
		r.setState(name, "failed", "", total, failed)
	case total > 0:
		r.setState(name, "done", "", total, failed)
	case first:
		cnt, err := r.st.CompletedCount(name)
		if err != nil {
			return 0, err
		}
		if cnt > 0 {
			r.setState(name, "done-previously", "", 0, 0)
		} else {
			r.setState(name, "done", "", 0, 0)
		}
	}
	// The sweep needs every valid check; after an enumeration error it would
	// delete the observations of checks that were never listed, so the redo
	// stays pending until a pass enumerates cleanly.
	if redoPending && !enumFailed {
		if err := r.st.Flush(); err != nil {
			return n, err
		}
		if err := r.st.FinishRedo(name, all); err != nil {
			return n, err
		}
	}
	// Only completed checks have observations, so there is nothing to retire
	// unless one of them was not yielded this pass.
	if retiring && !enumFailed {
		unlisted := false
		for k := range done {
			if _, ok := all[k]; !ok {
				unlisted = true
				break
			}
		}
		if unlisted {
			if err := r.st.Retire(name, all); err != nil {
				return n, err
			}
		}
	}
	return n, nil
}

func (r *Runner) isAborted(stage string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.aborted[stage]
}

// failCheck records a transient failure and warns about it.
func (r *Runner) failCheck(stage, key, msg string) {
	r.recordFailure(stage, key, msg)
	r.warn("%s check %s failed: %s", stage, key, msg)
}

// recordFailure records a transient failure: not a completion, not retried this run.
func (r *Runner) recordFailure(stage, key, msg string) {
	r.mu.Lock()
	r.failedLocked(stage)[key] = true
	r.stat(stage).failed++
	r.mu.Unlock()
	r.st.Fail(stage, key, msg)
}

// emitCounts emits the category counts that changed. They are counted from the
// snapshot render wrote the files from, with its Visibility, so the totals match
// the files' rows.
func (r *Runner) emitCounts(snap output.Snapshot) {
	totals := snap.Vis.Totals(snap.Records)
	r.lastTot = totals
	for _, k := range slices.Sorted(maps.Keys(totals)) {
		if r.counts[k] != totals[k] {
			r.counts[k] = totals[k]
			r.emit("count", map[string]any{"category": k, "n": totals[k]})
		}
	}
}

func (r *Runner) emitSummary() {
	failed, deferred := map[string]int{}, map[string]int{}
	r.mu.Lock()
	for name, s := range r.stats {
		if s.failed > 0 {
			failed[name] = s.failed
		}
		if s.deferred > 0 {
			deferred[name] = s.deferred
		}
	}
	r.mu.Unlock()
	recs, _ := r.records(kinds.Finding.Name())
	listed := []map[string]any{}
	for _, f := range findings.Headline(recs) {
		listed = append(listed, map[string]any{"category": f.Category, "severity": f.Severity, "target": f.Target, "detail": f.Detail})
	}
	high, medium := r.rankedCandidates()
	for _, c := range high {
		r.emit("candidate", c)
	}
	fields := map[string]any{"totals": r.lastTot, "failed": failed, "deferred": deferred, "findings": listed, "candidates": high}
	if r.cfg.Verbose {
		fields["medium_candidates"] = medium
	}
	r.emit("summary", fields)
}

// rankedCandidates are the current candidates of high and of medium confidence,
// best first, each with the input that promotes it. A candidate that is no
// longer current keeps its rank for candidates.csv but is not listed.
func (r *Runner) rankedCandidates() (high, medium []map[string]any) {
	high, medium = []map[string]any{}, []map[string]any{}
	recs, _ := r.currentRecords(kinds.CandidateRank)
	var ranked []kinds.CandidateRankAttrs
	for _, rec := range recs {
		if a := kinds.CandidateRank.Attrs(rec); a.Current {
			ranked = append(ranked, a)
		}
	}
	entry := func(a kinds.CandidateRankAttrs) candidates.Entry {
		return candidates.Entry{Value: a.Value, Current: true, Confidence: candidates.Confidence(a.Confidence), Count: a.EvidenceCount}
	}
	slices.SortFunc(ranked, func(a, b kinds.CandidateRankAttrs) int {
		return cmp.Or(candidates.Compare(entry(a), entry(b)), strings.Compare(a.Type, b.Type))
	})
	for _, a := range ranked {
		c := map[string]any{"kind": a.Type, "value": a.Value, "sources": a.Sources, "evidence_count": a.EvidenceCount,
			"confidence": a.Confidence, "promote": candidates.Promote(a.Type, a.Value)}
		switch candidates.Confidence(a.Confidence) {
		case candidates.High:
			high = append(high, c)
		case candidates.Medium:
			medium = append(medium, c)
		}
	}
	return high, medium
}

// onNewRecord prints records of Printed kinds the first time the engagement sees them.
func (r *Runner) onNewRecord(kind, key string, attrs map[string]any) {
	if !r.vis.Load().Printed(kind, store.Record{Key: key, Attrs: attrs}) {
		return
	}
	k, _ := kinds.Get(kind)
	f := map[string]any{"category": k.Singular, "value": key}
	if k.Found != nil {
		maps.Copy(f, k.Found(store.Record{Kind: kind, Key: key, Attrs: attrs}))
	}
	if kind == kinds.Finding.Name() {
		fd := findings.FromRecord(store.Record{Key: key, Attrs: attrs})
		f["category"], f["value"] = k.Singular+" "+fd.Category, fd.Target
		if fd.Severity != "" {
			f["severity"] = fd.Severity
		}
	}
	r.emit("found", f)
}

// render writes the output files from the store and returns the snapshot it
// wrote them from: the records of every kind, which it reads so a new kind's
// file can never render empty, and the scope they were filtered by.
func (r *Runner) render() (output.Snapshot, error) {
	if err := r.st.Flush(); err != nil {
		return output.Snapshot{}, err
	}
	// Findings are derived before the files are written on every path that renders,
	// including an interrupt, so the files and the totals never lag the evidence.
	if err := r.derive(); err != nil {
		return output.Snapshot{}, err
	}
	eng := r.cfg.Engagement
	inputs, err := r.st.Inputs()
	if err != nil {
		return output.Snapshot{}, err
	}
	snap := output.Snapshot{Today: r.today(), Inputs: inputs, Records: map[string][]store.Record{}, Scope: r.sc.Load(), Inv: r.inv.Load()}
	for _, k := range kinds.All() {
		recs, err := r.records(k.Name)
		if err != nil {
			return output.Snapshot{}, err
		}
		snap.Records[k.Name] = recs
	}
	snap.Storage = r.attribution // computed with the findings, from the same evidence
	if snap.Scope == nil {
		snap.Scope = scope.New(scope.Config{})
	}
	if snap.Inv == nil {
		snap.Inv = inventory.New(inventory.Data{}, provider.Default())
	}
	snap.Vis = kinds.NewVisibility(snap.Scope, snap.Inv)
	if snap.ASNNetblocks, err = r.asnNetblocks(r.inputs); err != nil {
		return output.Snapshot{}, err
	}
	return snap, output.Render(eng.Dir(), r.cfg.Files, snap)
}

// deriveFindings derives the findings from the evidence and stores them as
// the "finding" records of the pseudo-stage "findings", its single check key
// "derived", like guard does. A finding no longer derived loses its only
// observation, so it becomes not current and keeps its first_seen; a new one
// is printed once by the store's OnNew callback.
func (r *Runner) deriveFindings() error {
	// Nothing Derive reads has changed since the last derivation (a derivation
	// bumps only "finding"), so the findings are already current.
	sig := r.derivationSignature()
	sc, inv := r.sc.Load(), r.inv.Load()
	if sc == nil || inv == nil || sig == r.derivedSig {
		return nil
	}
	var readErr error
	in := findings.Input{Scope: sc, Inv: inv, Settings: r.cfg.Settings, Today: r.today(),
		Records: func(k kinds.Named) []store.Record {
			recs, err := r.records(k.Name())
			if err != nil && readErr == nil {
				readErr = err
			}
			return recs
		},
		Roots: r.inputs.Roots, Orgs: r.inputs.Orgs}
	fs, attribution := findings.DeriveAll(in)
	if readErr != nil {
		return readErr
	}
	obs := make([]store.Obs, len(fs))
	for i, f := range fs {
		obs[i] = kinds.Finding.Obs(f.Key(), f.Attrs)
	}
	// Storing the same findings again on the same day changes nothing.
	stored := fmt.Sprint(r.today(), obs)
	if stored != r.storedFindings {
		r.st.Complete("findings", "derived", obs)
		if err := r.st.Flush(); err != nil {
			return err
		}
		r.storedFindings = stored
	}
	r.derivedSig, r.attribution = sig, attribution
	return nil
}

// records returns every record of a kind, current or not, read again only
// when the kind has changed since the last read. The version is read first, so
// a commit racing the read is re-read next time. Callers must not modify the
// returned slice.
func (r *Runner) records(kind string) ([]store.Record, error) {
	c, err := r.cached(kind)
	return c.all, err
}

func (r *Runner) cached(kind string) (recordsCache, error) {
	ver := r.st.KindVersion(kind)
	r.recMu.Lock()
	c, ok := r.recs[kind]
	r.recMu.Unlock()
	if ok && c.ver == ver {
		return c, nil
	}
	all, err := r.st.Records(kind, r.order)
	if err != nil {
		return recordsCache{}, err
	}
	c = recordsCache{ver: ver, all: all}
	for _, rec := range all {
		if rec.Current {
			c.curr = append(c.curr, rec)
		}
	}
	r.recMu.Lock()
	r.recs[kind] = c
	r.recMu.Unlock()
	return c, nil
}

// derivationSignature changes whenever a record of any kind but the derived
// kinds ("finding" and those the derivers write), the date or the engagement's
// inputs change. The Scope and Inventory are built from nothing else, and the
// settings are fixed for the Runner's life. The findings do not read the
// derived records, so storing them must not derive the findings again.
func (r *Runner) derivationSignature() string {
	derived := map[string]bool{kinds.Finding.Name(): true}
	for _, d := range r.derivers {
		derived[d.writes.Name()] = true
	}
	var b strings.Builder
	for _, k := range kinds.All() {
		if !derived[k.Name] {
			fmt.Fprintf(&b, "%s=%d;", k.Name, r.st.KindVersion(k.Name))
		}
	}
	fmt.Fprintf(&b, "%s;%v", r.today(), r.inputs)
	return b.String()
}

// currentRecords returns the current records of a kind. Callers must not
// modify the returned slice.
func (r *Runner) currentRecords(k kinds.Named) ([]store.Record, error) {
	c, err := r.cached(k.Name())
	return c.curr, err
}

// inventoryData reads the current records the inventory is computed from.
func (r *Runner) inventoryData() (inventory.Data, error) {
	var d inventory.Data
	hosts, err := r.currentRecords(kinds.Hostname)
	if err != nil {
		return d, err
	}
	for _, rec := range hosts {
		d.Hosts = append(d.Hosts, inventory.Host{Name: input.NormaliseHost(rec.Key), Stages: rec.Stages})
	}
	recs, err := r.currentRecords(kinds.Resolution)
	if err != nil {
		return d, err
	}
	for _, rec := range recs {
		a := kinds.Resolution.Attrs(rec)
		if name := input.NormaliseHost(a.Name); name != "" {
			d.Resolutions = append(d.Resolutions, inventory.Resolution{Name: name, Type: a.Type, Value: a.Value})
		}
	}
	if recs, err = r.currentRecords(kinds.Wildcard); err != nil {
		return d, err
	}
	for _, rec := range recs {
		a := kinds.Wildcard.Attrs(rec)
		w := inventory.Wildcard{Zone: rec.Key, CNAME: a.CNAME}
		for _, s := range a.Addrs {
			if addr, err := netip.ParseAddr(s); err == nil {
				w.Addrs = append(w.Addrs, addr)
			}
		}
		d.Wildcards = append(d.Wildcards, w)
	}
	if recs, err = r.currentRecords(kinds.IP); err != nil {
		return d, err
	}
	for _, rec := range recs {
		if a, err := netip.ParseAddr(rec.Key); err == nil {
			d.IPs = append(d.IPs, a.Unmap())
		}
	}
	if recs, err = r.currentRecords(kinds.IPOwner); err != nil {
		return d, err
	}
	d.Owners = map[netip.Addr]provider.Owner{}
	for _, rec := range recs {
		if addr, err := netip.ParseAddr(rec.Key); err == nil {
			a := kinds.IPOwner.Attrs(rec)
			d.Owners[addr.Unmap()] = provider.Owner{ASN: a.ASN, Holder: a.Holder, Known: true}
		}
	}
	if d.Ranges, err = r.providerRanges(); err != nil {
		return d, err
	}
	if recs, err = r.currentRecords(kinds.IPHostname); err != nil {
		return d, err
	}
	for _, rec := range recs {
		a := kinds.IPHostname.Attrs(rec)
		if addr, err := netip.ParseAddr(a.IP); err == nil {
			d.IPHostnames = append(d.IPHostnames, inventory.IPHostname{IP: addr.Unmap(), Hostname: input.NormaliseHost(a.Hostname), Source: a.Source})
		}
	}
	return d, nil
}

// providerRanges returns the indexed provider_range records, re-reading them
// only when the store says they have changed since the last call.
func (r *Runner) providerRanges() (*provider.Ranges, error) {
	ver := r.st.KindVersion(kinds.ProviderRange.Name())
	if r.ranges != nil && ver == r.rangesVer {
		return r.ranges, nil
	}
	recs, err := r.currentRecords(kinds.ProviderRange)
	if err != nil {
		return nil, err
	}
	var rs []provider.Range
	for _, rec := range recs {
		a := kinds.ProviderRange.Attrs(rec)
		if p, err := netip.ParsePrefix(a.Prefix); err == nil {
			rs = append(rs, provider.Range{Prefix: p.Masked(), Provider: a.Provider, Service: a.Service, Region: a.Region})
		}
	}
	r.ranges, r.rangesVer = provider.NewRanges(rs), ver
	return r.ranges, nil
}
