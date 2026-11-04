// Package run executes stages over an engagement: repeated passes in registry
// order, a worker pool per stage, gating, the netblock guard, redo and the
// stage states shown on the console.
package run

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rafaelh/recon/internal/config"
	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/engagement"
	"github.com/rafaelh/recon/internal/fault"
	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/inventory"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/output"
	"github.com/rafaelh/recon/internal/provider"
	"github.com/rafaelh/recon/internal/report"
	"github.com/rafaelh/recon/internal/scope"
	"github.com/rafaelh/recon/internal/store"
)

// Exit codes (D17).
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
	Kinds               *kinds.Registry
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

	// ranges caches the indexed provider_range records (thousands of rows) as
	// of store KindVersion rangesVer; buildScope runs after every stage.
	ranges    *provider.Ranges
	rangesVer uint64

	mu      sync.Mutex
	failed  map[string]map[string]bool // stage -> check key, failed this run
	stats   map[string]*stageStats
	last    map[string]string // last printed state signature
	counts  map[string]int    // last emitted category counts
	lastTot map[string]int    // category counts computed by the last emitCounts
	aborted map[string]bool

	guarded sync.Map // value+"\x00"+reason already sent to the guard pseudo-stage
}

type stageStats struct{ attempted, failed int }

// New creates a Runner.
func New(cfg Config) *Runner {
	r := &Runner{
		cfg: cfg, st: cfg.Engagement.Store(),
		failed: map[string]map[string]bool{}, stats: map[string]*stageStats{},
		last: map[string]string{}, counts: map[string]int{}, aborted: map[string]bool{},
	}
	for _, s := range cfg.Stages {
		r.order = append(r.order, s.Name())
	}
	if cfg.Kinds == nil {
		r.cfg.Kinds = kinds.Default()
	}
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
	if rerr := r.render(); rerr != nil && err == nil {
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
			}
		}
		if err := r.render(); err != nil {
			return ExitFatal, err
		}
		r.emitCounts()
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

// buildScope builds the Scope and the egress Policy from stored inputs and
// observations, then applies the netblock guard (B15).
func (r *Runner) buildScope() error {
	eng := r.cfg.Engagement
	in, err := eng.Inputs()
	if err != nil {
		return err
	}
	r.inputs = in
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

	cands := map[string]bool{}
	roots, err := r.currentRecords("root")
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
	r.cfg.Egress.SetPolicy(&egress.Policy{
		Scope: sc, Ack: eng.Acked(), Passive: r.cfg.Passive,
		Ports: r.cfg.Settings.Ports, SensitivePaths: r.cfg.Settings.SensitivePathList,
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
		return eng.SetNetblockApproved(int(count))
	}
	return nil
}

// guard records an address that triggered an exclusion at dial time, once per
// distinct value and reason per run.
func (r *Runner) guard(value, reason string) {
	if _, seen := r.guarded.LoadOrStore(value+"\x00"+reason, struct{}{}); seen {
		return
	}
	r.st.Complete("guard", value, []store.Obs{{Kind: "excluded", Key: value, Attrs: map[string]any{"reason": reason}}})
}

// asnNetblocks maps each current netblock observed by the asn stage under a
// check for an input ASN to that ASN. It never depends on a mutable attribute.
func (r *Runner) asnNetblocks(in input.Parsed) (map[string]string, error) {
	rows, err := r.st.Observations("netblock", "asn")
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
	r.mu.Lock()
	aborted := r.aborted[name]
	r.mu.Unlock()
	if aborted {
		return 0, nil
	}
	done, err := r.st.Completed(name)
	if err != nil {
		return 0, err
	}
	pend, _ := r.st.PendingRedo()
	redoPending := slices.Contains(pend, name)
	failedSet := r.failedSet(name)
	clients := r.cfg.Egress.Clients(name, s.Contact() == Target, s.Sources())
	view := View{r: r, sc: r.sc.Load(), inv: r.inv.Load(), cache: &recordCache{m: map[string][]store.Record{}}}

	work := make(chan Check)
	var wg sync.WaitGroup
	var attempted atomic.Int64
	for i := 0; i < r.cfg.Settings.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range work {
				if ctx.Err() != nil {
					continue
				}
				r.mu.Lock()
				ab := r.aborted[name]
				r.mu.Unlock()
				if ab {
					r.failCheck(name, c.Key, "stage aborted earlier in this run")
					attempted.Add(1)
					continue
				}
				fault.PointDetail("in-flight", c.Key)
				obs, err := s.Run(ctx, c, clients)
				if ctx.Err() != nil {
					continue // in-flight checks are abandoned and redone next run
				}
				attempted.Add(1)
				if err != nil {
					if errors.Is(err, ErrAbortStage) {
						r.mu.Lock()
						r.aborted[name] = true
						r.mu.Unlock()
					}
					r.failCheck(name, c.Key, err.Error())
					continue
				}
				r.st.Complete(name, c.Key, toStoreObs(obs))
			}
		}()
	}

	all := map[string]struct{}{} // in stored (redacted) form, like done
	enumFailed := false
	pending := 0
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
		all[stored] = struct{}{}
		if _, ok := done[stored]; ok {
			continue
		}
		r.mu.Lock()
		skip := failedSet[c.Key]
		ab := r.aborted[name]
		r.mu.Unlock()
		if skip {
			continue
		}
		if ab {
			pending++
			attempted.Add(1)
			r.failCheck(name, c.Key, "stage aborted earlier in this run")
			continue
		}
		if pending == 0 {
			r.setState(name, "running", "", 0, 0)
		}
		pending++
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

	n := int(attempted.Load())
	r.mu.Lock()
	ss := r.stat(name)
	ss.attempted += n
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
	return n, nil
}

// failCheck records a transient failure: not a completion, not retried this run.
func (r *Runner) failCheck(stage, key, msg string) {
	r.mu.Lock()
	r.failedLocked(stage)[key] = true
	r.stat(stage).failed++
	r.mu.Unlock()
	r.st.Fail(stage, key, msg)
	r.warn("%s check %s failed: %s", stage, key, msg)
}

func toStoreObs(obs []Observation) []store.Obs {
	out := make([]store.Obs, len(obs))
	for i, o := range obs {
		out[i] = store.Obs{Kind: o.Kind, Key: o.Key, Attrs: o.Attrs}
	}
	return out
}

// categoryOf returns the summary category of a record ("" if it is not counted).
func categoryOf(k kinds.Kind, rec store.Record, sc *scope.Scope) string {
	if !k.Entity {
		return k.Category
	}
	switch k.Name {
	case "excluded":
		return kinds.Excluded
	case "hostname", "root":
		switch sc.ClassifyHost(rec.Key).Class {
		case scope.InScope:
			if k.Name == "hostname" {
				return kinds.Hosts
			}
			return ""
		case scope.Candidate:
			return kinds.Candidates
		default:
			return kinds.Excluded
		}
	case "netblock":
		if sc != nil && sc.HasNetblock(rec.Key) {
			return kinds.Netblocks
		}
		return kinds.Candidates
	}
	return k.Category
}

func (r *Runner) totals() map[string]int {
	sc := r.sc.Load()
	totals := map[string]int{kinds.Hosts: 0}
	for _, k := range r.cfg.Kinds.All() {
		if k.Category == "" {
			continue
		}
		if !k.Entity {
			totals[k.Category] += 0 // listed even when empty
		}
		recs, err := r.st.Records(k.Name, r.order)
		if err != nil {
			r.warn("counting %s: %v", k.Name, err)
			continue
		}
		for _, rec := range recs {
			if !rec.Current {
				continue
			}
			if cat := categoryOf(k, rec, sc); cat != "" {
				totals[cat]++
			}
		}
	}
	return totals
}

func (r *Runner) emitCounts() {
	totals := r.totals()
	r.lastTot = totals
	for _, k := range slices.Sorted(maps.Keys(totals)) {
		if r.counts[k] != totals[k] {
			r.counts[k] = totals[k]
			r.emit("count", map[string]any{"category": k, "n": totals[k]})
		}
	}
}

func (r *Runner) emitSummary() {
	failed := map[string]int{}
	r.mu.Lock()
	for name, s := range r.stats {
		if s.failed > 0 {
			failed[name] = s.failed
		}
	}
	r.mu.Unlock()
	var findings []map[string]any
	recs, _ := r.st.Records("finding", r.order)
	for _, rec := range recs {
		sev, _ := rec.Attrs["severity"].(string)
		if !rec.Current || (sev != "high" && sev != "medium") {
			continue
		}
		findings = append(findings, map[string]any{
			"category": rec.Attrs["category"], "severity": sev, "target": rec.Attrs["target"], "detail": rec.Attrs["detail"],
		})
	}
	sort.SliceStable(findings, func(i, j int) bool {
		si, sj := findings[i]["severity"].(string), findings[j]["severity"].(string)
		if si != sj {
			return si == "high"
		}
		return fmt.Sprint(findings[i]["target"]) < fmt.Sprint(findings[j]["target"])
	})
	if findings == nil {
		findings = []map[string]any{}
	}
	r.emit("summary", map[string]any{"totals": r.lastTot, "failed": failed, "findings": findings})
}

// onNewRecord prints records of Printed kinds the first time the engagement sees them.
func (r *Runner) onNewRecord(kind, key string, attrs map[string]any) {
	k, ok := r.cfg.Kinds.Get(kind)
	if !ok || !k.Printed {
		return
	}
	if k.Entity {
		sc := r.sc.Load()
		if sc == nil || sc.ClassifyHost(key).Class != scope.InScope {
			return
		}
	}
	f := map[string]any{"category": k.Singular, "value": key}
	if sev, ok := attrs["severity"].(string); ok && sev != "" {
		f["severity"] = sev
		if t, ok := attrs["target"].(string); ok && t != "" {
			f["value"] = t
		}
		if c, ok := attrs["category"].(string); ok && c != "" {
			f["category"] = k.Singular + " " + c
		}
	}
	r.emit("found", f)
}

// render writes the output files from the store.
func (r *Runner) render() error {
	if err := r.st.Flush(); err != nil {
		return err
	}
	eng := r.cfg.Engagement
	inputs, err := r.st.Inputs()
	if err != nil {
		return err
	}
	snap := output.Snapshot{Today: r.today(), Inputs: inputs, Records: map[string][]store.Record{}, Scope: r.sc.Load(), Inv: r.inv.Load()}
	if snap.Scope == nil {
		snap.Scope = scope.New(scope.Config{})
	}
	if snap.Inv == nil {
		snap.Inv = inventory.New(inventory.Data{}, provider.Default())
	}
	for _, kind := range []string{"root", "hostname", "netblock", "excluded", "resolution", "unresolved", "ip"} {
		recs, err := r.st.Records(kind, r.order)
		if err != nil {
			return err
		}
		snap.Records[kind] = recs
	}
	if snap.ASNNetblocks, err = r.asnNetblocks(r.inputs); err != nil {
		return err
	}
	return output.Render(eng.Dir(), r.cfg.Files, snap)
}

// currentRecords returns the current records of a kind.
func (r *Runner) currentRecords(kind string) ([]store.Record, error) {
	recs, err := r.st.Records(kind, r.order)
	if err != nil {
		return nil, err
	}
	out := recs[:0]
	for _, rec := range recs {
		if rec.Current {
			out = append(out, rec)
		}
	}
	return out, nil
}

// inventoryData reads the current records the inventory is computed from.
func (r *Runner) inventoryData() (inventory.Data, error) {
	var d inventory.Data
	hosts, err := r.currentRecords("hostname")
	if err != nil {
		return d, err
	}
	for _, rec := range hosts {
		d.Hosts = append(d.Hosts, inventory.Host{Name: input.NormaliseHost(rec.Key), Stages: rec.Stages})
	}
	recs, err := r.currentRecords("resolution")
	if err != nil {
		return d, err
	}
	for _, rec := range recs {
		name := input.NormaliseHost(rec.Str("name"))
		if name != "" {
			d.Resolutions = append(d.Resolutions, inventory.Resolution{Name: name, Type: rec.Str("type"), Value: rec.Str("value")})
		}
	}
	if recs, err = r.currentRecords("wildcard"); err != nil {
		return d, err
	}
	for _, rec := range recs {
		w := inventory.Wildcard{Zone: rec.Key, CNAME: rec.Str("cname")}
		list, _ := rec.Attrs["addrs"].([]any)
		for _, a := range list {
			if s, ok := a.(string); ok {
				if addr, err := netip.ParseAddr(s); err == nil {
					w.Addrs = append(w.Addrs, addr)
				}
			}
		}
		d.Wildcards = append(d.Wildcards, w)
	}
	if recs, err = r.currentRecords("ip"); err != nil {
		return d, err
	}
	for _, rec := range recs {
		if a, err := netip.ParseAddr(rec.Key); err == nil {
			d.IPs = append(d.IPs, a.Unmap())
		}
	}
	if recs, err = r.currentRecords("ip_owner"); err != nil {
		return d, err
	}
	d.Owners = map[netip.Addr]provider.Owner{}
	for _, rec := range recs {
		if a, err := netip.ParseAddr(rec.Key); err == nil {
			asn, _ := rec.Attrs["asn"].(float64)
			d.Owners[a.Unmap()] = provider.Owner{ASN: int(asn), Holder: rec.Str("holder"), Known: true}
		}
	}
	if d.Ranges, err = r.providerRanges(); err != nil {
		return d, err
	}
	if recs, err = r.currentRecords("ip_hostname"); err != nil {
		return d, err
	}
	for _, rec := range recs {
		if a, err := netip.ParseAddr(rec.Str("ip")); err == nil {
			d.IPHostnames = append(d.IPHostnames, inventory.IPHostname{IP: a.Unmap(), Hostname: input.NormaliseHost(rec.Str("hostname")), Source: rec.Str("source")})
		}
	}
	return d, nil
}

// providerRanges returns the indexed provider_range records, re-reading them
// only when the store says they have changed since the last call.
func (r *Runner) providerRanges() (*provider.Ranges, error) {
	ver := r.st.KindVersion("provider_range")
	if r.ranges != nil && ver == r.rangesVer {
		return r.ranges, nil
	}
	recs, err := r.currentRecords("provider_range")
	if err != nil {
		return nil, err
	}
	var rs []provider.Range
	for _, rec := range recs {
		if p, err := netip.ParsePrefix(rec.Str("prefix")); err == nil {
			rs = append(rs, provider.Range{Prefix: p.Masked(), Provider: rec.Str("provider"), Service: rec.Str("service"), Region: rec.Str("region")})
		}
	}
	r.ranges, r.rangesVer = provider.NewRanges(rs), ver
	return r.ranges, nil
}
