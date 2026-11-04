// Package inventory derives views from stored records that outputs, the
// runner's View and the egress Policy all need: which names are wildcard-only,
// what is shared provider infrastructure, which addresses may be port-checked.
// Everything is computed on read from plain data, never stored (Spec 1 D16),
// so a new binary's provider data or a late-discovered name is reflected at once.
package inventory

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/rafaelh/recon/internal/provider"
	"github.com/rafaelh/recon/internal/scope"
)

// Host is a hostname record and the stages currently observing it.
type Host struct {
	Name   string
	Stages []string
}

// Resolution is one resolved row: Type is A, AAAA or CNAME. A and AAAA rows are
// keyed to the queried name; a CNAME row's Name is the alias and Value its target.
type Resolution struct{ Name, Type, Value string }

// Wildcard is a zone that answers for names that do not exist.
type Wildcard struct {
	Zone  string
	Addrs []netip.Addr
	CNAME string
}

// IPHostname is a hostname seen for an address, by a source ("rdns", "shodan").
type IPHostname struct {
	IP               netip.Addr
	Hostname, Source string
}

// Data is everything the Inventory is computed from.
type Data struct {
	Hosts       []Host
	Resolutions []Resolution
	Wildcards   []Wildcard
	IPs         []netip.Addr
	Owners      map[netip.Addr]provider.Owner
	Ranges      *provider.Ranges
	IPHostnames []IPHostname
}

// ProviderHost is a hostname that is on shared provider infrastructure.
type ProviderHost struct {
	Hostname, Provider, Service string
	Evidence                    string // cname, range or asn
	CNAME                       string // the matching chain target, for cname evidence
	Resolves                    bool
}

// IPRow is one address in ips.csv.
type IPRow struct {
	IP                       netip.Addr
	ASN                      int
	Owner, Provider, Service string
	InScope, PortEligible    bool
	Hostnames                []string
}

// Inventory is an immutable derived view of Data.
type Inventory struct {
	d    Data
	db   *provider.DB
	addr map[string][]netip.Addr // queried name -> addresses
	cn   map[string][]string     // alias -> targets
	wo   map[string]bool
	// cnameShared holds the addresses of names whose CNAME chain ends on a known provider.
	cnameShared map[netip.Addr]provider.Match

	mu    sync.Mutex
	class map[netip.Addr]provider.Result
}

// New computes the inventory.
func New(d Data, db *provider.DB) *Inventory {
	i := &Inventory{d: d, db: db, addr: map[string][]netip.Addr{}, cn: map[string][]string{},
		wo:    map[string]bool{},
		class: map[netip.Addr]provider.Result{}, cnameShared: map[netip.Addr]provider.Match{}}
	for _, r := range d.Resolutions {
		switch r.Type {
		case "A", "AAAA":
			if a, err := netip.ParseAddr(r.Value); err == nil {
				i.addr[r.Name] = append(i.addr[r.Name], a.Unmap())
			}
		case "CNAME":
			i.cn[r.Name] = append(i.cn[r.Name], r.Value)
		}
	}
	wild := map[string]Wildcard{}
	for _, w := range d.Wildcards {
		wild[w.Zone] = w
	}
	// In name order, the first name to claim an address labels it, so the
	// label is the same on every run.
	for _, name := range slices.Sorted(maps.Keys(i.addr)) {
		if m, ok := i.chainProvider(name); ok {
			for _, a := range i.addr[name] {
				if _, seen := i.cnameShared[a]; !seen {
					i.cnameShared[a] = m
				}
			}
		}
	}
	for _, h := range d.Hosts {
		if w, ok := wild[parent(h.Name)]; ok && i.matchesWildcard(h.Name, w) {
			i.wo[h.Name] = true
		}
	}
	return i
}

// chainProviders calls yield for each CNAME target on name's chain (up to 8
// hops, following the first target) whose suffix matches a known provider,
// until yield returns false.
func (i *Inventory) chainProviders(name string, yield func(target string, m provider.Match) bool) {
	cur := name
	for hop := 0; hop < 8; hop++ {
		targets := i.cn[cur]
		if len(targets) == 0 {
			return
		}
		for _, t := range targets {
			if m, ok := i.db.CNAME(t); ok && !yield(t, m) {
				return
			}
		}
		cur = targets[0]
	}
}

// chainProvider returns the first provider whose suffix matches a CNAME target on name's chain.
func (i *Inventory) chainProvider(name string) (m provider.Match, ok bool) {
	i.chainProviders(name, func(_ string, pm provider.Match) bool {
		m, ok = pm, true
		return false
	})
	return m, ok
}

func parent(name string) string {
	_, rest, _ := strings.Cut(name, ".")
	return rest
}

func (i *Inventory) matchesWildcard(name string, w Wildcard) bool {
	if w.CNAME != "" {
		for _, t := range i.cn[name] {
			if t == w.CNAME {
				return true
			}
		}
	}
	for _, a := range i.addr[name] {
		for _, wa := range w.Addrs {
			if a == wa.Unmap() {
				return true
			}
		}
	}
	return false
}

// Addrs maps each queried name to its A/AAAA addresses (unmapped). Callers
// must not modify it.
func (i *Inventory) Addrs() map[string][]netip.Addr { return i.addr }

// WildcardOnly is the set of names that resolve only because of a wildcard.
func (i *Inventory) WildcardOnly() map[string]bool { return i.wo }

// Representatives maps each wildcard zone to its smallest wildcard-only name
// that is in scope and resolves, so the representative is always probeable.
func (i *Inventory) Representatives(sc *scope.Scope) map[string]string {
	reps := map[string]string{}
	for name := range i.wo {
		if len(i.addr[name]) == 0 || sc.ClassifyHost(name).Class != scope.InScope {
			continue
		}
		zone := parent(name)
		if cur, ok := reps[zone]; !ok || name < cur {
			reps[zone] = name
		}
	}
	return reps
}

// Seeds are the in-scope, non-wildcard-only hostnames that some stage other
// than generator observes, whose parent name is also in scope (so an apex is
// never split into a label and a public suffix). Names are never generated
// from the generator's own output.
func (i *Inventory) Seeds(sc *scope.Scope, generator string) []string {
	var out []string
	for _, h := range i.d.Hosts {
		if i.wo[h.Name] || sc.ClassifyHost(h.Name).Class != scope.InScope ||
			sc.ClassifyHost(parent(h.Name)).Class != scope.InScope {
			continue
		}
		for _, s := range h.Stages {
			if s != generator {
				out = append(out, h.Name)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

func (i *Inventory) result(a netip.Addr) provider.Result {
	a = a.Unmap()
	i.mu.Lock()
	defer i.mu.Unlock()
	if r, ok := i.class[a]; ok {
		return r
	}
	r := i.db.Classify(a, i.d.Owners[a], i.d.Ranges)
	// A CNAME into a provider is extra evidence (D17): it makes an address shared
	// even where ranges or ASNs call it dedicated (Heroku on EC2) or do not know it.
	if m, ok := i.cnameShared[a]; ok && !r.Shared {
		r = provider.Result{Known: true, Shared: true, Provider: m.Provider, Service: m.Service, Evidence: "cname"}
	}
	i.class[a] = r
	return r
}

// Shared reports whether the address is shared provider infrastructure.
func (i *Inventory) Shared(a netip.Addr) bool { return i.result(a).Shared }

// OwnerKnown reports whether anything is known about who owns the address: it
// is in an in-scope netblock, has an owner record, or a provider range covers it.
func (i *Inventory) OwnerKnown(a netip.Addr, sc *scope.Scope) bool {
	return sc.InScopeIP(a) || i.result(a).Known
}

// ProbeHostnames are the resolved in-scope, non-excluded names that are not
// wildcard-only, plus one representative for each wildcard zone.
func (i *Inventory) ProbeHostnames(sc *scope.Scope) []string {
	set := map[string]bool{}
	for name, addrs := range i.addr {
		if len(addrs) > 0 && !i.wo[name] && sc.ClassifyHost(name).Class == scope.InScope {
			set[name] = true
		}
	}
	for _, rep := range i.Representatives(sc) {
		set[rep] = true
	}
	return slices.Sorted(maps.Keys(set))
}

// ProviderHosts lists the in-scope names that are on shared provider
// infrastructure, by CNAME suffix anywhere on the chain (resolving or not), and
// by the provider range or ASN of their addresses.
func (i *Inventory) ProviderHosts(sc *scope.Scope) []ProviderHost {
	names := map[string]bool{}
	for _, h := range i.d.Hosts {
		names[h.Name] = true
	}
	for n := range i.addr {
		names[n] = true
	}
	var out []ProviderHost
	for _, n := range slices.Sorted(maps.Keys(names)) {
		if i.wo[n] || sc.ClassifyHost(n).Class != scope.InScope {
			continue
		}
		resolves := len(i.addr[n]) > 0
		seen := map[string]bool{}
		add := func(p ProviderHost) {
			k := p.Provider + "|" + p.Service + "|" + p.Evidence + "|" + p.CNAME
			if !seen[k] {
				seen[k] = true
				out = append(out, p)
			}
		}
		i.chainProviders(n, func(t string, m provider.Match) bool {
			add(ProviderHost{Hostname: n, Provider: m.Provider, Service: m.Service, Evidence: "cname", CNAME: t, Resolves: resolves})
			return true
		})
		for _, a := range i.addr[n] {
			if r := i.result(a); r.Shared && r.Provider != "" && r.Evidence != "cname" {
				add(ProviderHost{Hostname: n, Provider: r.Provider, Service: r.Service, Evidence: r.Evidence, Resolves: true})
			}
		}
	}
	return out
}

// IPRows lists every known address with its owner, provider label and whether
// it may be port-checked (the same decision egress makes).
func (i *Inventory) IPRows(sc *scope.Scope) []IPRow {
	byIP := map[netip.Addr]map[string]bool{}
	touch := func(a netip.Addr) map[string]bool {
		a = a.Unmap()
		if byIP[a] == nil {
			byIP[a] = map[string]bool{}
		}
		return byIP[a]
	}
	for _, a := range i.d.IPs {
		touch(a)
	}
	for _, h := range i.d.IPHostnames {
		if sc.ClassifyHost(h.Hostname).Class != scope.Excluded {
			touch(h.IP)[h.Hostname] = true
		} else {
			touch(h.IP)
		}
	}
	for name, addrs := range i.addr {
		if i.wo[name] || sc.ClassifyHost(name).Class == scope.Excluded {
			continue
		}
		for _, a := range addrs {
			touch(a)[name] = true
		}
	}
	rows := make([]IPRow, 0, len(byIP))
	for a, names := range byIP {
		res := i.result(a)
		owner := i.d.Owners[a]
		eligible, _, _ := sc.PortEligible(a, res.Shared, i.OwnerKnown(a, sc))
		row := IPRow{IP: a, Provider: res.Provider, Service: res.Service, InScope: sc.InScopeIP(a),
			PortEligible: eligible, Hostnames: slices.Sorted(maps.Keys(names))}
		switch {
		case owner.Known:
			row.ASN, row.Owner = owner.ASN, owner.Holder
			if row.Owner == "" {
				row.Owner = fmt.Sprintf("AS%d", owner.ASN)
			}
		case row.InScope:
			row.Owner = "in-scope netblock"
		case res.Provider != "":
			row.Owner = res.Provider
		}
		if row.Owner == "" {
			row.Owner = "unknown"
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(x, y int) bool { return rows[x].IP.Less(rows[y].IP) })
	return rows
}
