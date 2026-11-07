// Package scope classifies hostnames and addresses against the engagement's
// inputs. A Scope is immutable and its functions are pure.
package scope

import (
	"fmt"
	"iter"
	"net/netip"
	"slices"
	"sort"

	"github.com/rafaelh/recon/internal/dnsname"
	"github.com/rafaelh/recon/internal/input"
)

// Class is the scope classification of a hostname.
type Class int

const (
	InScope Class = iota
	Candidate
	Excluded
)

func (c Class) String() string { return [...]string{"in-scope", "candidate", "excluded"}[c] }

// Classification is a Class with the reason for an exclusion.
type Classification struct {
	Class  Class
	Reason string
}

// Config is everything a Scope is built from.
type Config struct {
	Roots       []string                // in-scope root domains
	Netblocks   []netip.Prefix          // CIDR inputs and ASN netblocks
	Exclusions  []input.Exclusion       // hostnames, wildcards and CIDRs
	Resolutions map[string][]netip.Addr // hostname -> addresses
	// WildcardOnly names resolve only because of a wildcard record; they do not
	// make an address port-check eligible.
	WildcardOnly map[string]bool
}

// Scope classifies names and addresses.
type Scope struct {
	roots     []string
	netblocks []netip.Prefix
	blockSet  map[netip.Prefix]bool
	exclHosts []input.Exclusion
	exclCIDRs []input.Exclusion
	resolved  map[string][]netip.Addr
	exclAddrs map[netip.Addr]string // addresses of hosts excluded by name
	hostAddrs map[netip.Addr]bool   // addresses of in-scope, non-wildcard-only hostnames
}

// New builds a Scope.
func New(c Config) *Scope {
	s := &Scope{roots: normaliseAll(c.Roots), netblocks: c.Netblocks, blockSet: map[netip.Prefix]bool{},
		resolved: map[string][]netip.Addr{}, exclAddrs: map[netip.Addr]string{}, hostAddrs: map[netip.Addr]bool{}}
	for _, p := range c.Netblocks {
		s.blockSet[p] = true
	}
	for _, e := range c.Exclusions {
		if _, ok := e.Prefix(); ok {
			s.exclCIDRs = append(s.exclCIDRs, e)
		} else {
			s.exclHosts = append(s.exclHosts, e)
		}
	}
	for h, addrs := range c.Resolutions {
		h = input.NormaliseHost(h)
		s.resolved[h] = addrs
		if e, ok := s.matchName(h); ok {
			for _, a := range addrs {
				s.exclAddrs[a] = fmt.Sprintf("address %s of excluded host %s (matched %s)", a, h, e.Entry)
			}
		}
	}
	for h, addrs := range s.resolved {
		if c.WildcardOnly[h] || s.ClassifyHost(h).Class != InScope {
			continue
		}
		for _, a := range addrs {
			s.hostAddrs[a] = true
		}
	}
	return s
}

func normaliseAll(in []string) []string {
	out := make([]string, len(in))
	for i, h := range in {
		out[i] = input.NormaliseHost(h)
	}
	return out
}

func (s *Scope) matchName(h string) (input.Exclusion, bool) {
	for _, e := range s.exclHosts {
		if e.MatchesHost(h) {
			return e, true
		}
	}
	return input.Exclusion{}, false
}

func (s *Scope) cidrOf(a netip.Addr) (input.Exclusion, bool) {
	for _, e := range s.exclCIDRs {
		if p, _ := e.Prefix(); p.Contains(a) {
			return e, true
		}
	}
	return input.Exclusion{}, false
}

// ClassifyHost returns InScope, Candidate or Excluded (with the reason). A name
// is excluded if it matches the exclusion list or resolves into an excluded CIDR.
func (s *Scope) ClassifyHost(host string) Classification {
	h := input.NormaliseHost(host)
	if e, ok := s.matchName(h); ok {
		return Classification{Excluded, "matched exclusion " + e.Entry}
	}
	for _, a := range s.resolved[h] {
		if e, ok := s.cidrOf(a); ok {
			return Classification{Excluded, fmt.Sprintf("resolves to %s in excluded %s", a, e.Entry)}
		}
	}
	for _, r := range s.roots {
		if dnsname.Under(h, r) {
			return Classification{InScope, ""}
		}
	}
	return Classification{Candidate, ""}
}

// InScopeIP reports whether the address is inside an in-scope netblock.
func (s *Scope) InScopeIP(a netip.Addr) bool {
	for _, p := range s.netblocks {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// WebHostInScope reports whether a web service or URL on host may be shown. It
// is the one decision behind the summary counts and the web CSVs:
// an IP literal is in an in-scope netblock and not excluded; a name is in scope.
func (s *Scope) WebHostInScope(host string) bool {
	h := input.NormaliseHost(host)
	if a, ok := input.IPLiteral(h); ok {
		excluded, _ := s.ExcludedAddr(a)
		return s.InScopeIP(a) && !excluded
	}
	return h != "" && s.ClassifyHost(h).Class == InScope
}

// ExcludedAddr reports whether the address is in an excluded CIDR or is an
// address of a host excluded by name.
func (s *Scope) ExcludedAddr(a netip.Addr) (bool, string) {
	if e, ok := s.cidrOf(a); ok {
		return true, fmt.Sprintf("address %s in excluded %s", a, e.Entry)
	}
	if why, ok := s.exclAddrs[a]; ok {
		return true, why
	}
	return false, ""
}

// ExcludedCIDR reports whether the address is inside an excluded CIDR (and so
// excluded regardless of shared infrastructure).
func (s *Scope) ExcludedCIDR(a netip.Addr) bool { _, ok := s.cidrOf(a); return ok }

// ExcludedFor reports whether an exclusion refuses traffic to the address: an
// excluded CIDR always does; the address of a host excluded by name does unless
// it is shared provider infrastructure. An unknown owner is not shared.
func (s *Scope) ExcludedFor(a netip.Addr, shared bool) (bool, string) {
	ok, why := s.ExcludedAddr(a)
	return ok && (!shared || s.ExcludedCIDR(a)), why
}

// Owner reports what is known about who owns an address: whether it is shared
// provider infrastructure, and whether anything is known about its owner at
// all (false fails closed). An unknown owner is not shared.
type Owner func(netip.Addr) (shared, known bool)

// PortEligible is the single decision whether an address may be port-checked,
// used both by egress and by the ips.csv report. Exclusions apply first
// (ExcludedFor). Then an address is eligible if it is in an in-scope netblock,
// or if its owner is known, it is not shared, and an in-scope hostname that is
// not wildcard-only resolves to it. owner is asked only when the decision needs
// it, so an in-scope netblock address costs no owner lookup. excluded is true
// when the refusal is an exclusion.
func (s *Scope) PortEligible(a netip.Addr, owner Owner) (ok bool, why string, excluded bool) {
	a = a.Unmap()
	if ex, why := s.ExcludedAddr(a); ex {
		if s.ExcludedCIDR(a) {
			return false, why, true
		}
		if shared, _ := owner(a); !shared {
			return false, why, true
		}
	}
	if s.InScopeIP(a) {
		return true, "", false
	}
	if shared, known := owner(a); shared || !known {
		return false, "address " + a.String() + " is shared provider infrastructure or its owner is unknown", false
	}
	if s.hostAddrs[a] {
		return true, "", false
	}
	return false, "address " + a.String() + " is not in scope", false
}

// Netblocks returns the in-scope netblocks.
func (s *Scope) Netblocks() []netip.Prefix { return slices.Clone(s.netblocks) }

// HasNetblock reports whether key, a CIDR, is one of the in-scope netblocks.
func (s *Scope) HasNetblock(key string) bool {
	p, err := netip.ParsePrefix(key)
	return err == nil && s.blockSet[p.Masked()]
}

// ipv4Range is an inclusive range of IPv4 addresses held as integers.
type ipv4Range struct{ lo, hi uint64 }

// ipv4Ranges returns the in-scope IPv4 netblocks as sorted ranges with the
// overlapping and adjacent ones merged, so each address is in exactly one.
func (s *Scope) ipv4Ranges() []ipv4Range {
	var ivs []ipv4Range
	for _, p := range s.netblocks {
		if !p.Addr().Is4() {
			continue
		}
		p = p.Masked()
		b := p.Addr().As4()
		lo := uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
		ivs = append(ivs, ipv4Range{lo, lo + (1 << (32 - p.Bits())) - 1})
	}
	sort.Slice(ivs, func(i, j int) bool { return ivs[i].lo < ivs[j].lo })
	var out []ipv4Range
	for _, r := range ivs {
		if n := len(out); n > 0 && r.lo <= out[n-1].hi+1 {
			out[n-1].hi = max(out[n-1].hi, r.hi)
			continue
		}
		out = append(out, r)
	}
	return out
}

// IPv4AddressCount is the number of distinct IPv4 addresses in the in-scope
// netblocks; overlapping netblocks are counted once.
func (s *Scope) IPv4AddressCount() uint64 {
	var total uint64
	for _, r := range s.ipv4Ranges() {
		total += r.hi - r.lo + 1
	}
	return total
}

// IPv4Addrs yields the distinct IPv4 addresses of the in-scope netblocks in
// ascending order: the addresses IPv4AddressCount counts.
func (s *Scope) IPv4Addrs() iter.Seq[netip.Addr] {
	return func(yield func(netip.Addr) bool) {
		for _, r := range s.ipv4Ranges() {
			for v := r.lo; v <= r.hi; v++ {
				if !yield(netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})) {
					return
				}
			}
		}
	}
}
