// Package scope classifies hostnames and addresses against the engagement's
// inputs. A Scope is immutable and its functions are pure.
package scope

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

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
		if h == r || strings.HasSuffix(h, "."+r) {
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
// it is shared provider infrastructure (D20). An unknown owner is not shared.
func (s *Scope) ExcludedFor(a netip.Addr, shared bool) (bool, string) {
	ok, why := s.ExcludedAddr(a)
	return ok && (!shared || s.ExcludedCIDR(a)), why
}

// PortEligible is the single decision whether an address may be port-checked,
// used both by egress and by the ips.csv report. shared is true for shared
// provider infrastructure; ownerKnown is false when nothing is known about who
// owns the address (fail closed). Exclusions apply first (ExcludedFor). Then an
// address is eligible if it is in an in-scope netblock, or if its owner is
// known, it is not shared, and an in-scope hostname that is not wildcard-only
// resolves to it. excluded is true when the refusal is an exclusion.
func (s *Scope) PortEligible(a netip.Addr, shared, ownerKnown bool) (ok bool, why string, excluded bool) {
	a = a.Unmap()
	if ex, why := s.ExcludedFor(a, shared); ex {
		return false, why, true
	}
	if s.InScopeIP(a) {
		return true, "", false
	}
	if shared || !ownerKnown {
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

// IPv4AddressCount is the number of distinct IPv4 addresses in the in-scope
// netblocks; overlapping netblocks are counted once.
func (s *Scope) IPv4AddressCount() uint64 {
	type iv struct{ lo, hi uint64 }
	var ivs []iv
	for _, p := range s.netblocks {
		if !p.Addr().Is4() {
			continue
		}
		p = p.Masked()
		b := p.Addr().As4()
		lo := uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
		ivs = append(ivs, iv{lo, lo + (1 << (32 - p.Bits())) - 1})
	}
	sort.Slice(ivs, func(i, j int) bool { return ivs[i].lo < ivs[j].lo })
	var total uint64
	var cur *iv
	for i := range ivs {
		if cur == nil || ivs[i].lo > cur.hi+1 {
			if cur != nil {
				total += cur.hi - cur.lo + 1
			}
			c := ivs[i]
			cur = &c
		} else if ivs[i].hi > cur.hi {
			cur.hi = ivs[i].hi
		}
	}
	if cur != nil {
		total += cur.hi - cur.lo + 1
	}
	return total
}
