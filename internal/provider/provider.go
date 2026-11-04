// Package provider recognises shared provider infrastructure (AWS, Azure,
// GCP, CDNs, SaaS platforms, shared hosting) from CNAME suffixes, provider
// address ranges and origin ASNs. Classification is pure and computed on read.
package provider

import (
	_ "embed"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"
)

//go:embed providers.yaml
var embedded []byte

// Match is a provider and service.
type Match struct{ Provider, Service string }

// Owner is the origin AS of an address, from Team Cymru or an in-scope netblock.
type Owner struct {
	ASN    int
	Holder string
	Known  bool
}

// Range is a published provider address range.
type Range struct {
	Prefix                    netip.Prefix
	Provider, Service, Region string
}

// Ranges indexes provider ranges by prefix, so finding the ranges that cover an
// address costs one map lookup per distinct prefix length, not a scan of them all.
type Ranges struct {
	all          []Range
	idx          map[netip.Prefix][]int // masked prefix -> positions in all
	lens4, lens6 []int                  // distinct prefix lengths, per family
}

// NewRanges indexes rs.
func NewRanges(rs []Range) *Ranges {
	x := &Ranges{all: rs, idx: map[netip.Prefix][]int{}}
	for i, r := range rs {
		p := r.Prefix.Masked()
		x.idx[p] = append(x.idx[p], i)
		lens := &x.lens6
		if p.Addr().Is4() {
			lens = &x.lens4
		}
		if !slices.Contains(*lens, p.Bits()) {
			*lens = append(*lens, p.Bits())
		}
	}
	return x
}

// covering returns the ranges that contain a, in their original order.
func (x *Ranges) covering(a netip.Addr) []*Range {
	if x == nil {
		return nil
	}
	lens := x.lens6
	if a.Is4() {
		lens = x.lens4
	}
	var pos []int
	for _, b := range lens {
		p, _ := a.Prefix(b)
		pos = append(pos, x.idx[p]...)
	}
	slices.Sort(pos)
	out := make([]*Range, len(pos))
	for i, j := range pos {
		out[i] = &x.all[j]
	}
	return out
}

// Result is what is known about an address. Evidence is "range" or "asn".
type Result struct {
	Known, Shared     bool
	Provider, Service string
	Evidence          string
}

// DB is the parsed providers.yaml.
type DB struct {
	cnames []struct {
		suffix string
		Match
	}
	asns map[int]struct{ provider, class string }
}

var (
	once sync.Once
	def  *DB
)

// Default returns the embedded database.
func Default() *DB {
	once.Do(func() {
		db, err := Parse(embedded)
		if err != nil {
			panic("provider: embedded providers.yaml: " + err.Error())
		}
		def = db
	})
	return def
}

// Parse reads a providers.yaml document.
func Parse(b []byte) (*DB, error) {
	var raw struct {
		CNAME []struct{ Suffix, Provider, Service string }
		ASN   []struct {
			ASN             int
			Provider, Class string
		}
	}
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	db := &DB{asns: map[int]struct{ provider, class string }{}}
	for _, c := range raw.CNAME {
		db.cnames = append(db.cnames, struct {
			suffix string
			Match
		}{strings.ToLower(c.Suffix), Match{c.Provider, c.Service}})
	}
	// Longest suffix first, so a specific service wins over its provider's generic domain.
	sort.SliceStable(db.cnames, func(i, j int) bool { return len(db.cnames[i].suffix) > len(db.cnames[j].suffix) })
	for _, a := range raw.ASN {
		db.asns[a.ASN] = struct{ provider, class string }{a.Provider, a.Class}
	}
	return db, nil
}

// CNAME returns the provider hosting a CNAME target, matching on label boundaries.
func (db *DB) CNAME(target string) (Match, bool) {
	t := strings.ToLower(strings.TrimSuffix(target, "."))
	for _, c := range db.cnames {
		if t == c.suffix || strings.HasSuffix(t, "."+c.suffix) {
			return c.Match, true
		}
	}
	return Match{}, false
}

// Classify says what is known about an address from the provider ranges and
// its owner. An address is Known if its owner is, or a range covers it.
// Hyperscaler addresses are shared unless an AWS EC2 range proves a dedicated
// VM; an address only in the AMAZON superset, GCP ranges (no service) and
// Azure (no ranges) all fail closed.
func (db *DB) Classify(a netip.Addr, owner Owner, ranges *Ranges) Result {
	a = a.Unmap()
	var ec2, amazon, gcp bool
	for _, r := range ranges.covering(a) {
		switch r.Provider {
		case "aws":
			switch r.Service {
			case "EC2":
				ec2 = true
			case "AMAZON":
				amazon = true
			default:
				return Result{Known: true, Shared: true, Provider: "aws", Service: r.Service, Evidence: "range"}
			}
		case "gcp":
			gcp = true
		}
	}
	switch {
	case gcp:
		return Result{Known: true, Shared: true, Provider: "gcp", Evidence: "range"}
	case ec2:
		return Result{Known: true, Provider: "aws", Service: "EC2", Evidence: "range"}
	case amazon:
		return Result{Known: true, Shared: true, Provider: "aws", Evidence: "range"}
	}
	if owner.Known {
		if p, ok := db.asns[owner.ASN]; ok {
			return Result{Known: true, Shared: true, Provider: p.provider, Evidence: "asn"}
		}
		return Result{Known: true}
	}
	return Result{}
}
