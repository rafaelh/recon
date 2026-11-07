// Package provider recognises shared provider infrastructure (AWS, Azure,
// GCP, CDNs, SaaS platforms, shared hosting) from CNAME suffixes, provider
// address ranges and origin ASNs. Classification is pure and computed on read.
package provider

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/rafaelh/recon/internal/dnsname"
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
// Class is "saas" for an address served by a third-party SaaS platform and
// empty otherwise.
type Result struct {
	Known, Shared     bool
	Provider, Service string
	Evidence          string
	Class             string
}

// ClassSaaS marks an entry or address served by a third-party SaaS platform.
const ClassSaaS = "saas"

// Entry is a matched CNAME entry of providers.yaml. NXDomain says a chain that
// dangles into it can be claimed; Body, an RE2 regex, matches the page an
// unclaimed resource serves.
type Entry struct {
	Match
	Suffix, Class string
	NXDomain      bool
	Body          string
	re            *regexp.Regexp
}

// BodyMatches reports whether body is what the entry's unclaimed resource serves.
func (e Entry) BodyMatches(body []byte) bool { return e.re != nil && e.re.Match(body) }

// Hash is a short stable identifier of everything about the entry that changes
// what a check for it does, so an edited fingerprint is re-checked and others are not.
func (e Entry) Hash() string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s|%v|%s", e.Suffix, e.Provider, e.Service, e.Class, e.NXDomain, e.Body)))
	return hex.EncodeToString(sum[:4])
}

// addrRange is a static address range of a provider (a SaaS reached by apex A records).
type addrRange struct {
	prefix netip.Prefix
	Match
	class string
}

// DB is the parsed providers.yaml.
type DB struct {
	cnames []Entry
	asns   map[int]struct{ provider, class string }
	ranges []addrRange
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
		CNAME []struct {
			Suffix, Provider, Service, Class, Body string
			NXDomain                               bool `yaml:"nxdomain"`
		}
		ASN []struct {
			ASN             int
			Provider, Class string
		}
		Ranges []struct {
			CIDR, Provider, Service, Class string
		}
	}
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	db := &DB{asns: map[int]struct{ provider, class string }{}}
	for _, c := range raw.CNAME {
		e := Entry{Match: Match{c.Provider, c.Service}, Suffix: strings.ToLower(c.Suffix), Class: c.Class, NXDomain: c.NXDomain, Body: c.Body}
		if c.Body != "" {
			re, err := regexp.Compile(c.Body)
			if err != nil {
				return nil, fmt.Errorf("cname %s: body %q: %w", c.Suffix, c.Body, err)
			}
			e.re = re
		}
		db.cnames = append(db.cnames, e)
	}
	// Longest suffix first, so a specific service wins over its provider's generic domain.
	sort.SliceStable(db.cnames, func(i, j int) bool { return len(db.cnames[i].Suffix) > len(db.cnames[j].Suffix) })
	for _, a := range raw.ASN {
		db.asns[a.ASN] = struct{ provider, class string }{a.Provider, a.Class}
	}
	for _, r := range raw.Ranges {
		p, err := netip.ParsePrefix(r.CIDR)
		if err != nil {
			return nil, fmt.Errorf("range %q: %w", r.CIDR, err)
		}
		db.ranges = append(db.ranges, addrRange{prefix: p.Masked(), Match: Match{r.Provider, r.Service}, class: r.Class})
	}
	return db, nil
}

// CNAME returns the provider hosting a CNAME target, matching on label boundaries.
func (db *DB) CNAME(target string) (Match, bool) {
	e, ok := db.CNAMEEntry(target)
	return e.Match, ok
}

// CNAMEEntry is CNAME with the whole matched entry.
func (db *DB) CNAMEEntry(target string) (Entry, bool) {
	t := dnsname.Normalise(target)
	for _, c := range db.cnames {
		if dnsname.Under(t, c.Suffix) {
			return c, true
		}
	}
	return Entry{}, false
}

func (db *DB) staticRange(a netip.Addr) (addrRange, bool) {
	for _, r := range db.ranges {
		if r.prefix.Contains(a) {
			return r, true
		}
	}
	return addrRange{}, false
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
	if r, ok := db.staticRange(a); ok {
		res := Result{Known: true, Shared: true, Provider: r.Provider, Service: r.Service, Evidence: "range"}
		if r.class == ClassSaaS {
			res.Class = ClassSaaS
		}
		return res
	}
	if owner.Known {
		if p, ok := db.asns[owner.ASN]; ok {
			res := Result{Known: true, Shared: true, Provider: p.provider, Evidence: "asn"}
			if p.class == ClassSaaS {
				res.Class = ClassSaaS
			}
			return res
		}
		return Result{Known: true}
	}
	return Result{}
}
