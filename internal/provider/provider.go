// Package provider recognises shared provider infrastructure (AWS, Azure,
// GCP, CDNs, SaaS platforms, shared hosting) from CNAME suffixes, provider
// address ranges and origin ASNs. Classification is pure and computed on read.
package provider

import (
	"cmp"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"maps"
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
// Class is the class of the providers.yaml entry that matched ("saas", "cdn",
// "hyperscaler" or "shared-hosting"), and for an address matched by a published
// range it is "cdn" for a CDN's ranges and empty otherwise. Region is the
// region a range publisher gives, where it does. An address two providers'
// ranges cover has their names (and services and regions) joined with ";".
type Result struct {
	Known, Shared     bool
	Provider, Service string
	Evidence          string
	Class             string
	Region            string
}

// ClassSaaS marks an entry or address served by a third-party SaaS platform.
const ClassSaaS = "saas"

// ClassCDN marks an address served by a content delivery network.
const ClassCDN = "cdn"

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

// txtPrefix is a TXT value prefix (lower case) and the platform it verifies ownership for.
type txtPrefix struct{ prefix, platform string }

// domainOwner is a domain suffix (lower case) and the provider that operates it.
type domainOwner struct{ suffix, provider string }

// DB is the parsed providers.yaml.
type DB struct {
	cnames  []Entry
	asns    map[int]struct{ provider, class string }
	ranges  []addrRange
	txt     []txtPrefix
	domains []domainOwner
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
		TXT     []struct{ Prefix, Platform string }
		Domains []struct{ Suffix, Provider string }
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
	for _, t := range raw.TXT {
		if t.Prefix == "" || t.Platform == "" {
			return nil, fmt.Errorf("txt entry %+v needs a prefix and a platform", t)
		}
		db.txt = append(db.txt, txtPrefix{strings.ToLower(t.Prefix), t.Platform})
	}
	for _, d := range raw.Domains {
		if d.Suffix == "" || d.Provider == "" {
			return nil, fmt.Errorf("domains entry %+v needs a suffix and a provider", d)
		}
		db.domains = append(db.domains, domainOwner{dnsname.Normalise(d.Suffix), d.Provider})
	}
	// Longest suffix first, as for CNAMEs, so a specific service wins.
	sort.SliceStable(db.domains, func(i, j int) bool { return len(db.domains[i].suffix) > len(db.domains[j].suffix) })
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

// rangeRule settles one provider's ranges that cover an address. rs is never
// empty and is in the order the ranges were recorded. It fills in only Shared,
// Service, Region and Class: classifyRanges sets the rest.
type rangeRule func(rs []*Range) Result

// rangeRules say, for each provider whose published ranges are fetched, what
// being inside one of them means. A provider with no rule here is ignored.
var rangeRules = map[string]rangeRule{
	"aws":          awsRule,
	"gcp":          wholeListRule(true, ""),
	"cloudflare":   wholeListRule(true, ClassCDN),
	"fastly":       wholeListRule(true, ClassCDN),
	"digitalocean": wholeListRule(false, ""),
	"linode":       wholeListRule(false, ""),
	"oracle":       oracleRule,
}

// HasRangeRule reports whether a provider's published ranges mean anything to
// Classify. A provider whose ranges are fetched needs one, or they are ignored.
func HasRangeRule(provider string) bool {
	_, ok := rangeRules[provider]
	return ok
}

// wholeListRule: every address in the provider's ranges is shared infrastructure
// (a customer's own machine when shared is false). The service is not reported,
// since the list does not discriminate by it.
func wholeListRule(shared bool, class string) rangeRule {
	return func(rs []*Range) Result { return Result{Shared: shared, Region: rs[0].Region, Class: class} }
}

// awsRule: an address is a dedicated VM only if an EC2 range proves it. A range
// of any other service makes it shared, and one only in the AMAZON superset
// fails closed.
func awsRule(rs []*Range) Result {
	var ec2, amazon *Range
	for _, r := range rs {
		switch r.Service {
		case "EC2":
			ec2 = cmp.Or(ec2, r)
		case "AMAZON":
			amazon = cmp.Or(amazon, r)
		default:
			return Result{Shared: true, Service: r.Service, Region: r.Region}
		}
	}
	if ec2 != nil {
		return Result{Service: "EC2", Region: ec2.Region}
	}
	return Result{Shared: true, Region: amazon.Region}
}

// oracleRule: a range tagged OSN (Oracle services) or OBJECT_STORAGE is shared
// and the rest are dedicated. An address in both kinds is shared. The range
// reported is the first by service, then region, whatever order they were
// recorded in.
func oracleRule(rs []*Range) Result {
	slices.SortFunc(rs, func(a, b *Range) int {
		return cmp.Or(cmp.Compare(a.Service, b.Service), cmp.Compare(a.Region, b.Region))
	})
	pick, shared := rs[0], false
	for _, r := range rs {
		if r.Service == "OSN" || r.Service == "OBJECT_STORAGE" {
			pick, shared = r, true
			break
		}
	}
	return Result{Shared: shared, Service: pick.Service, Region: pick.Region}
}

// classifyRanges settles an address from the ranges that cover it. Each
// provider first settles its own ranges by its own rule, so an EC2 range still
// wins over the AMAZON superset that also covers it. Across providers the names
// are joined with ";" in name order and the address is shared if any provider's
// result is: it fails closed. ok is false when no range of a known provider
// covers the address.
func classifyRanges(covering []*Range) (res Result, ok bool) {
	by := map[string][]*Range{}
	for _, r := range covering {
		if _, known := rangeRules[r.Provider]; known {
			by[r.Provider] = append(by[r.Provider], r)
		}
	}
	if len(by) == 0 {
		return Result{}, false
	}
	var names, services, regions []string
	res = Result{Known: true, Evidence: "range"}
	for _, p := range slices.Sorted(maps.Keys(by)) {
		r := rangeRules[p](by[p])
		names = append(names, p)
		if r.Service != "" {
			services = append(services, r.Service)
		}
		if r.Region != "" {
			regions = append(regions, r.Region)
		}
		res.Shared = res.Shared || r.Shared
		res.Class = cmp.Or(res.Class, r.Class)
	}
	res.Provider = strings.Join(names, ";")
	res.Service = strings.Join(services, ";")
	res.Region = strings.Join(regions, ";")
	return res, true
}

// Classify says what is known about an address from the provider ranges and
// its owner. An address is Known if its owner is, or a range covers it. A
// published range takes precedence over the owner's ASN, which is the fallback
// when the list is missing. Each provider's own rule says what its ranges
// mean (see rangeRules); hyperscaler addresses with no range to prove
// otherwise, and Azure (no ranges), fail closed.
func (db *DB) Classify(a netip.Addr, owner Owner, ranges *Ranges) Result {
	a = a.Unmap()
	if res, ok := classifyRanges(ranges.covering(a)); ok {
		return res
	}
	if r, ok := db.staticRange(a); ok {
		return Result{Known: true, Shared: true, Provider: r.Provider, Service: r.Service, Evidence: "range", Class: r.class}
	}
	if owner.Known {
		if p, ok := db.asns[owner.ASN]; ok {
			return Result{Known: true, Shared: true, Provider: p.provider, Evidence: "asn", Class: p.class}
		}
		return Result{Known: true}
	}
	return Result{}
}

// Verification returns the platform a root TXT record is a domain-ownership
// verification for: the value starts with a listed prefix, in any case.
func (db *DB) Verification(value string) (string, bool) {
	v := strings.ToLower(strings.TrimSpace(value))
	for _, t := range db.txt {
		if strings.HasPrefix(v, t.prefix) {
			return t.platform, true
		}
	}
	return "", false
}

// DomainOwner returns the provider that operates a domain, such as a managed
// DNS service for its name servers, matching on label boundaries.
func (db *DB) DomainOwner(name string) (string, bool) {
	n := dnsname.Normalise(name)
	for _, d := range db.domains {
		if dnsname.Under(n, d.suffix) {
			return d.provider, true
		}
	}
	return "", false
}
