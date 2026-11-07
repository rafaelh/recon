// Package input parses and validates the inputs given on the command line:
// domains, organisations, ASNs, CIDRs and exclusions.
package input

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/rafaelh/recon/internal/dnsname"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Raw is the unvalidated input as given on the command line.
type Raw struct {
	Domains     []string
	DomainsFile string
	Orgs        []string
	ASNs        []string
	CIDRs       []string
	Exclude     []string
	ExcludeFile string
}

// Parsed holds canonical, de-duplicated inputs (sorted, except First).
type Parsed struct {
	Roots      []string
	Orgs       []string
	ASNs       []string // "AS123"
	CIDRs      []string // masked
	Exclusions []string // canonical entries
	First      string   // first input, used to name the engagement
}

// Empty reports whether no scope inputs were given.
func (p Parsed) Empty() bool {
	return len(p.Roots)+len(p.Orgs)+len(p.ASNs)+len(p.CIDRs) == 0
}

// NormaliseHost trims, lowercases and drops the trailing dot of a hostname.
func NormaliseHost(h string) string { return dnsname.Normalise(h) }

// IPLiteral parses host as an IP address, unmapped. A zoned address is not a
// literal egress will dial, and a bracketed form is a URL authority, not a host.
func IPLiteral(host string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(host)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// ParseDomain lowercases, converts to punycode and validates a root domain.
// Public suffixes and IP literals are rejected.
func ParseDomain(s string) (string, error) {
	orig := s
	d := NormaliseHost(s)
	if d == "" {
		return "", fmt.Errorf("invalid domain %q: empty", orig)
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return "", fmt.Errorf("invalid domain %q: IP addresses are not domains", orig)
	}
	if strings.ContainsAny(d, "/:@ _*") {
		return "", fmt.Errorf("invalid domain %q: contains characters not allowed in a hostname", orig)
	}
	ascii, err := idna.Lookup.ToASCII(d)
	if err != nil {
		return "", fmt.Errorf("invalid domain %q: %v", orig, err)
	}
	if len(ascii) > 253 {
		return "", fmt.Errorf("invalid domain %q: too long", orig)
	}
	for _, label := range strings.Split(ascii, ".") {
		if !dnsname.ValidLabel(label) {
			return "", fmt.Errorf("invalid domain %q: bad label %q", orig, label)
		}
	}
	if suffix, _ := publicsuffix.PublicSuffix(ascii); suffix == ascii {
		return "", fmt.Errorf("invalid domain %q: it is a public suffix, not a registrable domain", orig)
	}
	return ascii, nil
}

// ParseOrg trims an organisation name and requires it to be non-empty.
func ParseOrg(s string) (string, error) {
	o := strings.TrimSpace(s)
	if o == "" {
		return "", fmt.Errorf("invalid organisation %q: empty", s)
	}
	return o, nil
}

// ParseASN accepts "AS123" or "123" (1..4294967295) and returns "AS123".
func ParseASN(s string) (string, error) {
	t := strings.TrimSpace(s)
	t = strings.TrimPrefix(strings.TrimPrefix(t, "AS"), "as")
	n, err := strconv.ParseUint(t, 10, 32)
	if err != nil || n < 1 || strings.HasPrefix(t, "+") {
		return "", fmt.Errorf("invalid ASN %q: want AS<number> in 1..4294967295", s)
	}
	return "AS" + strconv.FormatUint(n, 10), nil
}

// ParseCIDR parses a prefix and masks host bits.
func ParseCIDR(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR %q: %v", s, err)
	}
	return p.Masked(), nil
}

// Exclusion is a hostname, wildcard or CIDR exclusion entry.
type Exclusion struct {
	Entry    string
	host     string
	wildBase string
	prefix   netip.Prefix
	isCIDR   bool
}

// ParseExclusion parses "host.example.com", "*.dev.example.com", a CIDR or a bare IP.
func ParseExclusion(s string) (Exclusion, error) {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return Exclusion{}, fmt.Errorf("invalid exclusion %q: empty", s)
	}
	if a, err := netip.ParseAddr(t); err == nil {
		p := netip.PrefixFrom(a, a.BitLen())
		return Exclusion{Entry: p.String(), prefix: p, isCIDR: true}, nil
	}
	if strings.Contains(t, "/") {
		p, err := netip.ParsePrefix(t)
		if err != nil {
			return Exclusion{}, fmt.Errorf("invalid exclusion %q: %v", s, err)
		}
		p = p.Masked()
		return Exclusion{Entry: p.String(), prefix: p, isCIDR: true}, nil
	}
	name := strings.TrimSuffix(t, ".")
	wild := false
	if rest, ok := strings.CutPrefix(name, "*."); ok {
		name, wild = rest, true
	}
	if name == "" || strings.Contains(name, "*") {
		return Exclusion{}, fmt.Errorf("invalid exclusion %q: wildcards are only allowed as a leading \"*.\"", s)
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) > 63 || label == "" || strings.ContainsAny(label, " /:@") || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return Exclusion{}, fmt.Errorf("invalid exclusion %q: bad hostname", s)
		}
	}
	ascii, err := idna.Lookup.ToASCII(name)
	if err != nil {
		// Underscores are legal in real DNS names even though IDNA rejects them.
		ascii = name
	}
	if wild {
		return Exclusion{Entry: "*." + ascii, wildBase: ascii}, nil
	}
	return Exclusion{Entry: ascii, host: ascii}, nil
}

// MatchesHost reports whether the hostname is excluded by name. CIDR entries never match a name.
func (e Exclusion) MatchesHost(h string) bool {
	h = NormaliseHost(h)
	switch {
	case e.isCIDR:
		return false
	case e.wildBase != "":
		return strings.HasSuffix(h, "."+e.wildBase)
	default:
		return h == e.host
	}
}

// Prefix returns the CIDR of a CIDR exclusion.
func (e Exclusion) Prefix() (netip.Prefix, bool) { return e.prefix, e.isCIDR }

// ReadList reads a file of one entry per line; blank lines and # comments
// (whole-line or trailing) are ignored.
func ReadList(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %v", path, errors.Unwrap(err))
	}
	defer f.Close()
	return ParseList(f)
}

// ParseList is ReadList for an open reader.
func ParseList(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

// Parse validates every input. All errors are reported together, each naming its value.
func Parse(raw Raw) (Parsed, error) {
	var errs []error
	var p Parsed
	first := ""
	setFirst := func(s string) {
		if first == "" {
			first = strings.TrimSpace(s)
		}
	}

	domains := append([]string(nil), raw.Domains...)
	if len(raw.Domains) > 0 {
		setFirst(raw.Domains[0])
	}
	if raw.DomainsFile != "" {
		lines, err := ReadList(raw.DomainsFile)
		if err != nil {
			errs = append(errs, err)
		} else {
			domains = append(domains, lines...)
			if len(lines) > 0 {
				setFirst(lines[0])
			}
		}
	}
	for _, o := range raw.Orgs {
		setFirst(o)
	}
	for _, a := range raw.ASNs {
		if canon, err := ParseASN(a); err == nil {
			setFirst(canon) // "123" and "as123" both name the engagement "as123"
		} else {
			setFirst(a)
		}
	}
	for _, c := range raw.CIDRs {
		setFirst(c)
	}

	set := func(vals []string, parse func(string) (string, error)) []string {
		seen := map[string]bool{}
		var out []string
		for _, v := range vals {
			c, err := parse(v)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
		sort.Strings(out)
		return out
	}
	p.Roots = set(domains, ParseDomain)
	p.Orgs = set(raw.Orgs, ParseOrg)
	p.ASNs = set(raw.ASNs, ParseASN)
	p.CIDRs = set(raw.CIDRs, func(s string) (string, error) {
		pr, err := ParseCIDR(s)
		return pr.String(), err
	})
	excl := append([]string(nil), raw.Exclude...)
	if raw.ExcludeFile != "" {
		lines, err := ReadList(raw.ExcludeFile)
		if err != nil {
			errs = append(errs, err)
		}
		excl = append(excl, lines...)
	}
	p.Exclusions = set(excl, func(s string) (string, error) {
		e, err := ParseExclusion(s)
		return e.Entry, err
	})
	p.First = first
	if len(errs) > 0 {
		return Parsed{}, errors.Join(errs...)
	}
	return p, nil
}

var nameOK = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// ValidateEngagementName checks a name given with -e.
func ValidateEngagementName(name string) error {
	if !nameOK.MatchString(name) || strings.Contains(name, "..") {
		return fmt.Errorf("invalid engagement name %q: must match ^[a-z0-9][a-z0-9._-]*$", name)
	}
	return nil
}

// EngagementName derives a safe directory name from the first input.
func EngagementName(first string) (string, error) {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(first)) {
		switch {
		case r == '/':
			b.WriteByte('_')
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	s := b.String()
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-._")
	if err := ValidateEngagementName(s); err != nil {
		return "", fmt.Errorf("cannot derive an engagement name from %q (use -e)", first)
	}
	return s, nil
}
