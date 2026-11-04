// Package dnsname has the pure name manipulation DNS stages need: reverse
// names, parent zones, registrable domains and permutation generation.
package dnsname

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// ReverseName is the PTR owner name of an address (in-addr.arpa or ip6.arpa).
func ReverseName(a netip.Addr) string { return reverse(a) + suffix(a, "in-addr.arpa", "ip6.arpa") }

// CymruOrigin is the Team Cymru origin TXT name of an address.
func CymruOrigin(a netip.Addr) string {
	return reverse(a) + suffix(a, "origin.asn.cymru.com", "origin6.asn.cymru.com")
}

func suffix(a netip.Addr, v4, v6 string) string {
	if a.Unmap().Is4() {
		return "." + v4
	}
	return "." + v6
}

func reverse(a netip.Addr) string {
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
	}
	b := a.As16()
	var parts []string
	for i := 15; i >= 0; i-- {
		parts = append(parts, fmt.Sprintf("%x", b[i]&0xf), fmt.Sprintf("%x", b[i]>>4))
	}
	return strings.Join(parts, ".")
}

// ETLDPlusOne is the registrable domain of name.
func ETLDPlusOne(name string) (string, bool) {
	d, err := publicsuffix.EffectiveTLDPlusOne(strings.ToLower(strings.TrimSuffix(name, ".")))
	return d, err == nil
}

// Parents returns the ancestors of name, nearest first, down to and including
// its registrable domain. A registrable domain (or a public suffix) has none.
func Parents(name string) []string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	reg, ok := ETLDPlusOne(name)
	if !ok {
		return nil
	}
	var out []string
	for name != reg {
		_, rest, found := strings.Cut(name, ".")
		if !found {
			break
		}
		name = rest
		out = append(out, name)
	}
	return out
}

// ValidLabel reports whether s is a valid hostname label.
func ValidLabel(s string) bool {
	if s == "" || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// Permute returns up to max variants of label built with words: digit
// changes first, then joins with "-", ".", or nothing, word before and after.
// The output is deterministic, unique, valid, and never contains label itself.
// A "." join yields two labels (the name is label.word.parent), checked per part.
func Permute(label string, words []string, max int) []string {
	var out []string
	seen := map[string]bool{label: true}
	add := func(s string) bool {
		if seen[s] {
			return true
		}
		for _, part := range strings.Split(s, ".") {
			if !ValidLabel(part) {
				return true
			}
		}
		seen[s] = true
		out = append(out, s)
		return len(out) < max
	}
	if max <= 0 {
		return nil
	}
	for _, d := range digitVariants(label) {
		if !add(d) {
			return out
		}
	}
	for _, w := range words {
		for _, v := range []string{label + "-" + w, w + "-" + label, label + "." + w, w + "." + label, label + w, w + label} {
			if !add(v) {
				return out
			}
		}
	}
	return out
}

func digitVariants(label string) []string {
	i := len(label)
	for i > 0 && label[i-1] >= '0' && label[i-1] <= '9' {
		i--
	}
	base, digits := label[:i], label[i:]
	if digits == "" {
		return []string{label + "1", label + "2"}
	}
	n, err := strconv.Atoi(digits)
	if err != nil {
		return nil
	}
	pad := func(v int) string { return fmt.Sprintf("%s%0*d", base, len(digits), v) }
	out := []string{pad(n + 1), pad(n + 2)}
	if n > 0 {
		out = append(out, pad(n-1))
	}
	return out
}
