package config

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ParsePorts parses a comma-separated list of ports and ranges ("80,443,8000-8100").
// The result is sorted and de-duplicated.
func ParsePorts(s string) ([]int, error) {
	return parsePortItems(strings.Split(s, ","))
}

func parsePortItems(items []string) ([]int, error) {
	set := map[int]bool{}
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		lo, hi := it, it
		if a, b, ok := strings.Cut(it, "-"); ok {
			lo, hi = a, b
		}
		l, err1 := strconv.Atoi(strings.TrimSpace(lo))
		h, err2 := strconv.Atoi(strings.TrimSpace(hi))
		if err1 != nil || err2 != nil || l < 1 || h > 65535 || l > h {
			return nil, fmt.Errorf("%q is not a port or range within 1-65535", it)
		}
		for p := l; p <= h; p++ {
			set[p] = true
		}
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

// FormatPorts renders ports with consecutive runs compressed ("21-23,80").
func FormatPorts(ports []int) string {
	ps := append([]int(nil), ports...)
	sort.Ints(ps)
	var parts []string
	for i := 0; i < len(ps); {
		j := i
		for j+1 < len(ps) && ps[j+1] == ps[j]+1 {
			j++
		}
		if j > i {
			parts = append(parts, fmt.Sprintf("%d-%d", ps[i], ps[j]))
		} else {
			parts = append(parts, strconv.Itoa(ps[i]))
		}
		i = j + 1
	}
	return strings.Join(parts, ",")
}

// portsFlag is a pflag.Value that keeps the raw text; Load parses and
// validates it so errors name the setting.
type portsFlag struct {
	raw     *string
	touched *bool
}

func (p portsFlag) String() string {
	if p.raw == nil {
		return ""
	}
	return *p.raw
}

func (p portsFlag) Set(s string) error {
	if *p.touched && *p.raw != "" {
		*p.raw += "," + s
	} else {
		*p.raw = s
	}
	*p.touched = true
	return nil
}

func (p portsFlag) Type() string { return "ports" }

// top100 is the nmap top 100 TCP ports plus the five default risky ports that
// are not among them (1521, 6379, 9200, 11211 and 27017), so every risky port is
// scanned by default.
var top100 = []int{
	7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199,
	389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
	1025, 1026, 1027, 1028, 1029, 1110, 1433, 1521, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717,
	3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666,
	5800, 5900, 6000, 6001, 6379, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9200, 9999, 10000,
	11211, 27017, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
}

// DefaultPorts returns the default TCP port list (about the top 100, 105 ports).
func DefaultPorts() []int { return append([]int(nil), top100...) }

var defaultRisky = []int{21, 23, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017}
