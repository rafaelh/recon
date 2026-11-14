// Package candidates ranks the candidates (roots, hostnames and netblocks
// found but not in scope) by how many independent signals support them. It is
// pure: it reads no store, scope or file.
//
// A candidate's evidence is a list of (source, item) pairs: the source is the
// stage or mechanism that observed it, the item is what linked it (an
// organisation, an address, a netblock, a root, a service). Sources are grouped
// into families, and the confidence is decided by how many families agree and
// by which. See Score for the rules.
package candidates

import (
	"cmp"
	"maps"
	"slices"
	"strings"
)

// Confidence is how far a candidate's evidence supports promoting it to scope.
type Confidence string

// The confidence levels.
const (
	Low    Confidence = "low"
	Medium Confidence = "medium"
	High   Confidence = "high"
)

func (c Confidence) rank() int {
	switch c {
	case High:
		return 0
	case Medium:
		return 1
	}
	return 2
}

// Evidence is one source and the item that linked the candidate.
type Evidence struct{ Source, Item string }

// Rank is the ranking of one candidate.
type Rank struct {
	Sources    []string // the distinct sources, sorted
	Count      int      // the distinct (source, item) pairs
	Confidence Confidence
}

// The families. A source outside the table is a family of its own, named after it.
const (
	certTransparency = "certificate transparency"
	webArchive       = "web archive"
	passiveDNS       = "passive dns"
	reverseIP        = "reverse ip"
	registrant       = "registrant"
	sharedInfra      = "shared infrastructure"
	webIdentifier    = "web identifier"
)

// families maps a source (a stage name, or the mechanism a stage reports) to
// its family. A source that is its own family is listed with its own name, so
// that Sources lists every value the sources column can hold. org-asn is a
// registrant source on the assumption that RIPEstat's organisation search
// matches registry organisation names; ct-org searches certificates by their
// organisation, so it is a certificate transparency source.
var families = map[string]string{
	"crtsh": certTransparency, "certspotter": certTransparency, "censys": certTransparency, "ct-org": certTransparency,
	"wayback": webArchive, "commoncrawl": webArchive,
	"otx": passiveDNS, "virustotal": passiveDNS, "securitytrails": passiveDNS, "shodan": passiveDNS,
	"shodan-dns": passiveDNS, "chaos": passiveDNS, "urlscan": passiveDNS, "anubis": passiveDNS, "hackertarget": passiveDNS,
	"reverseip":        reverseIP,
	"rdap":             registrant,
	"whoisxml":         registrant,
	"org-asn":          registrant,
	"nsreverse":        sharedInfra,
	"identifier-pivot": webIdentifier,
	// Their own families.
	"httpprobe": "httpprobe", "rdns": "rdns", "crawl": "crawl",
}

// Family is the family a source belongs to.
func Family(source string) string {
	if f, ok := families[source]; ok {
		return f
	}
	return source
}

// Sources lists every source the family table names, sorted: the values the
// sources column can hold for a stage this package knows.
func Sources() []string {
	out := make([]string, 0, len(families))
	for s := range families {
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

// Score ranks a candidate's evidence. orgs are the --org inputs.
//
// The confidence is high when a registrant-family match of an input
// organisation is joined by any other family, or three or more families agree;
// medium with two families, or a shared name server or mail host, or reverse IP
// on two or more addresses, or a registrant match alone; low otherwise. A
// registrant match is evidence from a registrant-family source whose item is an
// input organisation, that is, a source that was asked about that organisation
// (a registry lookup applies the word rule of package orgname to the names it
// gets back where it can; a search by organisation name leaves it to the
// service), so without an --org input the rule never applies. A shared
// name server or mail host is shared-infrastructure evidence: its stage reports
// only self-hosted ones.
func Score(ev []Evidence, orgs []string) Rank {
	pairs := map[Evidence]bool{}
	sources := map[string]bool{}
	fams := map[string]bool{}
	reverseItems := map[string]bool{}
	match := false
	for _, e := range ev {
		if pairs[e] {
			continue
		}
		pairs[e] = true
		sources[e.Source] = true
		f := Family(e.Source)
		fams[f] = true
		switch f {
		case reverseIP:
			reverseItems[e.Item] = true
		case registrant:
			match = match || slices.Contains(orgs, e.Item)
		}
	}
	r := Rank{Sources: slices.Sorted(maps.Keys(sources)), Count: len(pairs), Confidence: Low}
	switch {
	case match && len(fams) > 1, len(fams) >= 3:
		r.Confidence = High
	case len(fams) == 2, fams[sharedInfra], len(reverseItems) >= 2, match:
		r.Confidence = Medium
	}
	return r
}

// Entry is what the sort order looks at.
type Entry struct {
	Value      string
	Current    bool
	Confidence Confidence
	Count      int
}

// Compare is the sort order of candidates.csv: rows that are current first,
// then high before medium before low, then more evidence, then by value. A row
// that is not current keeps the confidence it last had, and sorts last.
func Compare(a, b Entry) int {
	switch {
	case a.Current != b.Current:
		if a.Current {
			return -1
		}
		return 1
	}
	return cmp.Or(
		cmp.Compare(a.Confidence.rank(), b.Confidence.rank()),
		cmp.Compare(b.Count, a.Count),
		strings.Compare(a.Value, b.Value),
	)
}

// Promote is the input that brings a candidate of the type into scope, as the
// user would type it: a root or hostname as a positional domain, a netblock as
// --cidr, an autonomous system as --asn and an organisation as --org.
func Promote(typ, value string) string {
	switch typ {
	case "netblock":
		return "--cidr " + shell(value)
	case "asn":
		return "--asn " + shell(value)
	case "organisation":
		return "--org " + shell(value)
	}
	return value
}

// shell quotes s for a POSIX shell when it needs it.
func shell(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/-") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
