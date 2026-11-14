// Package orgname is the word rule that decides whether a name belongs to an
// organisation input: the name must contain every word of the organisation,
// ignoring case, punctuation and legal suffixes ("Pty", "Ltd", "Inc"). Stages
// that look an organisation up in a registry apply it to the registry's names,
// so they all keep the same matches.
package orgname

import (
	"regexp"
	"strings"
)

var legalSuffix = map[string]bool{
	"inc": true, "llc": true, "ltd": true, "limited": true, "corp": true, "corporation": true, "co": true,
	"company": true, "plc": true, "gmbh": true, "sa": true, "ag": true, "pty": true, "pte": true, "bv": true, "nv": true,
}

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// Tokens are the lower-case words of an organisation name without legal suffixes.
func Tokens(org string) []string {
	var out []string
	for _, t := range nonAlnum.Split(strings.ToLower(org), -1) {
		if t != "" && !legalSuffix[t] {
			out = append(out, t)
		}
	}
	return out
}

// Matches reports whether name contains every word of org. An organisation
// with no words (only legal suffixes, or nothing) matches nothing.
func Matches(org, name string) bool {
	want := Tokens(org)
	if len(want) == 0 {
		return false
	}
	name = strings.ToLower(name)
	for _, t := range want {
		if !strings.Contains(name, t) {
			return false
		}
	}
	return true
}
