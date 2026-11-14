package candidates_test

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/recon/internal/candidates"
)

func ev(pairs ...string) []candidates.Evidence {
	var out []candidates.Evidence
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, candidates.Evidence{Source: pairs[i], Item: pairs[i+1]})
	}
	return out
}

// The rules of confidence, one row per rule and one per edge of a rule.
func TestScore(t *testing.T) {
	acme := []string{"Acme Pty Ltd"}
	cases := []struct {
		name  string
		ev    []candidates.Evidence
		orgs  []string
		want  candidates.Confidence
		count int
	}{
		{"registrant match joined by another family", ev("whoisxml", "Acme Pty Ltd", "certspotter", "k"), acme, candidates.High, 2},
		{"registrant match joined by reverse ip on one address", ev("org-asn", "Acme Pty Ltd", "reverseip", "198.51.100.1"), acme, candidates.High, 2},
		{"three families", ev("crtsh", "a", "wayback", "b", "otx", "c"), nil, candidates.High, 3},
		{"two families", ev("crtsh", "a", "wayback", "b"), nil, candidates.Medium, 2},
		{"registrant match alone", ev("whoisxml", "Acme Pty Ltd"), acme, candidates.Medium, 1},
		{"two registrant sources are one family", ev("whoisxml", "Acme Pty Ltd", "org-asn", "Acme Pty Ltd"), acme, candidates.Medium, 2},
		{"no --org: a registrant source alone is one signal", ev("whoisxml", "Acme Pty Ltd"), nil, candidates.Low, 1},
		{"no --org: registrant plus another family is two families", ev("whoisxml", "Acme Pty Ltd", "crtsh", "a"), nil, candidates.Medium, 2},
		{"registrant evidence about another organisation is not a match", ev("rdap", "Other Org", "crtsh", "a"), acme, candidates.Medium, 2},
		{"registrant evidence about another organisation alone", ev("rdap", "Other Org"), acme, candidates.Low, 1},
		{"reverse ip on two addresses", ev("reverseip", "198.51.100.1", "reverseip", "198.51.100.2"), nil, candidates.Medium, 2},
		{"reverse ip on one address", ev("reverseip", "198.51.100.1"), nil, candidates.Low, 1},
		{"shared name server or mail host", ev("nsreverse", "ns1.other.org"), nil, candidates.Medium, 1},
		{"one source", ev("crtsh", "a"), nil, candidates.Low, 1},
		{"one source, several items, is one family", ev("crtsh", "a", "crtsh", "b"), nil, candidates.Low, 2},
		{"two sources of one family", ev("crtsh", "a", "certspotter", "a"), nil, candidates.Low, 2},
		{"the same pair twice counts once", ev("crtsh", "a", "crtsh", "a"), nil, candidates.Low, 1},
		{"sources outside the table are their own family", ev("httpprobe", "a.example.com:443", "rdns", "198.51.100.9"), nil, candidates.Medium, 2},
		{"three sources outside the table", ev("httpprobe", "a", "rdns", "b", "crawl", "c"), nil, candidates.High, 3},
		{"no evidence", nil, acme, candidates.Low, 0},
	}
	for _, c := range cases {
		got := candidates.Score(c.ev, c.orgs)
		if got.Confidence != c.want || got.Count != c.count {
			t.Errorf("%s: got %s with %d evidence, want %s with %d", c.name, got.Confidence, got.Count, c.want, c.count)
		}
	}
}

func TestScoreSources(t *testing.T) {
	got := candidates.Score(ev("wayback", "a", "crtsh", "b", "crtsh", "c", "wayback", "a"), nil)
	if want := []string{"crtsh", "wayback"}; !slices.Equal(got.Sources, want) {
		t.Errorf("sources = %v, want the distinct sources sorted: %v", got.Sources, want)
	}
}

func TestFamily(t *testing.T) {
	for source, want := range map[string]string{
		"crtsh": "certificate transparency", "certspotter": "certificate transparency", "censys": "certificate transparency",
		"wayback": "web archive", "commoncrawl": "web archive",
		"otx": "passive dns", "virustotal": "passive dns", "securitytrails": "passive dns", "shodan": "passive dns",
		"chaos": "passive dns", "urlscan": "passive dns", "anubis": "passive dns", "hackertarget": "passive dns",
		"reverseip": "reverse ip",
		"rdap":      "registrant", "whoisxml": "registrant", "org-asn": "registrant",
		"nsreverse":        "shared infrastructure",
		"identifier-pivot": "web identifier",
		"httpprobe":        "httpprobe", "rdns": "rdns", "something-new": "something-new",
	} {
		if got := candidates.Family(source); got != want {
			t.Errorf("Family(%q) = %q, want %q", source, got, want)
		}
	}
}

// high first, then more evidence, then value; a row that is not current is
// last whatever it had, and keeps its own confidence.
func TestCompare(t *testing.T) {
	rows := []candidates.Entry{
		{Value: "gone-high.org", Confidence: candidates.High, Count: 9, Current: false},
		{Value: "low-many.org", Confidence: candidates.Low, Count: 7, Current: true},
		{Value: "med-b.org", Confidence: candidates.Medium, Count: 2, Current: true},
		{Value: "high-few.org", Confidence: candidates.High, Count: 3, Current: true},
		{Value: "med-a.org", Confidence: candidates.Medium, Count: 2, Current: true},
		{Value: "high-many.org", Confidence: candidates.High, Count: 5, Current: true},
		{Value: "gone-low.org", Confidence: candidates.Low, Count: 1, Current: false},
	}
	slices.SortFunc(rows, candidates.Compare)
	var got []string
	for _, r := range rows {
		got = append(got, r.Value)
	}
	want := []string{"high-many.org", "high-few.org", "med-a.org", "med-b.org", "low-many.org", "gone-high.org", "gone-low.org"}
	if !slices.Equal(got, want) {
		t.Errorf("order = %v\nwant    %v", got, want)
	}
}

func TestPromote(t *testing.T) {
	for _, c := range []struct{ typ, value, want string }{
		{"root", "other.org", "other.org"},
		{"hostname", "www.other.org", "www.other.org"},
		{"netblock", "198.51.100.0/24", "--cidr 198.51.100.0/24"},
		{"asn", "AS64500", "--asn AS64500"},
		{"organisation", "Acme", "--org Acme"},
		{"organisation", "Acme Pty Ltd", "--org 'Acme Pty Ltd'"},
		{"organisation", "O'Neil & Sons", `--org 'O'\''Neil & Sons'`},
	} {
		if got := candidates.Promote(c.typ, c.value); got != c.want {
			t.Errorf("Promote(%q, %q) = %q, want %q", c.typ, c.value, got, c.want)
		}
	}
}

// The README lists every source the sources column can hold, so adding one to
// the family table without documenting it fails here.
func TestREADMEListsEverySource(t *testing.T) {
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range candidates.Sources() {
		if !strings.Contains(string(b), "`"+s+"`") {
			t.Errorf("README.md does not list the candidate source `%s`", s)
		}
	}
}
