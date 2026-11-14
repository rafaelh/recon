package orgname_test

import (
	"slices"
	"testing"

	"github.com/rafaelh/recon/internal/orgname"
)

func TestTokens(t *testing.T) {
	for org, want := range map[string][]string{
		"Acme Pty Ltd":         {"acme"},
		"Acme, Inc.":           {"acme"},
		"Big-Co Holdings GmbH": {"big", "holdings"},
		"  ACME   widgets ":    {"acme", "widgets"},
		"Ltd":                  nil,
		"":                     nil,
	} {
		if got := orgname.Tokens(org); !slices.Equal(got, want) {
			t.Errorf("Tokens(%q) = %v, want %v", org, got, want)
		}
	}
}

// A name matches when it contains every word of the organisation, whatever
// else it holds. An organisation with no words matches nothing.
func TestMatches(t *testing.T) {
	for _, c := range []struct {
		org, name string
		want      bool
	}{
		{"Acme Pty Ltd", "ACME NETWORKS LTD", true},
		{"Acme Widgets", "ACME-NET", false},
		{"Acme Widgets", "Acme Widgets Australia", true},
		{"Acme", "Roadrunner Pty", false},
		{"Ltd", "Ltd", false},
		{"", "anything", false},
	} {
		if got := orgname.Matches(c.org, c.name); got != c.want {
			t.Errorf("Matches(%q, %q) = %v, want %v", c.org, c.name, got, c.want)
		}
	}
}
