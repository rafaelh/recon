package dns

import (
	"context"
	"testing"
	"time"

	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/egress/egresstest"
	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/scope"
)

// A permutation whose CNAME dangles (NXDOMAIN) exists, and is a takeover
// candidate; a plain NXDOMAIN does not.
func TestPermutationsKeepDanglingCNAME(t *testing.T) {
	d := egresstest.NewDNS(t)
	d.CNAME("dev.example.com", "gone.herokuapp.com")
	d.A("www.example.com", "203.0.113.1")
	eg := egress.New(egress.Options{ResolverAddrs: []string{d.Addr}, DNSTimeout: 300 * time.Millisecond, RateDNS: 100000})
	eg.SetPolicy(&egress.Policy{Scope: scope.New(scope.Config{})})
	c := run.Check{Key: "k", Input: permInput{kind: "root", name: "example.com", words: []string{"dev", "www", "nope"}}}
	obs, err := NewPermutations().Run(context.Background(), c, eg.Clients("t", false, nil))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, o := range obs {
		got = append(got, o.Key)
	}
	if len(got) != 2 || got[0] != "dev.example.com" || got[1] != "www.example.com" {
		t.Errorf("hostnames = %v, want dev (dangling CNAME) and www", got)
	}
}
