package dns_test

import (
	"context"
	"net/netip"
	"regexp"
	"testing"
	"time"

	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/egress/egresstest"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/scope"
	"github.com/rafaelh/recon/internal/stages/dns"
	"github.com/rafaelh/recon/internal/store"
)

func clients(t *testing.T, d *egresstest.DNS) egress.Clients {
	t.Helper()
	eg := egress.New(egress.Options{ResolverAddrs: []string{d.Addr}, DNSTimeout: 300 * time.Millisecond, RateDNS: 100000})
	eg.SetPolicy(&egress.Policy{Scope: scope.New(scope.Config{})})
	return eg.Clients("t", false, nil)
}

// The probe labels come from an injectable source; there are always two, and they differ.
func TestWildcardProbeLabels(t *testing.T) {
	d := egresstest.NewDNS(t)
	labels := []string{"aaaa", "aaaa", "bbbb"} // the second draw repeats the first
	i := 0
	st := dns.NewWildcard(func() string { l := labels[i]; i++; return l })
	obs, err := st.Run(context.Background(), run.Check{Key: "example.com"}, clients(t, d))
	if err != nil || len(obs) != 0 {
		t.Fatalf("no wildcard: %+v %v", obs, err)
	}
	if got := d.Queried("A"); len(got) != 2 || got[0] != "aaaa.example.com" || got[1] != "bbbb.example.com" {
		t.Errorf("probes = %v", got)
	}
}

func TestDefaultWildcardLabelsAreRandom16(t *testing.T) {
	d := egresstest.NewDNS(t)
	d.Wildcard("example.com", "203.0.113.1")
	obs, err := dns.NewWildcard(nil).Run(context.Background(), run.Check{Key: "example.com"}, clients(t, d))
	if err != nil || len(obs) != 1 || obs[0].Kind != "wildcard" || obs[0].Key != "example.com" {
		t.Fatalf("%+v %v", obs, err)
	}
	re := regexp.MustCompile(`^[0-9a-f]{16}\.example\.com$`)
	for _, n := range d.Queried("A") {
		if !re.MatchString(n) {
			t.Errorf("probe name %q is not a random 16-char label", n)
		}
	}
	if addrs := kinds.Wildcard.Attrs(store.Record{Attrs: obs[0].Attrs}).Addrs; len(addrs) != 1 || addrs[0] != "203.0.113.1" {
		t.Errorf("attrs = %v", obs[0].Attrs)
	}
}

// A SERVFAIL on a probe is a transient failure, never "not a wildcard".
func TestWildcardServFailIsAnError(t *testing.T) {
	d := egresstest.NewDNS(t)
	d.RcodeSuffix("example.com", 2) // SERVFAIL
	if obs, err := dns.NewWildcard(nil).Run(context.Background(), run.Check{Key: "example.com"}, clients(t, d)); err == nil {
		t.Errorf("a SERVFAIL probe must fail the check, got %+v", obs)
	}
}

// A probe that answered proves the wildcard even if another probe SERVFAILs.
func TestWildcardAnswerWinsOverServFail(t *testing.T) {
	d := egresstest.NewDNS(t)
	d.Wildcard("example.com", "203.0.113.1")
	d.Rcode("bbbb.example.com", 2) // SERVFAIL
	labels := []string{"aaaa", "bbbb"}
	i := 0
	st := dns.NewWildcard(func() string { l := labels[i]; i++; return l })
	obs, err := st.Run(context.Background(), run.Check{Key: "example.com"}, clients(t, d))
	if err != nil || len(obs) != 1 || obs[0].Kind != "wildcard" {
		t.Errorf("want the wildcard recorded: %+v %v", obs, err)
	}
}

// A wildcard CNAME that dangles (NXDOMAIN) is still a wildcard, so the
// permutations it makes "exist" come out wildcard-only.
func TestWildcardDanglingCNAME(t *testing.T) {
	d := egresstest.NewDNS(t)
	d.WildcardCNAME("example.com", "gone.herokuapp.com")
	obs, err := dns.NewWildcard(nil).Run(context.Background(), run.Check{Key: "example.com"}, clients(t, d))
	if err != nil || len(obs) != 1 || obs[0].Kind != "wildcard" || obs[0].Attrs["cname"] != "gone.herokuapp.com" {
		t.Fatalf("want the wildcard recorded with its cname: %+v %v", obs, err)
	}
}

// A resolver failure is transient; an address Cymru does not know is a result.
func TestIPOwnerFailureModes(t *testing.T) {
	d := egresstest.NewDNS(t)
	st := dns.NewIPOwner()
	chk := run.Check{Key: "203.0.113.5", Input: mustAddr("203.0.113.5")}
	if obs, err := st.Run(context.Background(), chk, clients(t, d)); err != nil || len(obs) != 0 {
		t.Errorf("unknown address (NXDOMAIN): %+v %v", obs, err)
	}
	d.RcodeSuffix("asn.cymru.com", 2) // SERVFAIL
	if _, err := st.Run(context.Background(), chk, clients(t, d)); err == nil {
		t.Error("a SERVFAIL must be a transient failure")
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
