package egress_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/scope"
)

// Web services on IP literals. The request is allowed iff the
// address is in an in-scope netblock and not excluded; egress dials that
// address, sends no SNI, and brackets IPv6 in the Host header on every port.

type ipFixture struct {
	srv   *httptest.Server
	port  int
	hits  atomic.Int32
	hosts chan string
	uris  chan string
	sni   atomic.Value
	eg    *egress.Egress
}

// newIPFixture serves one handler on loopback and maps each logical address:port
// in dial onto it. The policy puts blocks in scope and excludes excl.
func newIPFixture(t *testing.T, tlsServer bool, blocks []string, excl []string, ports []int, dial ...string) *ipFixture {
	t.Helper()
	f := &ipFixture{hosts: make(chan string, 64), uris: make(chan string, 64)}
	f.sni.Store("unset")
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		f.hosts <- r.Host
		f.uris <- r.URL.RequestURI()
		if r.URL.Path == "/redirect-in" {
			w.Header().Set("Location", "http://198.51.100.8:8080/landed")
			w.WriteHeader(http.StatusFound)
			return
		}
		if r.URL.Path == "/redirect-out" {
			w.Header().Set("Location", "http://203.0.113.9:8080/landed")
			w.WriteHeader(http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	f.srv = httptest.NewUnstartedServer(h)
	if tlsServer {
		f.srv.TLS = &tls.Config{GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
			f.sni.Store(hi.ServerName)
			return nil, nil
		}}
		f.srv.StartTLS()
	} else {
		f.srv.Start()
	}
	t.Cleanup(f.srv.Close)
	f.port = portOf(t, strings.TrimPrefix(strings.TrimPrefix(f.srv.URL, "https://"), "http://"))
	dm := map[string]string{}
	for _, d := range dial {
		dm[d] = "127.0.0.1:" + strconv.Itoa(f.port)
	}
	var prefixes []netip.Prefix
	for _, b := range blocks {
		prefixes = append(prefixes, netip.MustParsePrefix(b))
	}
	f.eg = egress.New(egress.Options{RatePerHost: 1000, HTTPTimeout: 2 * time.Second, ConnectTimeout: time.Second, DialMap: dm})
	f.eg.SetPolicy(&egress.Policy{
		Scope: scope.New(scope.Config{Roots: []string{"example.com"}, Netblocks: prefixes, Exclusions: mustExcl(t, excl...)}),
		Ack:   true, Ports: ports,
	})
	return f
}

func (f *ipFixture) get(t *testing.T, r egress.Request) egress.HTTPResult {
	t.Helper()
	res, err := f.eg.Clients("t", true, nil).HTTP.Get(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// response is get, failing the test unless the result is a Response.
func (f *ipFixture) response(t *testing.T, r egress.Request) egress.Response {
	t.Helper()
	res, ok := f.get(t, r).(egress.Response)
	if !ok {
		t.Fatalf("not a Response: %#v", f.get(t, r))
	}
	return res
}

func (f *ipFixture) lastHost() string {
	select {
	case h := <-f.hosts:
		return h
	default:
		return ""
	}
}

func TestIPLiteralInScopeIPv4(t *testing.T) {
	f := newIPFixture(t, false, []string{"198.51.100.0/24"}, nil, []int{8080}, "198.51.100.7:8080")
	r, ok := f.get(t, egress.Root("198.51.100.7", "http", 8080)).(egress.Response)
	if !ok || r.Status != 200 || string(r.Body) != "ok" {
		t.Fatalf("response: %#v", r)
	}
	if h := f.lastHost(); h != "198.51.100.7:8080" {
		t.Errorf("Host header = %q, want the literal with its port", h)
	}
}

func TestIPLiteralIPv6HostHeaderIsBracketedOnDefaultPort(t *testing.T) {
	f := newIPFixture(t, false, []string{"2001:db8:1::/64"}, nil, []int{8080}, "[2001:db8:1::5]:80", "[2001:db8:1::5]:8080")
	r, ok := f.get(t, egress.Root("2001:db8:1::5", "http", 80)).(egress.Response)
	if !ok || r.Status != 200 {
		t.Fatalf("response: %#v", r)
	}
	if h := f.lastHost(); h != "[2001:db8:1::5]" {
		t.Errorf("Host header on port 80 = %q, want [2001:db8:1::5]", h)
	}
	if _, ok := f.get(t, egress.Root("2001:db8:1::5", "http", 8080)).(egress.Response); !ok {
		t.Fatal("non-default port refused")
	}
	if h := f.lastHost(); h != "[2001:db8:1::5]:8080" {
		t.Errorf("Host header on port 8080 = %q, want [2001:db8:1::5]:8080", h)
	}
}

func TestIPLiteralLinkStaysOnTheIP(t *testing.T) {
	f := newIPFixture(t, false, []string{"2001:db8:1::/64"}, nil, []int{8080}, "[2001:db8:1::5]:8080")
	r := f.response(t, egress.Root("2001:db8:1::5", "http", 8080))
	req, err := egress.Link(r, "/next?x=1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.get(t, req).(egress.Response); !ok {
		t.Fatal("link on the same IP was refused")
	}
	<-f.uris
	if u := <-f.uris; u != "/next?x=1" {
		t.Errorf("link URI = %q", u)
	}
	if _, err := egress.Link(r, "http://[2001:db8:1::6]:8080/other"); err == nil {
		t.Error("a link to a different IP must be refused by Link")
	}
}

func TestIPLiteralSendsNoSNI(t *testing.T) {
	f := newIPFixture(t, true, []string{"198.51.100.0/24"}, nil, []int{8443}, "198.51.100.7:8443")
	if _, ok := f.get(t, egress.Root("198.51.100.7", "https", 8443)).(egress.Response); !ok {
		t.Fatal("https to an IP literal failed")
	}
	if s := f.sni.Load(); s != "" {
		t.Errorf("SNI for an IP literal = %q, want none", s)
	}
}

// Control for the test above: the fixture does capture an SNI for a hostname.
func TestHostnameStillSendsSNI(t *testing.T) {
	f := newIPFixture(t, true, nil, nil, []int{8443}, "203.0.113.5:8443")
	f.eg.SetPolicy(&egress.Policy{
		Scope: scope.New(scope.Config{Roots: []string{"example.com"}}), Ack: true, Ports: []int{8443},
		Resolutions: map[string][]netip.Addr{"a.example.com": {addr("203.0.113.5")}},
	})
	if _, ok := f.get(t, egress.Root("a.example.com", "https", 8443)).(egress.Response); !ok {
		t.Fatal("https to a hostname failed")
	}
	if s := f.sni.Load(); s != "a.example.com" {
		t.Errorf("SNI = %q, want a.example.com", s)
	}
}

func TestIPLiteralPolicyRefusals(t *testing.T) {
	f := newIPFixture(t, false, []string{"198.51.100.0/24", "2001:db8:1::/64"}, []string{"198.51.100.128/25"}, []int{8080},
		"198.51.100.7:8080", "198.51.100.200:8080", "203.0.113.9:8080", "[2001:db8:2::1]:8080")
	for _, c := range []struct{ name, host string }{
		{"out of scope IPv4", "203.0.113.9"},
		{"out of scope IPv6", "2001:db8:2::1"},
		{"in scope but in an excluded CIDR", "198.51.100.200"},
		{"zoned address", "fe80::1%eth0"},
		{"bracketed literal", "[2001:db8:1::5]"},
	} {
		t.Run(c.name, func(t *testing.T) {
			res := f.get(t, egress.Root(c.host, "http", 8080))
			if _, ok := res.(egress.Refused); !ok {
				t.Errorf("%s: got %#v, want Refused", c.host, res)
			}
		})
	}
	if n := f.hits.Load(); n != 0 {
		t.Errorf("a refused literal reached the server %d times", n)
	}
	if _, ok := f.get(t, egress.Root("198.51.100.7", "http", 8080)).(egress.Response); !ok {
		t.Error("the in-scope, non-excluded neighbour must still be reachable")
	}
}

func TestIPLiteralGateStillApplies(t *testing.T) {
	f := newIPFixture(t, false, []string{"198.51.100.0/24"}, nil, []int{8080}, "198.51.100.7:8080")
	for name, mod := range map[string]func(*egress.Policy){
		"passive":        func(p *egress.Policy) { p.Passive = true },
		"no authorised":  func(p *egress.Policy) { p.Ack = false },
		"port not asked": func(p *egress.Policy) { p.Ports = nil },
	} {
		pol := &egress.Policy{
			Scope: scope.New(scope.Config{Netblocks: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}}),
			Ack:   true, Ports: []int{8080},
		}
		mod(pol)
		f.eg.SetPolicy(pol)
		if res := f.get(t, egress.Root("198.51.100.7", "http", 8080)); !isRefused(res) {
			t.Errorf("%s: got %#v, want Refused", name, res)
		}
	}
	if f.hits.Load() != 0 {
		t.Error("a gated request was sent")
	}
}

func TestIPLiteralRedirectFollowsTheSameRule(t *testing.T) {
	f := newIPFixture(t, false, []string{"198.51.100.0/24"}, nil, []int{8080},
		"198.51.100.7:8080", "198.51.100.8:8080", "203.0.113.9:8080")

	r := redirectFrom(t, f, "/redirect-in")
	req, err := egress.Redirect(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.get(t, req).(egress.Response); !ok {
		t.Error("a redirect to another in-scope IP must be followed")
	}

	r = redirectFrom(t, f, "/redirect-out")
	req, err = egress.Redirect(r)
	if err != nil {
		t.Fatal(err)
	}
	before := f.hits.Load()
	if res := f.get(t, req); !isRefused(res) {
		t.Errorf("a redirect to an out-of-scope IP must be refused: %#v", res)
	}
	if f.hits.Load() != before {
		t.Error("the out-of-scope redirect target was requested")
	}
}

// redirectFrom fetches a path of the fixture's first address to get a redirecting Response.
func redirectFrom(t *testing.T, f *ipFixture, path string) egress.Response {
	t.Helper()
	root := f.response(t, egress.Root("198.51.100.7", "http", 8080))
	req, err := egress.Link(root, path)
	if err != nil {
		t.Fatal(err)
	}
	r := f.response(t, req)
	if r.Status != http.StatusFound {
		t.Fatalf("%s: %#v", path, r)
	}
	return r
}
