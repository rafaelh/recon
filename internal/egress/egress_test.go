package egress_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/rafaelh/recon/internal/config"
	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/scope"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func mustExcl(t *testing.T, entries ...string) []input.Exclusion {
	t.Helper()
	var out []input.Exclusion
	for _, e := range entries {
		x, err := input.ParseExclusion(e)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, x)
	}
	return out
}

func portOf(t *testing.T, hostport string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(p)
	return n
}

// --- DNS (B8) ---

func fakeDNS(t *testing.T, h mdns.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &mdns.Server{PacketConn: pc, Handler: h}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestResolverResults(t *testing.T) {
	var queries atomic.Int32
	srv := fakeDNS(t, func(w mdns.ResponseWriter, r *mdns.Msg) {
		queries.Add(1)
		m := new(mdns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		switch q.Name {
		case "nx.example.com.":
			m.Rcode = mdns.RcodeNameError
		case "nodata.example.com.":
			// NOERROR, no answers
		case "fail.example.com.":
			m.Rcode = mdns.RcodeServerFailure
		case "alias.example.com.":
			m.Answer = append(m.Answer,
				&mdns.CNAME{Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: 60}, Target: "real.example.com."},
				&mdns.A{Hdr: mdns.RR_Header{Name: "real.example.com.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1")})
		}
		_ = w.WriteMsg(m)
	})
	eg := egress.New(egress.Options{ResolverAddrs: []string{srv}, DNSTimeout: 300 * time.Millisecond, RateDNS: 1000})
	dnsc := eg.Clients("t", false, nil).DNS

	res, err := dnsc.Query(context.Background(), "nx.example.com", mdns.TypeA)
	if err != nil || res.RCode != egress.RCodeNXDomain {
		t.Errorf("NXDOMAIN: %+v %v", res, err)
	}
	res, err = dnsc.Query(context.Background(), "nodata.example.com", mdns.TypeA)
	if err != nil || res.RCode != egress.RCodeSuccess || len(res.Answers) != 0 {
		t.Errorf("NODATA: %+v %v", res, err)
	}
	res, err = dnsc.Query(context.Background(), "fail.example.com", mdns.TypeA)
	if err != nil || res.RCode != egress.RCodeServFail {
		t.Errorf("SERVFAIL: %+v %v", res, err)
	}
	res, err = dnsc.Query(context.Background(), "alias.example.com", mdns.TypeA)
	if err != nil || len(res.CNAMEs) != 1 || res.CNAMEs[0] != (egress.CNAME{Name: "alias.example.com", Target: "real.example.com"}) || len(res.Answers) != 1 || res.Answers[0].Value != "192.0.2.1" {
		t.Errorf("CNAME: %+v %v", res, err)
	}
}

func TestResolverTimeoutIsError(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	eg := egress.New(egress.Options{ResolverAddrs: []string{pc.LocalAddr().String()}, DNSTimeout: 100 * time.Millisecond, RateDNS: 1000})
	_, err = eg.Clients("t", false, nil).DNS.Query(context.Background(), "x.example.com", mdns.TypeA)
	if err == nil {
		t.Fatal("timeout must be an error, not a result")
	}
}

func TestResolverHasNoZoneTransfer(t *testing.T) {
	tt := reflect.TypeOf((*egress.Resolver)(nil)).Elem()
	if tt.NumMethod() != 1 || tt.Method(0).Name != "Query" {
		t.Errorf("Resolver has methods beyond Query")
	}
	// A transfer query type must be refused rather than sent.
	srv := fakeDNS(t, func(w mdns.ResponseWriter, r *mdns.Msg) { _ = w.WriteMsg(new(mdns.Msg).SetReply(r)) })
	eg := egress.New(egress.Options{ResolverAddrs: []string{srv}, DNSTimeout: 200 * time.Millisecond, RateDNS: 1000})
	if _, err := eg.Clients("t", false, nil).DNS.Query(context.Background(), "example.com", mdns.TypeAXFR); err == nil {
		t.Error("AXFR must be refused")
	}
}

// --- TCP (B8, B12, B16) ---

func tcpPolicy(t *testing.T, ports ...int) *egress.Policy {
	return &egress.Policy{
		Scope: scope.New(scope.Config{Netblocks: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("192.0.2.0/24")}}),
		Ack:   true,
		Ports: ports,
	}
}

func TestTCPOutcomes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-test\r\n"))
			c.Close()
		}
	}()
	openPort := portOf(t, ln.Addr().String())
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := portOf(t, closed.Addr().String())
	closed.Close()

	eg := egress.New(egress.Options{ConnectTimeout: 300 * time.Millisecond, BannerWait: 500 * time.Millisecond, RatePerHost: 1000,
		DialMap: map[string]string{
			"192.0.2.1:" + strconv.Itoa(closedPort): "10.255.255.1:81",
			"192.0.2.2:" + strconv.Itoa(closedPort): "127.0.0.1:99999",
		}})
	eg.SetPolicy(tcpPolicy(t, openPort, closedPort))
	tcp := eg.Clients("t", true, nil).TCP

	res, err := tcp.Connect(context.Background(), addr("127.0.0.1"), openPort)
	if o, ok := res.(egress.Open); err != nil || !ok || !strings.HasPrefix(string(o.Banner), "SSH-2.0") {
		t.Errorf("open: %#v %v", res, err)
	}
	res, err = tcp.Connect(context.Background(), addr("127.0.0.1"), closedPort)
	if _, ok := res.(egress.Closed); err != nil || !ok {
		t.Errorf("closed: %#v %v", res, err)
	}
	// Anything that is neither a refusal nor a connection is Filtered. An
	// unusable mapped address makes the dial fail without being refused.
	res, err = tcp.Connect(context.Background(), addr("192.0.2.2"), closedPort)
	if _, ok := res.(egress.Filtered); err != nil || !ok {
		t.Errorf("filtered (dial failure): %#v %v", res, err)
	}
	// A genuinely blackholed address times out; skipped where the network answers instead.
	if c, derr := net.DialTimeout("tcp", "10.255.255.1:81", 300*time.Millisecond); derr == nil {
		c.Close()
	} else if ne, ok := derr.(net.Error); ok && ne.Timeout() {
		start := time.Now()
		res, err = tcp.Connect(context.Background(), addr("192.0.2.1"), closedPort)
		if _, ok := res.(egress.Filtered); err != nil || !ok {
			t.Errorf("filtered (timeout): %#v %v", res, err)
		}
		if time.Since(start) > 3*time.Second {
			t.Error("filtered took too long")
		}
	}
}

// B12: port list, scope, passive and ack are enforced.
func TestTCPPolicyRefusals(t *testing.T) {
	p := tcpPolicy(t, 8080)
	eg := egress.New(egress.Options{ConnectTimeout: 100 * time.Millisecond, RatePerHost: 1000})
	eg.SetPolicy(p)
	tcp := eg.Clients("t", true, nil).TCP
	check := func(name string, res egress.TCPResult, err error) {
		t.Helper()
		if _, ok := res.(egress.Refused); err != nil || !ok {
			t.Errorf("%s: want Refused, got %#v %v", name, res, err)
		}
	}
	res, err := tcp.Connect(context.Background(), addr("127.0.0.1"), 9999)
	check("port not in list", res, err)
	res, err = tcp.Connect(context.Background(), addr("8.8.8.8"), 8080)
	check("address out of scope", res, err)

	p2 := tcpPolicy(t, 8080)
	p2.Passive = true
	eg.SetPolicy(p2)
	res, err = tcp.Connect(context.Background(), addr("127.0.0.1"), 8080)
	check("passive", res, err)

	p3 := tcpPolicy(t, 8080)
	p3.Ack = false
	eg.SetPolicy(p3)
	res, err = tcp.Connect(context.Background(), addr("127.0.0.1"), 8080)
	check("no ack", res, err)
}

// B16: addresses of excluded hosts and excluded CIDRs are refused; the guard reports it.
func TestTCPExclusions(t *testing.T) {
	var reported []string
	p := &egress.Policy{
		Scope: scope.New(scope.Config{
			Roots:       []string{"example.com"},
			Netblocks:   []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
			Exclusions:  mustExcl(t, "admin.example.com", "127.0.0.9/32"),
			Resolutions: map[string][]netip.Addr{"admin.example.com": {addr("127.0.0.5")}, "www.example.com": {addr("127.0.0.5"), addr("127.0.0.6")}},
		}),
		Ack:         true,
		Ports:       []int{8080},
		Resolutions: map[string][]netip.Addr{"admin.example.com": {addr("127.0.0.5")}, "www.example.com": {addr("127.0.0.5"), addr("127.0.0.6")}},
		Excluded:    func(v, why string) { reported = append(reported, v+"|"+why) },
	}
	eg := egress.New(egress.Options{ConnectTimeout: 100 * time.Millisecond, RatePerHost: 1000})
	eg.SetPolicy(p)
	tcp := eg.Clients("t", true, nil).TCP
	for _, a := range []string{"127.0.0.5", "127.0.0.9"} {
		res, err := tcp.Connect(context.Background(), addr(a), 8080)
		if _, ok := res.(egress.Refused); err != nil || !ok {
			t.Errorf("%s: want refused, got %#v %v", a, res, err)
		}
	}
	if len(reported) != 2 {
		t.Errorf("guard should report both exclusions: %v", reported)
	}
	res, _ := tcp.Connect(context.Background(), addr("127.0.0.6"), 8080)
	if _, ok := res.(egress.Refused); ok {
		t.Errorf("non-excluded address must be allowed through policy: %#v", res)
	}
}

// --- HTTP (B12, B16) ---

type httpFixture struct {
	srv  *httptest.Server
	port int
	hits atomic.Int32
	eg   *egress.Egress
	pol  *egress.Policy
}

func newHTTPFixture(t *testing.T, h http.HandlerFunc) *httpFixture {
	t.Helper()
	f := &httpFixture{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		h(w, r)
	}))
	t.Cleanup(f.srv.Close)
	f.port = portOf(t, strings.TrimPrefix(f.srv.URL, "http://"))
	res := map[string][]netip.Addr{
		"www.example.com": {addr("127.0.0.1")},
		"a.example.com":   {addr("127.0.0.1")},
		"b.example.com":   {addr("127.0.0.1")},
	}
	f.pol = &egress.Policy{
		Scope:          scope.New(scope.Config{Roots: []string{"example.com"}, Resolutions: res}),
		Ack:            true,
		Ports:          []int{f.port},
		SensitivePaths: []string{"/.git/HEAD", "/server-status"},
		Resolutions:    res,
	}
	f.eg = egress.New(egress.Options{RatePerHost: 1000, HTTPTimeout: 2 * time.Second, ConnectTimeout: time.Second})
	f.eg.SetPolicy(f.pol)
	return f
}

func (f *httpFixture) client() egress.TargetHTTP { return f.eg.Clients("t", true, nil).HTTP }

func TestHTTPRootAndHeaders(t *testing.T) {
	var gotUA, gotAuth, gotCookie, gotMethod, gotHost string
	f := newHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) {
		gotUA, gotAuth, gotCookie, gotMethod, gotHost = r.UserAgent(), r.Header.Get("Authorization"), r.Header.Get("Cookie"), r.Method, r.Host
		http.SetCookie(w, &http.Cookie{Name: "s", Value: "1"})
		w.Header().Set("X-Test", "yes")
		_, _ = w.Write([]byte("hello"))
	})
	res, err := f.client().Get(context.Background(), egress.Root("www.example.com", "http", f.port))
	r, ok := res.(egress.Response)
	if err != nil || !ok || r.Status != 200 || string(r.Body) != "hello" || r.Header["X-Test"][0] != "yes" {
		t.Fatalf("%#v %v", res, err)
	}
	if gotUA == "" || strings.HasPrefix(gotUA, "Go-http-client") || gotAuth != "" || gotCookie != "" || gotMethod != "GET" || !strings.HasPrefix(gotHost, "www.example.com") {
		t.Errorf("request shape: ua=%q auth=%q cookie=%q method=%q host=%q", gotUA, gotAuth, gotCookie, gotMethod, gotHost)
	}
	// No cookie jar: a second request carries no cookie.
	_, _ = f.client().Get(context.Background(), egress.Root("www.example.com", "http", f.port))
	if gotCookie != "" {
		t.Error("cookies must not be replayed")
	}
	res, _ = f.client().Head(context.Background(), egress.Root("www.example.com", "http", f.port))
	if r, ok := res.(egress.Response); !ok || gotMethod != "HEAD" || len(r.Body) != 0 {
		t.Errorf("head: %#v method=%s", res, gotMethod)
	}
}

// RootAt dials only the given address, and only if the name may be reached there.
func TestHTTPRootAtPinsTheAddress(t *testing.T) {
	f := newHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	if res, err := f.client().Get(context.Background(), egress.RootAt("www.example.com", "http", f.port, addr("127.0.0.1"))); err != nil {
		t.Fatal(err)
	} else if r, ok := res.(egress.Response); !ok || r.Status != 200 {
		t.Fatalf("pinned to a permitted address: %#v", res)
	}
	before := f.hits.Load()
	res, err := f.client().Get(context.Background(), egress.RootAt("www.example.com", "http", f.port, addr("127.0.0.2")))
	if err != nil || !isRefused(res) {
		t.Errorf("pinned to an address the name does not resolve to: %#v %v, want Refused", res, err)
	}
	if f.hits.Load() != before {
		t.Error("a refused pinned request reached the server")
	}
}

func TestHTTPSensitivePathAndLink(t *testing.T) {
	var paths []string
	f := newHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.RequestURI())
		_, _ = w.Write([]byte(`<a href="/next">x</a>`))
	})
	svc := egress.Service{Host: "www.example.com", Scheme: "http", Port: f.port}
	_, _ = f.client().Get(context.Background(), egress.SensitivePath(svc, 1))
	if len(paths) != 1 || paths[0] != "/server-status" {
		t.Errorf("sensitive path: %v", paths)
	}
	// Out-of-range index is refused rather than panicking.
	if res, _ := f.client().Get(context.Background(), egress.SensitivePath(svc, 9)); !isRefused(res) {
		t.Errorf("bad index: %#v", res)
	}

	root, _ := f.client().Get(context.Background(), egress.Root("www.example.com", "http", f.port))
	resp := root.(egress.Response)
	req, err := egress.Link(resp, "/next")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.client().Get(context.Background(), req)
	if paths[len(paths)-1] != "/next" {
		t.Errorf("link not followed: %v", paths)
	}
	hits := f.hits.Load()
	if _, err := egress.Link(resp, "http://other.example.com:"+strconv.Itoa(f.port)+"/x"); err == nil {
		t.Error("Link to another host must be refused")
	}
	if _, err := egress.Link(egress.Response{}, "/x"); err == nil {
		t.Error("Link from a Response not produced by egress must be refused")
	}
	if f.hits.Load() != hits {
		t.Error("refused link must not send traffic")
	}
}

func isRefused(res egress.HTTPResult) bool { _, ok := res.(egress.Refused); return ok }

func TestHTTPRedirectNotFollowed(t *testing.T) {
	f := newHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/landing", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("landed"))
	})
	res, _ := f.client().Get(context.Background(), egress.Root("www.example.com", "http", f.port))
	r := res.(egress.Response)
	if r.Status != 302 || r.Location != "/landing" || f.hits.Load() != 1 {
		t.Fatalf("redirect: %+v hits=%d", r, f.hits.Load())
	}
	req, err := egress.Redirect(r)
	if err != nil {
		t.Fatal(err)
	}
	res, _ = f.client().Get(context.Background(), req)
	if r2 := res.(egress.Response); string(r2.Body) != "landed" {
		t.Errorf("explicit redirect: %+v", r2)
	}
	if _, err := egress.Redirect(egress.Response{Status: 200}); err == nil {
		t.Error("no Location, no redirect request")
	}
}

func TestHTTPPolicyRefusals(t *testing.T) {
	f := newHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) {})
	cases := map[string]egress.Request{
		"out of scope host": egress.Root("www.example.org", "http", f.port),
		"port not in list":  egress.Root("www.example.com", "http", 9),
		"bad scheme":        egress.Root("www.example.com", "ftp", f.port),
		"userinfo":          egress.Root("user:pw@www.example.com", "http", f.port),
		"path in host":      egress.Root("www.example.com/x", "http", f.port),
	}
	for name, req := range cases {
		if res, err := f.client().Get(context.Background(), req); err != nil || !isRefused(res) {
			t.Errorf("%s: want Refused, got %#v %v", name, res, err)
		}
	}
	f.pol.Passive = true
	if res, _ := f.client().Get(context.Background(), egress.Root("www.example.com", "http", f.port)); !isRefused(res) {
		t.Error("passive must refuse")
	}
	f.pol.Passive = false
	f.pol.Ack = false
	if res, _ := f.client().Get(context.Background(), egress.Root("www.example.com", "http", f.port)); !isRefused(res) {
		t.Error("missing ack must refuse")
	}
	if f.hits.Load() != 0 {
		t.Errorf("refused requests reached the server %d times", f.hits.Load())
	}
}

func TestHTTPNoService(t *testing.T) {
	f := newHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) {})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := portOf(t, ln.Addr().String())
	ln.Close()
	f.pol.Ports = append(f.pol.Ports, dead)
	res, err := f.client().Get(context.Background(), egress.Root("www.example.com", "http", dead))
	ns, ok := res.(egress.NoService)
	if err != nil || !ok || ns.Reason != egress.NoServiceRefused {
		t.Errorf("%#v %v", res, err)
	}
}

// B16/D9: excluded host's address is refused unless labelled shared.
func TestHTTPExclusionAndSharedInfra(t *testing.T) {
	var reported []string
	f := newHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(r.Host)) })
	res := map[string][]netip.Addr{"www.example.com": {addr("127.0.0.1")}, "admin.example.com": {addr("127.0.0.1")}}
	f.pol.Scope = scope.New(scope.Config{Roots: []string{"example.com"}, Exclusions: mustExcl(t, "admin.example.com"), Resolutions: res})
	f.pol.Resolutions = res
	f.pol.Excluded = func(v, why string) { reported = append(reported, v) }

	if r, _ := f.client().Get(context.Background(), egress.Root("www.example.com", "http", f.port)); !isRefused(r) {
		t.Errorf("non-shared address of an excluded host must be refused: %#v", r)
	}
	if r, _ := f.client().Get(context.Background(), egress.Root("admin.example.com", "http", f.port)); !isRefused(r) {
		t.Error("excluded name must be refused")
	}
	if f.hits.Load() != 0 {
		t.Fatalf("traffic reached the excluded address (%d hits)", f.hits.Load())
	}
	if len(reported) == 0 {
		t.Error("guard should report the address that triggered an exclusion")
	}

	f.pol.Shared = func(a netip.Addr) bool { return a == addr("127.0.0.1") }
	r, _ := f.client().Get(context.Background(), egress.Root("www.example.com", "http", f.port))
	if resp, ok := r.(egress.Response); !ok || !strings.HasPrefix(string(resp.Body), "www.example.com") {
		t.Errorf("shared infra: in-scope host must be allowed: %#v", r)
	}
	if r, _ := f.client().Get(context.Background(), egress.Root("admin.example.com", "http", f.port)); !isRefused(r) {
		t.Error("the excluded hostname itself is never requested, even on shared infra")
	}
}

// Dial map test hook: policy logic sees the real address, the dial goes elsewhere.
func TestHTTPDialMap(t *testing.T) {
	f := newHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	res := map[string][]netip.Addr{"www.example.com": {addr("203.0.113.5")}}
	f.pol.Resolutions = res
	f.pol.Scope = scope.New(scope.Config{Roots: []string{"example.com"}, Resolutions: res})
	eg := egress.New(egress.Options{RatePerHost: 1000, DialMap: map[string]string{"203.0.113.5:" + strconv.Itoa(f.port): "127.0.0.1:" + strconv.Itoa(f.port)}})
	eg.SetPolicy(f.pol)
	r, err := eg.Clients("t", true, nil).HTTP.Get(context.Background(), egress.Root("www.example.com", "http", f.port))
	if resp, ok := r.(egress.Response); err != nil || !ok || string(resp.Body) != "ok" {
		t.Errorf("%#v %v", r, err)
	}
}

// B12: API shape. No method other than Get/Head, no raw URLs, no connections.
func TestTargetAPIShape(t *testing.T) {
	ht := reflect.TypeOf((*egress.TargetHTTP)(nil)).Elem()
	var names []string
	for i := 0; i < ht.NumMethod(); i++ {
		names = append(names, ht.Method(i).Name)
	}
	if strings.Join(names, ",") != "Get,Head" {
		t.Errorf("TargetHTTP methods = %v", names)
	}
	reqT := reflect.TypeOf((*egress.Request)(nil)).Elem()
	for i := 0; i < ht.NumMethod(); i++ {
		if ht.Method(i).Type.In(1) != reqT {
			t.Errorf("%s must take the typed Request", ht.Method(i).Name)
		}
	}
	// Request can't be implemented outside the package.
	for i := 0; i < reqT.NumMethod(); i++ {
		if reqT.Method(i).IsExported() {
			t.Errorf("Request has exported method %s; it must not be implementable externally", reqT.Method(i).Name)
		}
	}
	tt := reflect.TypeOf((*egress.TargetTCP)(nil)).Elem()
	if tt.NumMethod() != 1 || tt.Method(0).Name != "Connect" {
		t.Error("TargetTCP must expose only Connect")
	}
	for _, v := range []any{egress.Open{}, egress.Closed{}, egress.Filtered{}, egress.Refused{}} {
		ty := reflect.TypeOf(v)
		for i := 0; i < ty.NumField(); i++ {
			ft := ty.Field(i).Type
			if ft.Implements(reflect.TypeOf((*net.Conn)(nil)).Elem()) || ft.Kind() == reflect.Interface {
				t.Errorf("%s exposes a connection-like field %s", ty, ty.Field(i).Name)
			}
		}
		if reflect.PointerTo(ty).Implements(reflect.TypeOf((*interface{ Write([]byte) (int, error) })(nil)).Elem()) {
			t.Errorf("%s is writable", ty)
		}
	}
	c := egress.Clients{}
	ct := reflect.TypeOf(c)
	for i := 0; i < ct.NumField(); i++ {
		switch ct.Field(i).Name {
		case "DNS", "ThirdParty", "HTTP", "TCP":
		default:
			t.Errorf("unexpected Clients field %s", ct.Field(i).Name)
		}
	}
}

// B12/D14: Target clients are only given to Target stages.
func TestClientsForThirdPartyStageHaveNoTargetClients(t *testing.T) {
	eg := egress.New(egress.Options{})
	c := eg.Clients("s", false, []string{"stat.ripe.net"})
	if c.HTTP != nil || c.TCP != nil {
		t.Error("ThirdParty stage must not get Target clients")
	}
	if c.ThirdParty == nil || c.DNS == nil {
		t.Error("ThirdParty and DNS clients expected")
	}
	c = eg.Clients("s", true, nil)
	if c.HTTP == nil || c.TCP == nil {
		t.Error("Target stage gets Target clients")
	}
}

// --- ThirdPartyHTTP (B12) ---

func TestThirdParty(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.RequestURI(), r.Method
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	eg := egress.New(egress.Options{SourceBaseURLs: map[string]string{"stat.ripe.net": srv.URL, "*.s3.amazonaws.com": srv.URL}, RatePerSource: 1000})
	eg.SetPolicy(&egress.Policy{
		Scope:      scope.New(scope.Config{Roots: []string{"example.com"}, Exclusions: mustExcl(t, "bad.example.net")}),
		Candidates: map[string]bool{"cand.example.org": true},
	})
	c := eg.Clients("asn", false, []string{"stat.ripe.net", "*.s3.amazonaws.com"}).ThirdParty

	resp, err := c.Do(context.Background(), egress.ThirdPartyRequest{Method: "GET", URL: "https://stat.ripe.net/data/x.json?resource=AS1"})
	if err != nil || resp.Status != 200 || string(resp.Body) != `{"ok":true}` || gotPath != "/data/x.json?resource=AS1" {
		t.Fatalf("%+v %v path=%s", resp, err, gotPath)
	}
	if _, err = c.Do(context.Background(), egress.ThirdPartyRequest{Method: "GET", URL: "https://bucket.s3.amazonaws.com/"}); err != nil {
		t.Errorf("wildcard source: %v", err)
	}
	if _, err = c.Do(context.Background(), egress.ThirdPartyRequest{Method: "POST", URL: "https://stat.ripe.net/q", Body: []byte("{}")}); err != nil || gotMethod != "POST" {
		t.Errorf("POST: %v %s", err, gotMethod)
	}
	hits := gotPath
	for name, req := range map[string]egress.ThirdPartyRequest{
		"host outside sources": {Method: "GET", URL: "https://evil.example.net/"},
		"in-scope host":        {Method: "GET", URL: "https://www.example.com/"},
		"candidate host":       {Method: "GET", URL: "https://cand.example.org/"},
		"excluded host":        {Method: "GET", URL: "https://bad.example.net/"},
		"method":               {Method: "DELETE", URL: "https://stat.ripe.net/"},
		"userinfo":             {Method: "GET", URL: "https://u:p@stat.ripe.net/"},
	} {
		if _, err := c.Do(context.Background(), req); err == nil {
			t.Errorf("%s should be refused", name)
		}
	}
	if gotPath != hits {
		t.Error("refused requests were sent")
	}
	// A source that is itself in scope is refused too.
	c2 := eg.Clients("x", false, []string{"www.example.com"}).ThirdParty
	if _, err := c2.Do(context.Background(), egress.ThirdPartyRequest{Method: "GET", URL: "https://www.example.com/"}); err == nil {
		t.Error("in-scope host must be refused even if listed in Sources()")
	}
}

func TestThirdPartyDoesNotFollowRedirects(t *testing.T) {
	var other atomic.Int32
	o := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { other.Add(1) }))
	defer o.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, o.URL, http.StatusFound) }))
	defer srv.Close()
	eg := egress.New(egress.Options{SourceBaseURLs: map[string]string{"src.example.net": srv.URL}, RatePerSource: 1000})
	eg.SetPolicy(&egress.Policy{Scope: scope.New(scope.Config{})})
	resp, err := eg.Clients("s", false, []string{"src.example.net"}).ThirdParty.Do(context.Background(), egress.ThirdPartyRequest{Method: "GET", URL: "https://src.example.net/"})
	if err != nil || resp.Status != 302 || other.Load() != 0 {
		t.Errorf("%+v %v other=%d", resp, err, other.Load())
	}
}

func TestThirdPartyKeyScrubbedFromErrors(t *testing.T) {
	// Server closed: the transport error includes the URL, which includes the key.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	base := srv.URL
	srv.Close()
	eg := egress.New(egress.Options{SourceBaseURLs: map[string]string{"api.example.net": base}, RatePerSource: 1000, Redactor: newRedactor("KEY-12345")})
	eg.SetPolicy(&egress.Policy{Scope: scope.New(scope.Config{})})
	_, err := eg.Clients("s", false, []string{"api.example.net"}).ThirdParty.Do(context.Background(), egress.ThirdPartyRequest{Method: "GET", URL: "https://api.example.net/x?key=KEY-12345"})
	if err == nil || strings.Contains(err.Error(), "KEY-12345") {
		t.Errorf("error must be scrubbed: %v", err)
	}
}

func TestThirdPartyEncodedKeyScrubbedFromErrors(t *testing.T) {
	// A key sent as a query parameter appears percent-encoded in the transport error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	base := srv.URL
	srv.Close()
	const key = "abc+def/ghi="
	eg := egress.New(egress.Options{SourceBaseURLs: map[string]string{"api.example.net": base}, RatePerSource: 1000,
		Keys: map[string]config.Secret{"src": key}, Redactor: newRedactor(key)})
	eg.SetPolicy(&egress.Policy{Scope: scope.New(scope.Config{})})
	_, err := eg.Clients("s", false, []string{"api.example.net"}).ThirdParty.Do(context.Background(),
		egress.ThirdPartyRequest{Method: "GET", URL: "https://api.example.net/x", KeySource: "src", KeyParam: "key"})
	if err == nil || strings.Contains(err.Error(), "abc") {
		t.Errorf("error must be scrubbed: %v", err)
	}
}

// --- Rate limits (B21) ---

func TestPerIPRateLimit(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := portOf(t, ln.Addr().String())
	eg := egress.New(egress.Options{RatePerHost: 20, ConnectTimeout: time.Second, BannerWait: 20 * time.Millisecond})
	eg.SetPolicy(tcpPolicy(t, port))
	tcp := eg.Clients("t", true, nil).TCP
	start := time.Now()
	for i := 0; i < 5; i++ {
		_, _ = tcp.Connect(context.Background(), addr("127.0.0.1"), port)
	}
	if el := time.Since(start); el < 180*time.Millisecond {
		t.Errorf("5 connects at 20/s took %v; want >= 200ms", el)
	}
}

func TestVhostsShareALimiter(t *testing.T) {
	f := newHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) {})
	f.eg = egress.New(egress.Options{RatePerHost: 20, HTTPTimeout: 2 * time.Second})
	f.eg.SetPolicy(f.pol)
	c := f.client()
	start := time.Now()
	for i := 0; i < 3; i++ {
		_, _ = c.Get(context.Background(), egress.Root("a.example.com", "http", f.port))
		_, _ = c.Get(context.Background(), egress.Root("b.example.com", "http", f.port))
	}
	if el := time.Since(start); el < 220*time.Millisecond {
		t.Errorf("6 requests to one IP across two vhosts took %v; want >= 250ms", el)
	}
}

// Waiting for a rate-limit token does not count against HTTPTimeout.
func TestRateLimitWaitOutsideHTTPTimeout(t *testing.T) {
	f := newHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	f.eg = egress.New(egress.Options{RatePerHost: 4, HTTPTimeout: 150 * time.Millisecond})
	f.eg.SetPolicy(f.pol)
	c := f.client()
	for i := 0; i < 2; i++ { // the second request waits ~250ms for its token
		res, err := c.Get(context.Background(), egress.Root("www.example.com", "http", f.port))
		if r, ok := res.(egress.Response); err != nil || !ok || string(r.Body) != "ok" {
			t.Fatalf("request %d: %#v %v", i, res, err)
		}
	}
}

// A body cut short is a transient error, not a (truncated) Response.
func TestHTTPTruncatedBodyIsError(t *testing.T) {
	f := newHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte("partial"))
		w.(http.Flusher).Flush()
		time.Sleep(time.Second)
	})
	f.eg = egress.New(egress.Options{RatePerHost: 1000, HTTPTimeout: 200 * time.Millisecond})
	f.eg.SetPolicy(f.pol)
	res, err := f.client().Get(context.Background(), egress.Root("www.example.com", "http", f.port))
	if err == nil {
		t.Errorf("want error, got %#v", res)
	}
}

// A sensitive path that is not absolute could change the request's host.
func TestRelativeSensitivePathRefused(t *testing.T) {
	f := newHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) {})
	f.pol.SensitivePaths = []string{"admin/.env", "@other.com/x"}
	f.eg.SetPolicy(f.pol)
	for i := range f.pol.SensitivePaths {
		svc := egress.Service{Host: "www.example.com", Scheme: "http", Port: f.port}
		res, err := f.client().Get(context.Background(), egress.SensitivePath(svc, i))
		if _, ok := res.(egress.Refused); err != nil || !ok {
			t.Errorf("%s: %#v %v", f.pol.SensitivePaths[i], res, err)
		}
	}
	if f.hits.Load() != 0 {
		t.Errorf("hits = %d", f.hits.Load())
	}
}

// HTTPS: verification is skipped for the connection but the chain is checked separately.
func TestHTTPSCertVerifyErrReported(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("secure")) }))
	defer srv.Close()
	port := portOf(t, strings.TrimPrefix(srv.URL, "https://"))
	res := map[string][]netip.Addr{"www.example.com": {addr("127.0.0.1")}}
	eg := egress.New(egress.Options{RatePerHost: 1000, HTTPTimeout: 2 * time.Second})
	eg.SetPolicy(&egress.Policy{
		Scope: scope.New(scope.Config{Roots: []string{"example.com"}, Resolutions: res}),
		Ack:   true, Ports: []int{port}, Resolutions: res,
	})
	r, err := eg.Clients("t", true, nil).HTTP.Get(context.Background(), egress.Root("www.example.com", "https", port))
	resp, ok := r.(egress.Response)
	if err != nil || !ok || string(resp.Body) != "secure" {
		t.Fatalf("%#v %v", r, err)
	}
	if len(resp.PeerCerts) == 0 || resp.CertVerifyErr == "" {
		t.Errorf("self-signed certificate must be fetched and flagged: certs=%d verifyErr=%q", len(resp.PeerCerts), resp.CertVerifyErr)
	}
	// A non-TLS port spoken to as https is NoService, not an error.
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer plain.Close()
	pp := portOf(t, strings.TrimPrefix(plain.URL, "http://"))
	eg.SetPolicy(&egress.Policy{
		Scope: scope.New(scope.Config{Roots: []string{"example.com"}, Resolutions: res}),
		Ack:   true, Ports: []int{pp}, Resolutions: res,
	})
	r, err = eg.Clients("t", true, nil).HTTP.Get(context.Background(), egress.Root("www.example.com", "https", pp))
	if ns, ok := r.(egress.NoService); err != nil || !ok || ns.Reason != egress.NoServiceTLSFailed {
		t.Errorf("tls failure: %#v %v", r, err)
	}
}
