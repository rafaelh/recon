package cli_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rafaelh/recon/internal/cli"
	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/testkit"
)

// --- certificates ---

type leafSpec struct {
	cn                  string
	dns, ips            []string
	notBefore, notAfter time.Time // default: 2020-01-01 to farFuture
	isCA                bool
}

var (
	farFuture = time.Date(2037, 6, 1, 12, 0, 0, 0, time.UTC)
	longAgo   = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func serial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func newCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key := newKey(t)
	tpl := &x509.Certificate{
		SerialNumber: serial(t), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: farFuture,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, der: der}
}

func (ls leafSpec) template(t *testing.T) *x509.Certificate {
	t.Helper()
	nb, na := ls.notBefore, ls.notAfter
	if nb.IsZero() {
		nb = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	if na.IsZero() {
		na = farFuture
	}
	tpl := &x509.Certificate{
		SerialNumber: serial(t), Subject: pkix.Name{CommonName: ls.cn},
		NotBefore: nb, NotAfter: na,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: ls.dns,
	}
	for _, ip := range ls.ips {
		tpl.IPAddresses = append(tpl.IPAddresses, net.ParseIP(ip))
	}
	if ls.isCA {
		tpl.IsCA, tpl.BasicConstraintsValid, tpl.KeyUsage = true, true, x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign
	}
	return tpl
}

// issue returns a leaf signed by the CA, presented with the CA in the chain.
func (c *testCA) issue(t *testing.T, ls leafSpec) tls.Certificate {
	t.Helper()
	key := newKey(t)
	der, err := x509.CreateCertificate(rand.Reader, ls.template(t), c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, c.der}, PrivateKey: key}
}

func selfSigned(t *testing.T, ls leafSpec) tls.Certificate {
	t.Helper()
	key := newKey(t)
	tpl := ls.template(t)
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// --- fake servers ---

type webReq struct {
	Method, URI, Host string
	TLS               bool
}

// site is one fake web server, with a log of what reached it.
type site struct {
	mu     sync.Mutex
	reqs   []webReq
	snis   []string
	hellos atomic.Int32 // TLS ClientHellos that reached a fussy or silent server
	conns  atomic.Int32 // connections accepted by a raw TCP server
}

func (s *site) wrap(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.reqs = append(s.reqs, webReq{Method: r.Method, URI: r.URL.RequestURI(), Host: r.Host, TLS: r.TLS != nil})
		s.mu.Unlock()
		h(w, r)
	}
}

func (s *site) requests() []webReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.reqs)
}

func (s *site) hits() int { return len(s.requests()) }

// count is the number of requests for exactly this request URI.
func (s *site) count(uri string) int {
	n := 0
	for _, r := range s.requests() {
		if r.URI == uri {
			n++
		}
	}
	return n
}

// uris are the distinct request URIs, sorted.
func (s *site) uris() []string {
	set := map[string]bool{}
	for _, r := range s.requests() {
		set[r.URI] = true
	}
	out := make([]string, 0, len(set))
	for u := range set {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

func (s *site) hostHeaders() []string {
	set := map[string]bool{}
	for _, r := range s.requests() {
		set[r.Host] = true
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func (s *site) onlyGET() bool {
	for _, r := range s.requests() {
		if r.Method != http.MethodGet {
			return false
		}
	}
	return true
}

func (s *site) sniSeen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.snis)
}

// filterListener hands HTTP connections to the server and gives TLS ones
// (first byte 0x16, a ClientHello) to onTLS, so a test can reset or hang them.
type filterListener struct {
	net.Listener
	ch    chan net.Conn
	done  chan struct{}
	once  sync.Once
	onTLS func(net.Conn)
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func newFilterListener(ln net.Listener, onTLS func(net.Conn)) *filterListener {
	f := &filterListener{Listener: ln, ch: make(chan net.Conn), done: make(chan struct{}), onTLS: onTLS}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.route(c)
		}
	}()
	return f
}

func (f *filterListener) route(c net.Conn) {
	br := bufio.NewReader(c)
	b, err := br.Peek(1)
	if err != nil {
		c.Close()
		return
	}
	if b[0] == 0x16 {
		f.onTLS(c)
		return
	}
	select {
	case f.ch <- &bufConn{Conn: c, r: br}:
	case <-f.done:
		c.Close()
	}
}

func (f *filterListener) Accept() (net.Conn, error) {
	select {
	case c := <-f.ch:
		return c, nil
	case <-f.done:
		return nil, net.ErrClosed
	}
}

func (f *filterListener) Close() error {
	f.once.Do(func() { close(f.done) })
	return f.Listener.Close()
}

// --- the web world ---

type openPort struct{ addr, banner string }

// web is a world with fake web servers. Every address a name resolves to, and
// every port a test declares open, is mapped to a loopback address: a real
// server where the test serves one, and a closed port elsewhere, so nothing
// ever leaves the machine.
type web struct {
	*world
	closed string
	ips    map[string]bool
	ports  map[int]bool
	mapped map[string]bool
	opens  []openPort
	perms  bool
}

func hostPort(ip string, port int) string { return net.JoinHostPort(ip, strconv.Itoa(port)) }

// insertBefore puts s ahead of the stage called name (or last if there is none).
func insertBefore(stages []run.Stage, name string, s run.Stage) []run.Stage {
	for i, st := range stages {
		if st.Name() == name {
			return slices.Insert(slices.Clone(stages), i, s)
		}
	}
	return append(slices.Clone(stages), s)
}

func newWeb(t *testing.T) *web { return newWebWith(t) }

// newWebWith is newWeb with the named Spec 5 stages in the stage list.
func newWebWith(t *testing.T, keep ...string) *web {
	t.Helper()
	w := newWorldWith(t, keep...)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	ln.Close()
	x := &web{world: w, closed: closed, ips: map[string]bool{"203.0.113.250": true}, ports: map[int]bool{}, mapped: map[string]bool{}}
	w.h.eopts.DialMap = map[string]string{}
	fake := &testkit.Stage{StageName: "fakeports", Kind: run.ThirdParty,
		ChecksFn: func(run.View) []run.Check {
			if len(x.opens) == 0 {
				return nil
			}
			return []run.Check{{Key: fmt.Sprintf("ports-%d", len(x.opens))}}
		},
		RunFn: func(context.Context, run.Check, egress.Clients) ([]run.Observation, error) {
			var out []run.Observation
			for _, o := range x.opens {
				ap := mustAddrPort(o.addr)
				out = append(out, run.Observation{Kind: "open_port", Key: ap.String(),
					Attrs: map[string]any{"ip": ap.Addr().String(), "port": int(ap.Port()), "banner": o.banner}})
			}
			return out, nil
		}}
	w.h.stages = insertBefore(w.h.stages, "httpprobe", fake)
	return x
}

// host gives a name addresses and remembers them so they are kept off the network.
func (x *web) host(name string, ips ...string) {
	x.dns.A(name, ips...)
	for _, ip := range ips {
		x.ips[ip] = true
	}
}

// names lists the given names as crt.sh results for example.com.
func (x *web) names(names ...string) {
	x.crtsh(map[string][]string{"example.com": names}, nil)
}

// open declares an open port (what Spec 4's port stage will emit).
func (x *web) open(addr, banner string) {
	ap := mustAddrPort(addr)
	x.ips[ap.Addr().String()] = true
	x.ports[int(ap.Port())] = true
	x.opens = append(x.opens, openPort{addr: addr, banner: banner})
}

func (x *web) mapTo(ip string, port int, real string) {
	key := hostPort(ip, port)
	x.ips[ip] = true
	x.mapped[key] = true
	x.h.eopts.DialMap[key] = real
}

func (x *web) plain(ip string, port int, h http.HandlerFunc) *site {
	x.t.Helper()
	s := &site{}
	srv := httptest.NewServer(s.wrap(h))
	x.t.Cleanup(srv.Close)
	x.mapTo(ip, port, srv.Listener.Addr().String())
	return s
}

func (x *web) secure(ip string, port int, cert tls.Certificate, h http.HandlerFunc) *site {
	x.t.Helper()
	s := &site{}
	srv := httptest.NewUnstartedServer(s.wrap(h))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
		s.mu.Lock()
		s.snis = append(s.snis, hi.ServerName)
		s.mu.Unlock()
		return nil, nil
	}}
	srv.StartTLS()
	x.t.Cleanup(srv.Close)
	x.mapTo(ip, port, srv.Listener.Addr().String())
	return s
}

// fussy serves plain HTTP but answers a TLS ClientHello with a reset ("reset")
// or silence ("hang"), as some plain servers do.
func (x *web) fussy(ip string, port int, mode string, h http.HandlerFunc) *site {
	x.t.Helper()
	s := &site{}
	real, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		x.t.Fatal(err)
	}
	var mu sync.Mutex
	var held []net.Conn
	x.t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			c.Close()
		}
	})
	srv := httptest.NewUnstartedServer(s.wrap(h))
	srv.Listener.Close()
	srv.Listener = newFilterListener(real, func(c net.Conn) {
		s.hellos.Add(1)
		if mode == "reset" {
			c.(*net.TCPConn).SetLinger(0)
			c.Close()
			return
		}
		mu.Lock()
		held = append(held, c)
		mu.Unlock()
	})
	srv.Start()
	x.t.Cleanup(srv.Close)
	x.mapTo(ip, port, real.Addr().String())
	return s
}

// silent accepts TCP connections and closes them at once: an open port that
// is not HTTP.
func (x *web) silent(ip string, port int) *site {
	x.t.Helper()
	s := &site{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		x.t.Fatal(err)
	}
	x.t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.conns.Add(1)
			c.Close()
		}
	}()
	x.mapTo(ip, port, ln.Addr().String())
	return s
}

// fill maps every address:port a probe could try that no test serves to the closed port.
func (x *web) fill() {
	for ip := range x.ips {
		for _, p := range []int{80, 443} {
			x.fillOne(ip, p)
		}
		for p := range x.ports {
			x.fillOne(ip, p)
		}
	}
}

func (x *web) fillOne(ip string, port int) {
	if key := hostPort(ip, port); !x.mapped[key] {
		x.h.eopts.DialMap[key] = x.closed
	}
}

// run executes recon for example.com as an authorised, non-passive run.
// Permutations are off unless a test sets x.perms.
func (x *web) run(args ...string) int {
	x.t.Helper()
	x.fill()
	full := append([]string{"--authorised", "--rate-per-host", "1000"}, args...)
	if !x.perms {
		full = append(full, "--no-permutations")
	}
	return x.world.run(append(full, "example.com")...)
}

func mustAddrPort(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

// --- reading results ---

func (x *web) services() []map[string]string { return x.table(eng, "web-services.csv") }
func (x *web) urls() []map[string]string     { return x.table(eng, "urls.csv") }

func (x *web) service(url string) map[string]string {
	x.t.Helper()
	r := find(x.services(), "url", url)
	if r == nil {
		x.t.Fatalf("web-services.csv has no %s:\n%s", url, x.file(eng, "web-services.csv"))
	}
	return r
}

func (x *web) serviceURLs() []string { return currentURLs(x.services()) }

func (x *web) urlSet() []string { return currentURLs(x.urls()) }

// currentURLs is the sorted url column of the current rows.
func currentURLs(rows []map[string]string) []string {
	var out []string
	for _, r := range rows {
		if r["current"] == "true" {
			out = append(out, r["url"])
		}
	}
	sort.Strings(out)
	return out
}

// observedBy returns the keys of kind observed by stage.
func (x *web) observedBy(kind, stage string) []string {
	x.t.Helper()
	return queryStrings(x.t, x.h.openDB(eng), "SELECT DISTINCT key FROM observations WHERE kind=? AND stage=?", kind, stage)
}

func page(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(body))
	}
}

// routes serves path -> handler, and a 404 for anything else.
func routes(m map[string]http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h, ok := m[r.URL.Path]; ok {
			h(w, r)
			return
		}
		http.NotFound(w, r)
	}
}

func redirectTo(code int, loc string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", loc)
		w.WriteHeader(code)
	}
}

func joinLines(s ...string) string { return strings.Join(s, "\n") }

// defaultStageList is the production stage registry.
func defaultStageList() []run.Stage { return cli.DefaultDeps().Stages }
