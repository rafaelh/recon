package cli_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/rafaelh/recon/internal/config"
	"github.com/rafaelh/recon/internal/dnsname"
	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/testkit"
)

// Spec 4: open ports. The tests drive cli.Execute with the real ports stage
// and a loopback listener behind egress's DialMap for every address and port
// the sweep may dial, so nothing leaves the machine. Every listener counts the
// connections it accepted, which is how the tests see what was contacted.

// portSrv is a loopback TCP server standing in for one or more address:port pairs.
type portSrv struct {
	ln    net.Listener
	conns atomic.Int32
	bytes atomic.Int64 // bytes the clients sent
}

func (s *portSrv) Close() { s.ln.Close() }

// pworld is the web world with the real ports stage in place of fakeports.
type pworld struct {
	*web
	mu        sync.Mutex
	seq       []string // accepted connections in order, "ip:port"
	cur, peak int
}

func newPorts(t *testing.T) *pworld {
	t.Helper()
	x := newWeb(t)
	var ports run.Stage
	for _, s := range defaultStageList() {
		if s.Name() == "ports" {
			ports = s
		}
	}
	if ports == nil {
		t.Fatal("the ports stage is not in the default registry")
	}
	stages := slices.DeleteFunc(slices.Clone(x.h.stages), func(s run.Stage) bool { return s.Name() == "fakeports" })
	i := slices.IndexFunc(stages, func(s run.Stage) bool { return s.Name() == "crawl" })
	if i < 0 {
		t.Fatal("no crawl stage")
	}
	x.h.stages = slices.Insert(stages, i+1, ports)
	// Connect and banner timeouts are short in the harness; a banner that arrives
	// late in a test is still inside the wait.
	x.h.eopts.BannerWait = 300 * time.Millisecond
	return &pworld{web: x}
}

// listen starts a server. A banner is sent after delay; with no banner the
// server hangs up at once, like a service that is open but not talking.
func (p *pworld) listen(key, banner string, delay time.Duration) *portSrv {
	return p.listenOn("127.0.0.1:0", key, banner, delay)
}

func (p *pworld) listenOn(bind, key, banner string, delay time.Duration) *portSrv {
	p.t.Helper()
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		p.t.Fatal(err)
	}
	p.t.Cleanup(func() { ln.Close() })
	s := &portSrv{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				p.mu.Lock()
				p.seq = append(p.seq, key)
				p.cur++
				p.peak = max(p.peak, p.cur)
				p.mu.Unlock()
				s.conns.Add(1)
				defer func() { p.mu.Lock(); p.cur--; p.mu.Unlock() }()
				if banner == "" {
					return
				}
				time.Sleep(delay)
				_, _ = c.Write([]byte(banner))
				n, _ := io.Copy(io.Discard, c) // until the client hangs up
				s.bytes.Add(n)
			}()
		}
	}()
	return s
}

// serve answers on ip:port with banner (or silently, hanging up, if it is empty).
func (p *pworld) serve(ip string, port int, banner string) *portSrv {
	return p.serveSlow(ip, port, banner, 0)
}

func (p *pworld) serveSlow(ip string, port int, banner string, delay time.Duration) *portSrv {
	s := p.listen(hostPort(ip, port), banner, delay)
	p.mapTo(ip, port, s.ln.Addr().String())
	p.ports[port] = true
	return s
}

// canary maps ip on every port to one server that must never be contacted.
func (p *pworld) canary(ip string, ports []int) *portSrv {
	s := p.listen(ip, "CANARY\r\n", 0)
	for _, port := range ports {
		p.mapTo(ip, port, s.ln.Addr().String())
		p.ports[port] = true
	}
	return s
}

// filter makes ip:port unanswered: the dial fails without being refused.
func (p *pworld) filter(ip string, port int) {
	p.mapTo(ip, port, "127.0.0.1:99999")
	p.ports[port] = true
}

func (p *pworld) addrs(ips ...string) {
	for _, ip := range ips {
		p.ips[ip] = true
	}
}

func (p *pworld) peakConns() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.peak
}

func (p *pworld) sequence() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.seq)
}

// sweep runs recon with the given port list and requires success.
func (p *pworld) sweep(ports []int, args ...string) {
	p.t.Helper()
	var list []string
	for _, port := range ports {
		p.ports[port] = true
		list = append(list, strconv.Itoa(port))
	}
	p.mustRun(append([]string{"--ports", strings.Join(list, ",")}, args...)...)
}

// keys are the check keys (and open_port keys) for each address on each port.
func portKeys(ips []string, ports []int) []string {
	var out []string
	for _, ip := range ips {
		for _, port := range ports {
			out = append(out, netip.AddrPortFrom(netip.MustParseAddr(ip), uint16(port)).String())
		}
	}
	sort.Strings(out)
	return out
}

func (p *pworld) checked() []string { return sorted(p.completedKeys("ports")) }

func (p *pworld) openPortRows() []map[string]string { return p.table(eng, "open-ports.csv") }

// openPortKeys are the current open-ports.csv rows as "ip:port".
func (p *pworld) openPortKeys() []string {
	var out []string
	for _, r := range p.openPortRows() {
		if r["current"] == "true" {
			port, _ := strconv.Atoi(r["port"])
			out = append(out, netip.AddrPortFrom(netip.MustParseAddr(r["ip"]), uint16(port)).String())
		}
	}
	sort.Strings(out)
	return out
}

func (p *pworld) stageState(name string) (string, string) { return stateOf(p.world, name) }

const hello = "HELLO\r\n"

// --- registration ---

// D1: the stage runs after crawl (and, since Spec 5 D4, after the Target stages
// that follow it), so a long sweep does not delay probing of hostnames.
func TestPortsD1_RegisteredAfterCrawl(t *testing.T) {
	var names []string
	for _, s := range defaultStageList() {
		names = append(names, s.Name())
	}
	n := len(names)
	if n < 2 || names[n-1] != "ports" || slices.Index(names, "crawl") > n-2 || slices.Index(names, "crawl") < 0 {
		t.Errorf("stage order ends %v, want ports last, after crawl", names[max(0, n-4):])
	}
	for _, s := range defaultStageList() {
		if s.Name() == "ports" && s.Contact() != run.Target {
			t.Error("ports must be a Target stage, so passive mode and the ack gate it")
		}
	}
}

// D8: both flags are documented, and ports is a stage --redo accepts.
func TestPortsD8_Help(t *testing.T) {
	h := newHarness(t, defaultStageList()...)
	if code := h.exec("--help"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	out := h.stdout.String()
	for _, want := range []string{"--port-concurrency", "workers per stage (ports: --port-concurrency)", "--ports", "ports"} {
		if !strings.Contains(out, want) {
			t.Errorf("help missing %q", want)
		}
	}
	if !strings.Contains(out, "Stages accepted by --redo:") || !strings.Contains(out, ", ports") {
		t.Errorf("help does not list ports as a --redo stage:\n%s", out)
	}
}

// D8: a stage that implements run.WorkerCounter gets that many workers; others get --concurrency.
type withWorkers struct {
	*testkit.Stage
	n int
}

func (w withWorkers) Workers(config.Settings) int { return w.n }

func TestPortsD8_WorkerCounter(t *testing.T) {
	slow := func(context.Context, run.Check, egress.Clients) ([]run.Observation, error) {
		time.Sleep(60 * time.Millisecond)
		return nil, nil
	}
	counted := &testkit.Stage{StageName: "counted", Kind: run.ThirdParty, ChecksFn: func(run.View) []run.Check { return testkit.Keys("c", 12) }, RunFn: slow}
	plain := &testkit.Stage{StageName: "plain", Kind: run.ThirdParty, ChecksFn: func(run.View) []run.Check { return testkit.Keys("p", 12) }, RunFn: slow}
	h := newHarness(t, withWorkers{counted, 5}, plain)
	if code := h.exec("a.com", "--json", "--concurrency", "2"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if got := counted.MaxActive(); got != 5 {
		t.Errorf("a WorkerCounter stage ran %d at once, want 5", got)
	}
	if got := plain.MaxActive(); got != 2 {
		t.Errorf("a stage without Workers ran %d at once, want --concurrency (2)", got)
	}
}

// --- B1: which addresses and ports ---

// B1/D2: the addresses checked are the eligible ones, no more and no fewer.
func TestPortsB1_AddressSet(t *testing.T) {
	p := newPorts(t)
	ports := []int{8080, 9999}
	p.names("app.example.com", "cdn.example.com", "ex.example.com", "wild1.w.example.com", "v6.example.com")
	p.host("app.example.com", "203.0.113.7") // hostname-resolved
	p.owner("203.0.113.7", 64500, "ACME-NET")
	p.host("cdn.example.com", "104.16.0.5") // shared provider infrastructure
	p.owner("104.16.0.5", 13335, "CLOUDFLARENET")
	p.host("ex.example.com", "203.0.113.70") // inside an excluded CIDR
	p.owner("203.0.113.70", 64500, "ACME-NET")
	p.dns.Wildcard("w.example.com", "203.0.113.99") // only a wildcard-only name resolves here
	p.owner("203.0.113.99", 64500, "ACME-NET")
	p.addrs("203.0.113.99")
	p.host("v6.example.com", "2001:db8:1::5") // IPv6, inside an in-scope netblock
	p.addrs("198.51.100.0", "198.51.100.1", "198.51.100.2")

	var never []*portSrv
	for _, ip := range []string{"198.51.100.3", "104.16.0.5", "203.0.113.70", "203.0.113.99"} {
		never = append(never, p.canary(ip, ports))
	}
	p.sweep(ports, "--cidr", "198.51.100.0/30", "--cidr", "2001:db8:1::/64", "-x", "198.51.100.3/32", "-x", "203.0.113.64/28")

	netblock := []string{"198.51.100.0", "198.51.100.1", "198.51.100.2"}
	eligible := []string{"203.0.113.7", "203.0.113.250", "2001:db8:1::5"}
	if got, want := p.checked(), portKeys(append(slices.Clone(netblock), eligible...), ports); !slices.Equal(got, want) {
		t.Errorf("checked = %v\nwant     %v", got, want)
	}
	for i, s := range never {
		if s.conns.Load() != 0 {
			t.Errorf("canary %d (an excluded, shared or wildcard-only address) was contacted", i)
		}
	}
	// ips.csv and the sweep cannot disagree (Spec 2 D18).
	checked := map[string]bool{}
	for _, k := range p.checked() {
		ap, _ := netip.ParseAddrPort(k)
		checked[ap.Addr().String()] = true
	}
	for _, r := range p.table(eng, "ips.csv") {
		if want := r["port_eligible"] == "true"; checked[r["ip"]] != want {
			t.Errorf("ips.csv %s port_eligible=%s but checked=%v", r["ip"], r["port_eligible"], checked[r["ip"]])
		}
	}
}

// B1: IPv6 is checked like IPv4, over a real IPv6 socket. ::1 is in the in-scope
// netblock ::1/128 and is found through the AAAA record of a name.
func TestPortsB1_IPv6(t *testing.T) {
	p := newPorts(t)
	if ln, err := net.Listen("tcp", "[::1]:0"); err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	} else {
		ln.Close()
	}
	p.names("v6.example.com")
	p.host("v6.example.com", "::1")
	srv := p.listenOn("[::1]:0", "[::1]:8080", "SSH-2.0-v6\r\n", 0)
	p.mapTo("::1", 8080, srv.ln.Addr().String())
	p.sweep([]int{8080}, "--cidr", "::1/128")
	if got := p.openPortKeys(); !slices.Contains(got, "[::1]:8080") {
		t.Errorf("open ports = %v, want [::1]:8080 among them", got)
	}
	if srv.conns.Load() != 1 || !slices.Contains(p.checked(), "[::1]:8080") {
		t.Errorf("IPv6 address not checked: conns=%d checked=%v", srv.conns.Load(), p.checked())
	}
}

// B1/D2: an address whose owner is not known is skipped with a warning, then checked once it is.
func TestPortsB1_UnknownOwnerSkippedThenChecked(t *testing.T) {
	p := newPorts(t)
	p.names("u.example.com")
	p.host("u.example.com", "192.0.2.77")
	origin := dnsname.CymruOrigin(mustAddr("192.0.2.77"))
	p.dns.Rcode(origin, int(mdns.RcodeServerFailure)) // the owner source is down
	srv := p.serve("192.0.2.77", 8080, hello)

	p.sweep([]int{8080}, "--verbose")
	if srv.conns.Load() != 0 {
		t.Fatal("an address of unknown owner was contacted")
	}
	if slices.Contains(p.checked(), "192.0.2.77:8080") {
		t.Error("an address of unknown owner must not be completed as checked")
	}
	var warned bool
	for _, e := range ofType(p.h.events(), "warning") {
		if m := e.str("message"); strings.HasPrefix(m, "ports: 1 address") && strings.Contains(m, "owner is unknown") {
			warned = true
		}
	}
	if s := lastState(p.h.events(), "ports"); s != nil && s.num("failed") != 0 {
		t.Errorf("a held-back address is not a failed check: %v", s)
	}
	if !warned {
		t.Errorf("no warning that 1 address was skipped for its unknown owner: %v", ofType(p.h.events(), "warning"))
	}

	p.dns.ClearRcode(origin)
	p.owner("192.0.2.77", 64500, "ACME-NET")
	p.sweep([]int{8080})
	if srv.conns.Load() != 1 || !slices.Contains(p.checked(), "192.0.2.77:8080") {
		t.Errorf("once its owner is known the address is checked: conns=%d checked=%v", srv.conns.Load(), p.checked())
	}
}

// B1/D4: every listed port is checked, port by port (not host by host).
func TestPortsB1_PortMajorOrder(t *testing.T) {
	p := newPorts(t)
	p.names("app.example.com")
	p.host("app.example.com", "203.0.113.7")
	p.owner("203.0.113.7", 64500, "ACME-NET")
	for _, port := range []int{8080, 9999} {
		for _, ip := range []string{"203.0.113.250", "203.0.113.7"} {
			p.serve(ip, port, hello)
		}
	}
	p.sweep([]int{9999, 8080}, "--port-concurrency", "1")

	seq := p.sequence()
	if len(seq) != 4 {
		t.Fatalf("connections = %v, want 4", seq)
	}
	portOf := func(s string) string { return s[strings.LastIndex(s, ":")+1:] }
	addrOf := func(s string) string { return s[:strings.LastIndex(s, ":")] }
	if portOf(seq[0]) != "8080" || portOf(seq[1]) != "8080" || portOf(seq[2]) != "9999" || portOf(seq[3]) != "9999" {
		t.Errorf("order = %v, want every address on 8080, then every address on 9999", seq)
	}
	if addrOf(seq[0]) != addrOf(seq[2]) || addrOf(seq[1]) != addrOf(seq[3]) || addrOf(seq[0]) == addrOf(seq[1]) {
		t.Errorf("addresses are not in the same order for each port: %v", seq)
	}
}

// B1/D3: adding a port creates only the new checks.
func TestPortsB1_AddedPortChecksOnlyTheNewPort(t *testing.T) {
	p := newPorts(t)
	s8080 := p.serve("203.0.113.250", 8080, hello)
	s9999 := p.serve("203.0.113.250", 9999, hello)
	p.sweep([]int{8080})
	p.sweep([]int{8080, 9999})
	if s8080.conns.Load() != 1 || s9999.conns.Load() != 1 {
		t.Errorf("connections: 8080=%d 9999=%d, want 1 and 1", s8080.conns.Load(), s9999.conns.Load())
	}
	if s := lastState(p.h.events(), "ports"); s == nil || s.num("checks") != 1 {
		t.Errorf("second run ports state = %v, want one new check", s)
	}
	if got, want := p.checked(), portKeys([]string{"203.0.113.250"}, []int{8080, 9999}); !slices.Equal(got, want) {
		t.Errorf("checked = %v, want %v", got, want)
	}
}

// B1/D8: --port-concurrency bounds the connects in flight; --concurrency still bounds other stages.
func TestPortsB1_WorkerBounds(t *testing.T) {
	p := newPorts(t)
	p.h.eopts.BannerWait = 500 * time.Millisecond
	var ports []int
	for port := 8001; port <= 8012; port++ {
		ports = append(ports, port)
		p.serveSlow("203.0.113.250", port, hello, 120*time.Millisecond)
	}
	other := &testkit.Stage{StageName: "other", Kind: run.ThirdParty,
		ChecksFn: func(run.View) []run.Check { return testkit.Keys("o", 8) },
		RunFn: func(context.Context, run.Check, egress.Clients) ([]run.Observation, error) {
			time.Sleep(60 * time.Millisecond)
			return nil, nil
		}}
	p.h.stages = append(p.h.stages, other)
	p.sweep(ports, "--concurrency", "2", "--port-concurrency", "4")

	if got := p.peakConns(); got < 3 || got > 4 {
		t.Errorf("connects in flight peaked at %d, want 4 (--port-concurrency) and never more", got)
	}
	if got := other.MaxActive(); got != 2 {
		t.Errorf("another stage ran %d at once, want --concurrency (2)", got)
	}
}

// B1: not run in passive mode, and not with an empty port list.
func TestPortsB1_Gates(t *testing.T) {
	p := newPorts(t)
	srv := p.serve("203.0.113.250", 8080, hello)

	p.mustRun("--ports", "8080", "--passive")
	if st, why := p.stageState("ports"); st != "not-configured" || why != "passive-only" {
		t.Errorf("passive: ports = %s (%s)", st, why)
	}
	p.mustRun("--ports", "")
	if st, why := p.stageState("ports"); st != "not-configured" || why != "no ports" {
		t.Errorf("no ports: ports = %s (%s)", st, why)
	}
	if srv.conns.Load() != 0 {
		t.Error("the port sweep contacted a target when it was not configured")
	}
}

// --- B2: banners and completed checks ---

func TestPortsB2_Banners(t *testing.T) {
	p := newPorts(t)
	sent := map[int]string{
		7001: "SSH-2.0-OpenSSH_9.6\r\n",
		7002: "\x00\n\x00\x00\n5.7.1-binary\xff\x00", // a MySQL-style greeting
		7003: "caf\xe9 \xc3(",                        // invalid UTF-8
		7004: "",                                     // open, says nothing
	}
	for port, banner := range sent {
		p.serve("203.0.113.250", port, banner)
	}
	// 7005 refuses (closed); 7006 never answers (filtered).
	p.ports[7005] = true
	p.filter("203.0.113.250", 7006)
	p.sweep([]int{7001, 7002, 7003, 7004, 7005, 7006})

	attrs := p.obsAttrs(eng, "open_port")
	if len(attrs) != 4 {
		t.Fatalf("open_port records = %v, want only the 4 open ports", attrs)
	}
	for port, banner := range sent {
		key := "203.0.113.250:" + strconv.Itoa(port)
		var a struct {
			IP     string `json:"ip"`
			Port   int    `json:"port"`
			Banner string `json:"banner"`
		}
		if err := json.Unmarshal([]byte(attrs[key]), &a); err != nil {
			t.Fatalf("%s: %v (%q)", key, err, attrs[key])
		}
		if a.IP != "203.0.113.250" || a.Port != port {
			t.Errorf("%s attrs = %+v", key, a)
		}
		back, err := strconv.Unquote(`"` + a.Banner + `"`)
		if err != nil || back != banner {
			t.Errorf("%s: banner %q does not reverse to %q (%v)", key, a.Banner, banner, err)
		}
		if banner == "" && a.Banner != "" {
			t.Errorf("%s: a silent port has banner %q", key, a.Banner)
		}
	}
	if !strings.Contains(attrs["203.0.113.250:7001"], `"banner":"SSH-2.0-OpenSSH_9.6\\r\\n"`) {
		t.Errorf("printable text must stay readable: %s", attrs["203.0.113.250:7001"])
	}
	if got, want := p.checked(), portKeys([]string{"203.0.113.250"}, []int{7001, 7002, 7003, 7004, 7005, 7006}); !slices.Equal(got, want) {
		t.Errorf("closed and filtered ports must complete too: %v, want %v", got, want)
	}
}

// B2: a closed or filtered port is recorded as checked and not retried.
func TestPortsB2_CompletedChecksAreNotRetried(t *testing.T) {
	p := newPorts(t)
	open := p.serve("203.0.113.250", 7001, hello)
	p.ports[7005] = true // closed
	p.filter("203.0.113.250", 7006)
	p.sweep([]int{7001, 7005, 7006})
	if s := lastState(p.h.events(), "ports"); s == nil || s.str("state") != "done" || s.num("checks") != 3 || s.num("failed") != 0 {
		t.Errorf("first run: %v", s)
	}
	if got := p.openPortKeys(); !slices.Equal(got, []string{"203.0.113.250:7001"}) {
		t.Errorf("open ports = %v", got)
	}
	p.sweep([]int{7001, 7005, 7006})
	if s := lastState(p.h.events(), "ports"); s == nil || s.str("state") != "done-previously" {
		t.Errorf("second run: %v, want every check skipped (done-previously)", s)
	}
	if open.conns.Load() != 1 {
		t.Errorf("open port contacted %d times, want 1", open.conns.Load())
	}
}

// B2: --redo ports re-checks, and a port that has since closed is no longer current.
func TestPortsB2_RedoMarksClosedPortNotCurrent(t *testing.T) {
	p := newPorts(t)
	srv := p.serve("203.0.113.250", 7001, hello)
	p.sweep([]int{7001})
	if got := p.openPortKeys(); !slices.Equal(got, []string{"203.0.113.250:7001"}) {
		t.Fatalf("open ports = %v", got)
	}
	srv.Close()
	p.sweep([]int{7001}, "--redo", "ports")
	if got := p.openPortKeys(); len(got) != 0 {
		t.Errorf("a port that has closed is still current: %v", got)
	}
	rows := p.openPortRows()
	if len(rows) != 1 || rows[0]["current"] != "false" {
		t.Errorf("the closed port must stay in the file as not current: %v", rows)
	}
}

// refusedTCP is a TargetTCP whose policy refuses everything.
type refusedTCP struct{}

func (refusedTCP) Connect(context.Context, netip.Addr, int) (egress.TCPResult, error) {
	return egress.Refused{Reason: "test"}, nil
}

// refusingPorts hands the ports stage a TCP client that refuses while refuse is set.
type refusingPorts struct {
	run.Stage
	refuse *atomic.Bool
}

func (r refusingPorts) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	if r.refuse.Load() {
		e.TCP = refusedTCP{}
	}
	return r.Stage.Run(ctx, c, e)
}

// B2/D5: checks are filtered by the same policy, so Refused is unexpected: a failure, retried next run.
func TestPortsB2_RefusedIsAFailedCheckRetried(t *testing.T) {
	p := newPorts(t)
	srv := p.serve("203.0.113.250", 7001, hello)
	var refuse atomic.Bool
	refuse.Store(true)
	for i, s := range p.h.stages {
		if s.Name() == "ports" {
			p.h.stages[i] = refusingPorts{s, &refuse}
		}
	}
	p.sweep([]int{7001})
	if s := lastState(p.h.events(), "ports"); s == nil || s.str("state") != "failed" || s.num("checks") != 1 || s.num("failed") != 1 {
		t.Errorf("refused run: %v, want a failed check", s)
	}
	if got := p.checked(); len(got) != 0 {
		t.Errorf("a refused check must not be completed: %v", got)
	}
	refuse.Store(false)
	p.sweep([]int{7001})
	if srv.conns.Load() != 1 || !slices.Equal(p.checked(), []string{"203.0.113.250:7001"}) {
		t.Errorf("the failed check was not retried: conns=%d checked=%v", srv.conns.Load(), p.checked())
	}
}

// --- B3: hand-off to web probing ---

func TestPortsB3_HTTPOnANonStandardPortIsProbed(t *testing.T) {
	p := newPorts(t)
	p.names("app.example.com")
	p.host("app.example.com", "203.0.113.5")
	p.owner("203.0.113.5", 64500, "ACME-NET")
	web := p.plain("203.0.113.5", 8080, page("<title>app</title>"))
	ssh := p.serve("203.0.113.5", 9999, "SSH-2.0-OpenSSH_9.6\r\n")
	p.ports[8080] = true
	p.sweep([]int{8080, 9999}, "--crawl-pages", "0")

	if got := p.openPortKeys(); !slices.Equal(got, []string{"203.0.113.5:8080", "203.0.113.5:9999"}) {
		t.Errorf("open ports = %v", got)
	}
	p.wantServices("http://app.example.com:8080")
	if web.hits() == 0 {
		t.Error("the HTTP server on the open port was never probed")
	}
	if ssh.conns.Load() != 1 || ssh.bytes.Load() != 0 {
		t.Errorf("a port that sends a banner: %d connections, %d bytes sent to it; want the port check only", ssh.conns.Load(), ssh.bytes.Load())
	}
}

// --- visibility on read (D9) and plumbing (D11, D14) ---

func TestPortsD9_ExclusionHidesAnOpenPortButNotTheView(t *testing.T) {
	p := newPorts(t)
	p.names("app.example.com")
	p.host("app.example.com", "203.0.113.7")
	p.owner("203.0.113.7", 64500, "ACME-NET")
	p.serve("203.0.113.7", 7001, hello)
	p.serve("203.0.113.250", 7001, hello)
	var seen atomic.Value
	p.h.stages = append(p.h.stages, &testkit.Stage{StageName: "peek", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check {
			var got []string
			for _, op := range v.OpenPorts() {
				got = append(got, op.Addr.String())
			}
			seen.Store(got)
			return nil
		}})

	p.sweep([]int{7001})
	if got := p.openPortKeys(); !slices.Equal(got, []string{"203.0.113.250:7001", "203.0.113.7:7001"}) || p.summaryTotal("open ports") != 2 {
		t.Fatalf("before the exclusion: rows=%v summary=%d", got, p.summaryTotal("open ports"))
	}
	p.sweep([]int{7001}, "-x", "203.0.113.7/32")
	if got := p.openPortKeys(); !slices.Equal(got, []string{"203.0.113.250:7001"}) {
		t.Errorf("open-ports.csv after the exclusion = %v", got)
	}
	if len(p.openPortRows()) != 1 {
		t.Errorf("an excluded address's port must be gone from the file, not just not current: %v", p.openPortRows())
	}
	if n := p.summaryTotal("open ports"); n != 1 {
		t.Errorf("summary open ports = %d, want 1", n)
	}
	if got, _ := seen.Load().([]string); !slices.Equal(got, []string{"203.0.113.250:7001", "203.0.113.7:7001"}) {
		t.Errorf("View.OpenPorts() = %v, want it unfiltered", got)
	}
}

func TestPortsPlumbing_OpenPortsCSV(t *testing.T) {
	p := newPorts(t)
	p.names("app.example.com")
	p.host("app.example.com", "203.0.113.7")
	p.owner("203.0.113.7", 64500, "ACME-NET")
	p.serve("203.0.113.250", 7001, "+OK ready\r\n")
	p.serve("203.0.113.250", 10001, hello)
	p.serve("203.0.113.7", 7001, hello)
	p.sweep([]int{7001, 10001})

	raw := p.file(eng, "open-ports.csv")
	if hdr := strings.SplitN(raw, "\n", 2)[0]; hdr != "ip,port,banner,hostnames,current,first_seen,last_seen" {
		t.Errorf("header = %q", hdr)
	}
	// Sorted as strings, like every other CSV: "10001" sorts before "7001".
	var order []string
	for _, r := range p.openPortRows() {
		order = append(order, r["ip"]+"|"+r["port"])
		if r["first_seen"] != "2026-11-01" || r["last_seen"] != "2026-11-01" || r["current"] != "true" {
			t.Errorf("dates: %v", r)
		}
	}
	if want := []string{"203.0.113.250|10001", "203.0.113.250|7001", "203.0.113.7|7001"}; !slices.Equal(order, want) {
		t.Errorf("rows = %v, want %v", order, want)
	}
	if !strings.Contains(raw, `'+OK ready\r\n`) || strings.Contains(raw, ",+OK") {
		t.Errorf("a banner starting with + must be neutralised:\n%s", raw)
	}
	ips := p.table(eng, "ips.csv")
	for _, r := range p.openPortRows() {
		if want := find(ips, "ip", r["ip"]); want == nil || r["hostnames"] != want["hostnames"] {
			t.Errorf("hostnames of %s = %q, ips.csv has %v", r["ip"], r["hostnames"], want)
		}
	}
	if n, rows := p.summaryTotal("open ports"), len(p.openPortKeys()); n != rows || n != 3 {
		t.Errorf("summary open ports = %d, rows = %d, want 3 and 3", n, rows)
	}
	p.sweep([]int{7001, 10001}, "--redo", "ports") // nothing new: no found lines
	if got := ofType(p.h.events(), "found"); len(got) != 0 {
		t.Errorf("known ports printed again: %v", got)
	}
}

func TestPortsD14_FoundLine(t *testing.T) {
	p := newPorts(t)
	p.serve("203.0.113.250", 7001, hello)
	p.sweep([]int{7001})
	var found []string
	for _, e := range ofType(p.h.events(), "found") {
		if e.str("category") == "open port" {
			found = append(found, e.str("value"))
		}
	}
	if !slices.Equal(found, []string{"203.0.113.250:7001"}) {
		t.Errorf("open port found lines = %v (events: %s)", found, fmt.Sprint(ofType(p.h.events(), "found")))
	}
}
