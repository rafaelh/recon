// Package egresstest is a fake DNS server for tests. It lives under
// internal/egress so the passive-boundary test allows its use of net and miekg/dns.
package egresstest

import (
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"testing"

	mdns "github.com/miekg/dns"
)

// DNS is a scriptable authoritative-for-everything DNS server on loopback.
type DNS struct {
	Addr string

	mu       sync.Mutex
	addrs    map[string][]netip.Addr
	cnames   map[string]string
	rcodes   map[string]int
	sufRcode map[string]int
	drop     map[string]bool
	wild     map[string]wildcard
	ptr      map[string][]string
	txt      map[string][]string
	queries  map[string]int
}

type wildcard struct {
	addrs []netip.Addr
	cname string
}

// NewDNS starts a server that is shut down when the test ends.
func NewDNS(t testing.TB) *DNS {
	t.Helper()
	d := &DNS{
		addrs: map[string][]netip.Addr{}, cnames: map[string]string{}, rcodes: map[string]int{},
		sufRcode: map[string]int{}, drop: map[string]bool{}, wild: map[string]wildcard{},
		ptr: map[string][]string{}, txt: map[string][]string{}, queries: map[string]int{},
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &mdns.Server{PacketConn: pc, Handler: mdns.HandlerFunc(d.serve)}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go srv.ActivateAndServe()
	<-started
	t.Cleanup(func() { srv.Shutdown() })
	d.Addr = pc.LocalAddr().String()
	return d
}

func norm(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }

// A makes name resolve to the addresses (IPv4 answer A queries, IPv6 answer AAAA).
func (d *DNS) A(name string, addrs ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, a := range addrs {
		d.addrs[norm(name)] = append(d.addrs[norm(name)], netip.MustParseAddr(a))
	}
}

// CNAME makes name an alias of target.
func (d *DNS) CNAME(name, target string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cnames[norm(name)] = norm(target)
}

// Rcode forces a response code for every query for name.
func (d *DNS) Rcode(name string, rcode int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rcodes[norm(name)] = rcode
}

// RcodeSuffix forces a response code for every name under suffix.
func (d *DNS) RcodeSuffix(suffix string, rcode int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sufRcode[norm(suffix)] = rcode
}

// Drop makes the server not answer queries for name (a client timeout).
func (d *DNS) Drop(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.drop[norm(name)] = true
}

// Undrop makes the server answer queries for name again.
func (d *DNS) Undrop(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.drop, norm(name))
}

// Wildcard makes every otherwise-unknown direct child of zone resolve to the addresses.
func (d *DNS) Wildcard(zone string, addrs ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	w := wildcard{}
	for _, a := range addrs {
		w.addrs = append(w.addrs, netip.MustParseAddr(a))
	}
	d.wild[norm(zone)] = w
}

// WildcardCNAME makes every otherwise-unknown direct child of zone an alias of target.
func (d *DNS) WildcardCNAME(zone, target string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.wild[norm(zone)] = wildcard{cname: norm(target)}
}

// PTR makes the reverse name of addr answer with hostname.
func (d *DNS) PTR(addr, hostname string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rev, _ := mdns.ReverseAddr(addr)
	d.ptr[norm(rev)] = append(d.ptr[norm(rev)], norm(hostname))
}

// TXT makes name answer TXT queries with text.
func (d *DNS) TXT(name, text string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.txt[norm(name)] = append(d.txt[norm(name)], text)
}

// Count is how many queries of the type ("A", "AAAA", "PTR", "TXT") were made for name.
func (d *DNS) Count(name, qtype string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.queries[norm(name)+"|"+qtype]
}

// Queried lists the names queried with the type, sorted.
func (d *DNS) Queried(qtype string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for k := range d.queries {
		if n, ty, _ := strings.Cut(k, "|"); ty == qtype {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// Total is the number of queries received.
func (d *DNS) Total() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, c := range d.queries {
		n += c
	}
	return n
}

func (d *DNS) known(name string) bool {
	_, a := d.addrs[name]
	_, c := d.cnames[name]
	_, p := d.ptr[name]
	_, x := d.txt[name]
	return a || c || p || x
}

func (d *DNS) serve(w mdns.ResponseWriter, r *mdns.Msg) {
	q := r.Question[0]
	name := norm(q.Name)
	ty := mdns.TypeToString[q.Qtype]

	d.mu.Lock()
	d.queries[name+"|"+ty]++
	dropped := d.drop[name]
	m := new(mdns.Msg)
	m.SetReply(r)
	hdr := func(t uint16) mdns.RR_Header {
		return mdns.RR_Header{Name: q.Name, Rrtype: t, Class: mdns.ClassINET, Ttl: 60}
	}
	if !dropped {
		d.answer(m, name, q.Qtype, hdr)
	}
	d.mu.Unlock()
	if dropped {
		return
	}
	w.WriteMsg(m)
}

// answer fills m. The caller holds d.mu.
func (d *DNS) answer(m *mdns.Msg, name string, qtype uint16, hdr func(uint16) mdns.RR_Header) {
	if rc, ok := d.rcodes[name]; ok {
		m.Rcode = rc
		return
	}
	for suf, rc := range d.sufRcode {
		if name == suf || strings.HasSuffix(name, "."+suf) {
			m.Rcode = rc
			return
		}
	}
	cur := name
	for hop := 0; hop < 8; hop++ {
		target, ok := d.cnames[cur]
		if !ok {
			if w, wok := d.wildTarget(cur); wok && w.cname != "" {
				target, ok = w.cname, true
			}
		}
		if !ok {
			break
		}
		h := hdr(mdns.TypeCNAME)
		h.Name = mdns.Fqdn(cur)
		m.Answer = append(m.Answer, &mdns.CNAME{Hdr: h, Target: mdns.Fqdn(target)})
		cur = target
	}
	known := d.known(cur)
	var wild *wildcard
	if !known {
		if w, ok := d.wildTarget(cur); ok && w.cname == "" {
			wild, known = &w, true
		}
	}
	if !known {
		m.Rcode = mdns.RcodeNameError // no such name, or a dangling chain
		return
	}
	h := hdr(qtype)
	h.Name = mdns.Fqdn(cur)
	switch qtype {
	case mdns.TypeA, mdns.TypeAAAA:
		addrs := d.addrs[cur]
		if wild != nil {
			addrs = wild.addrs
		}
		for _, a := range addrs {
			if a.Is4() && qtype == mdns.TypeA {
				m.Answer = append(m.Answer, &mdns.A{Hdr: h, A: net.IP(a.AsSlice())})
			} else if a.Is6() && qtype == mdns.TypeAAAA {
				m.Answer = append(m.Answer, &mdns.AAAA{Hdr: h, AAAA: net.IP(a.AsSlice())})
			}
		}
	case mdns.TypePTR:
		for _, p := range d.ptr[cur] {
			m.Answer = append(m.Answer, &mdns.PTR{Hdr: h, Ptr: mdns.Fqdn(p)})
		}
	case mdns.TypeTXT:
		for _, t := range d.txt[cur] {
			m.Answer = append(m.Answer, &mdns.TXT{Hdr: h, Txt: []string{t}})
		}
	}
}

func (d *DNS) wildTarget(name string) (wildcard, bool) {
	if d.known(name) {
		return wildcard{}, false
	}
	_, parent, ok := strings.Cut(name, ".")
	if !ok {
		return wildcard{}, false
	}
	w, ok := d.wild[parent]
	return w, ok
}
