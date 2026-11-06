package web

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"iter"
	"net/netip"
	"net/url"
	"strings"

	"github.com/rafaelh/recon/internal/cloudstorage"
	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/run"
)

// maxHops is how many redirects a probe follows (Spec 3 D11).
const maxHops = 10

// Probe is the httpprobe stage: it finds the HTTP and HTTPS services of every
// probe hostname and of every in-scope IP with an open port, and records each
// with what an ordinary browser would see (Spec 3 B1 to B5).
type Probe struct{}

// NewProbe returns the httpprobe stage.
func NewProbe() *Probe { return &Probe{} }

func (*Probe) Name() string                      { return "httpprobe" }
func (*Probe) Contact() run.Contact              { return run.Target }
func (*Probe) Sources() []string                 { return nil }
func (*Probe) Configured(run.Env) (bool, string) { return true, "" }

// probeInput is the Check.Input of httpprobe.
type probeInput struct {
	host   string // hostname, or an IP literal
	port   int
	scheme string // "" tries https, then http
	detect bool   // a port-detection check (D4), not a hostname check
	addr   netip.AddrPort
}

// Checks yields h:80 and h:443 for every probe hostname (D2), one detection
// check per open port with no banner whose representative has not already
// been given one on that port (D4), and h:port for the other names on each
// address that answered HTTP (D5). A key may repeat; the runner keeps the first.
func (*Probe) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		if _, err := fingerprints(); err != nil {
			v.Warn("httpprobe: technology detection is off: %v", err)
		}
		sc := v.Scope()
		emit := func(key string, in probeInput) bool {
			return yield(run.Check{Key: key, Input: in}, nil)
		}
		for _, h := range v.ProbeHostnames() {
			if !emit(fmt.Sprintf("%s:80", h), probeInput{host: h, port: 80, scheme: "http"}) ||
				!emit(fmt.Sprintf("%s:443", h), probeInput{host: h, port: 443, scheme: "https"}) {
				return
			}
		}
		detecting := map[string]bool{} // "rep:port" of the detection checks yielded
		for _, op := range v.OpenPorts() {
			if op.Banner != "" { // HTTP servers never speak first
				continue
			}
			addr, port := op.Addr.Addr(), int(op.Addr.Port())
			rep, isName := "", false
			if hosts := v.HostsFor(addr); len(hosts) > 0 {
				rep, isName = hosts[0], true
			} else if sc.WebHostInScope(addr.String()) {
				rep = addr.String()
			}
			if rep == "" || (isName && (port == 80 || port == 443)) {
				continue
			}
			// A name on several addresses is tested on one of them (D5).
			rp := fmt.Sprintf("%s:%d", rep, port)
			if detecting[rp] {
				continue
			}
			detecting[rp] = true
			in := probeInput{host: rep, port: port, detect: true, addr: op.Addr}
			switch port {
			case 80:
				in.scheme = "http"
			case 443:
				in.scheme = "https"
			}
			if !emit("port|"+op.Addr.String(), in) {
				return
			}
		}
		// A representative already answered on that port, on whichever address.
		reps := map[string]bool{}
		ports := v.Records("http_port")
		for _, rec := range ports {
			if ap, err := netip.ParseAddrPort(rec.Key); err == nil {
				reps[fmt.Sprintf("%s:%d", rec.Str("host"), ap.Port())] = true
			}
		}
		for _, rec := range ports {
			ap, err := netip.ParseAddrPort(rec.Key)
			if err != nil {
				continue
			}
			for _, h := range v.HostsFor(ap.Addr()) {
				if !reps[fmt.Sprintf("%s:%d", h, ap.Port())] && !emit(fmt.Sprintf("%s:%d", h, ap.Port()), probeInput{host: h, port: int(ap.Port()), scheme: rec.Str("scheme")}) {
					return
				}
			}
		}
	}
}

// Run probes one service. A live answer (any status) is recorded; NoService and
// Refused complete the check with nothing (D7). On an undecided port https is
// tried first, then http unless the connection was refused (D4).
func (p *Probe) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	in := c.Input.(probeInput)
	schemes := []string{in.scheme}
	if in.scheme == "" {
		schemes = []string{"https", "http"}
	}
	for i, scheme := range schemes {
		req := egress.Root(in.host, scheme, in.port)
		if in.detect { // the http_port record is about this address, not the name's others
			req = egress.RootAt(in.host, scheme, in.port, in.addr.Addr())
		}
		res, err := e.HTTP.Get(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.Key, err)
		}
		switch r := res.(type) {
		case egress.Response:
			obs, err := p.service(ctx, in, scheme, r, e)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", c.Key, err)
			}
			if in.detect {
				obs = append(obs, run.Observation{Kind: "http_port", Key: in.addr.String(), Attrs: map[string]any{"scheme": scheme, "host": in.host}})
			}
			return obs, nil
		case egress.NoService:
			if i+1 < len(schemes) && r.Reason != egress.NoServiceRefused {
				continue
			}
		}
		return nil, nil
	}
	return nil, nil
}

// obsSet collects observations without duplicates.
type obsSet struct {
	seen map[string]bool
	list []run.Observation
}

func newObsSet() *obsSet { return &obsSet{seen: map[string]bool{}} }

func (s *obsSet) add(o run.Observation) {
	if k := o.Kind + "\x00" + o.Key; !s.seen[k] {
		s.seen[k] = true
		s.list = append(s.list, o)
	}
}

func isRedirect(status int) bool {
	switch status {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}

// redirectTarget is the normalised absolute URL a redirect response points to.
func redirectTarget(r egress.Response) (string, bool) {
	base, err := url.Parse(r.URL())
	if err != nil {
		return "", false
	}
	t, err := base.Parse(r.Location)
	if err != nil {
		return "", false
	}
	return NormaliseURL(t.String())
}

// otherHost is host as a hostname observation, if it is a domain other than
// self. The probed host itself would turn a permutation-only name into a seed,
// and an IP literal would land in candidates.csv.
func otherHost(host, self string) (string, bool) {
	if host == strings.ToLower(self) {
		return "", false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", false
	}
	d, err := input.ParseDomain(host)
	return d, err == nil
}

// service builds the web_service record from the first response and the page
// the redirect chain ends on (D8), following in-scope redirects (D11).
func (p *Probe) service(ctx context.Context, in probeInput, scheme string, first egress.Response, e egress.Clients) ([]run.Observation, error) {
	obs := newObsSet()
	last := first
	visited := map[string]bool{}
	if u, ok := NormaliseURL(first.URL()); ok {
		visited[u] = true
	}
	for hop := 0; hop < maxHops && isRedirect(last.Status) && last.Location != ""; hop++ {
		target, ok := redirectTarget(last)
		if !ok {
			break
		}
		host := HostOfURL(target)
		hopAttrs := map[string]any{"url": target, "host": host}
		obs.add(run.Observation{Kind: "url", Key: target, Attrs: hopAttrs})
		if d, ok := otherHost(host, in.host); ok {
			obs.add(run.Observation{Kind: "hostname", Key: d})
		}
		// A redirect to a storage URL is a reference, and a browser follows it (Spec 5 D8).
		if ref, ok := cloudstorage.ParseRef(target); ok {
			if page, ok := NormaliseURL(last.URL()); ok {
				obs.add(storageObservation(storageRef{ref: ref, url: target, page: page, via: "asset"}))
			}
		}
		if visited[target] {
			break
		}
		visited[target] = true
		req, err := egress.Redirect(last)
		if err != nil {
			break
		}
		res, err := e.HTTP.Get(ctx, req)
		if err != nil {
			return nil, err
		}
		next, ok := res.(egress.Response)
		if !ok { // out of scope, excluded, unresolved or not answering: the chain stops here
			break
		}
		hopAttrs["status"] = next.Status // D15: a fetched url carries its status
		last = next
	}

	attrs := map[string]any{
		"url": Origin(scheme, in.host, in.port), "host": in.host, "port": in.port, "scheme": scheme,
		"status": first.Status, "server": last.HeaderValue("Server"),
		"technologies": technologies(last.Header, last.Body),
	}
	if first.Location != "" {
		attrs["redirect"] = first.Location
	}
	if u, ok := NormaliseURL(last.URL()); ok {
		attrs["final_url"] = u
	}
	if last.ContentType() == "text/html" {
		if pg, ok := parsePage(last.Body); ok {
			attrs["title"] = pg.title()
		}
	}
	if len(first.PeerCerts) > 0 {
		leaf := first.PeerCerts[0]
		sans := append([]string(nil), leaf.DNSNames...)
		for _, ip := range leaf.IPAddresses {
			sans = append(sans, ip.String())
		}
		attrs["tls_subject"] = leaf.Subject.String()
		attrs["tls_sans"] = strings.Join(sans, ";")
		attrs["tls_issuer"] = leaf.Issuer.String()
		attrs["tls_expiry"] = leaf.NotAfter.UTC().Format("2006-01-02")
		attrs["tls_error"] = first.CertVerifyErr
		attrs["tls_self_signed"] = selfSigned(leaf)
		for _, name := range leaf.DNSNames {
			if d, ok := sanHost(name); ok && d != strings.ToLower(in.host) {
				obs.add(run.Observation{Kind: "hostname", Key: d})
			}
		}
	}
	return append([]run.Observation{{Kind: "web_service", Key: Origin(scheme, in.host, in.port), Attrs: attrs}}, obs.list...), nil
}

// sanHost turns a certificate DNS name into a hostname: a wildcard contributes
// its base name; malformed names, IP literals and public suffixes are skipped (D12).
func sanHost(name string) (string, bool) {
	name = strings.TrimPrefix(strings.TrimSpace(name), "*.")
	if strings.ContainsAny(name, "*@/: ") {
		return "", false
	}
	d, err := input.ParseDomain(name)
	return d, err == nil
}

// selfSigned reports whether the certificate was issued and signed by itself.
// Checking the signature directly, not CheckSignatureFrom, also covers a
// self-signed leaf that is not marked as a CA.
func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) &&
		c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}
