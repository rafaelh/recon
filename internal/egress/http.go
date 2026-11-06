package egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/scope"
)

const (
	maxTargetBody = 1 << 20
	userAgent     = "recon/1"
)

// MaxTargetBody is the cap on Response.Body: a body of exactly this length may have been cut.
const MaxTargetBody = maxTargetBody

// Reasons carried by NoService.
const (
	NoServiceRefused   = "refused"
	NoServiceTimeout   = "timeout"
	NoServiceTLSFailed = "tls-failed"
	NoServiceOther     = "other"
)

var errHTTPTimeout = errors.New("no complete response within the HTTP timeout")

// HTTPResult is the outcome of a target request: a Response, NoService or Refused.
type HTTPResult interface{ httpResult() }

// Response is an HTTP response. Redirects are never followed automatically.
type Response struct {
	Status        int
	Header        map[string][]string
	Body          []byte // capped at 1 MiB; empty for HEAD
	Location      string
	PeerCerts     []*x509.Certificate
	CertVerifyErr string // non-empty if the chain did not verify (expired, self-signed, ...)

	origin *origin
}

// NoService means nothing answered HTTP at that address and port.
type NoService struct{ Reason string }

func (Response) httpResult()  {}
func (NoService) httpResult() {}
func (Refused) httpResult()   {}

// origin is where a Response came from. uri is the request URI, so a relative
// reference in the body or in Location resolves against the page's real URL.
type origin struct {
	scheme, host string
	port         int
	uri          string
}

func (o *origin) base() *url.URL {
	u := &url.URL{Scheme: o.scheme, Host: HostPort(o.scheme, o.host, strconv.Itoa(o.port)), Path: "/"}
	if ru, err := url.ParseRequestURI(o.uri); err == nil {
		u.Path, u.RawPath, u.RawQuery = ru.Path, ru.RawPath, ru.RawQuery
	}
	return u
}

// HostPort is the authority of a URL: host[:port], with an IPv6 literal
// bracketed and an empty or default port for the scheme dropped.
func HostPort(scheme, host, port string) string {
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port == "" || (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		return host
	}
	return host + ":" + port
}

// URL is the absolute URL of the request that produced the response: the
// default port is omitted and an IPv6 literal is bracketed.
func (r Response) URL() string {
	if r.origin == nil {
		return ""
	}
	return r.origin.base().String()
}

// HeaderValue is the first value of the named header, matched case-insensitively,
// or "" if there is none.
func (r Response) HeaderValue(name string) string { return http.Header(r.Header).Get(name) }

// ContentType is the media type of the response, lower case and without
// parameters ("text/html"), or "" if there is none.
func (r Response) ContentType() string {
	v := r.HeaderValue("Content-Type")
	if v == "" {
		return ""
	}
	if mt, _, err := mime.ParseMediaType(v); err == nil {
		return mt
	}
	return strings.ToLower(strings.TrimSpace(strings.SplitN(v, ";", 2)[0]))
}

// ipLiteral parses host as an IP address. A zoned address is not a literal
// egress will dial, and a bracketed form is a URL authority, not a host.
func ipLiteral(host string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(host)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// Service identifies a web service for SensitivePath requests.
type Service struct {
	Host, Scheme string
	Port         int
}

// ParseService splits a web_service key (scheme://host[:port], an http or https
// origin) into a Service, with the scheme's default port if none is given.
func ParseService(origin string) (Service, bool) {
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return Service{}, false
	}
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if p := u.Port(); p != "" {
		if port, err = strconv.Atoi(p); err != nil {
			return Service{}, false
		}
	}
	return Service{Host: strings.ToLower(u.Hostname()), Scheme: u.Scheme, Port: port}, true
}

// Request is a typed target request. It can only be built with Root, RootAt,
// SensitivePath, Link or Redirect; there is no way to name an arbitrary URL.
type Request interface{ target() target }

type target struct {
	scheme, host string
	port         int
	sensitiveIdx int // >=0: index into the sensitive-path list
	requestURI   string
	pin          netip.Addr // if valid, the only address dialled
}

type req struct{ t target }

func (r req) target() target { return r.t }

// Root requests "/" of a service.
func Root(host, scheme string, port int) Request {
	return req{target{scheme: scheme, host: host, port: port, sensitiveIdx: -1, requestURI: "/"}}
}

// RootAt requests "/" of a service by name, dialling only addr, so the answer
// is known to come from that address. addr must be one of the name's permitted
// addresses. Redirects and links from the response are not pinned.
func RootAt(host, scheme string, port int, addr netip.Addr) Request {
	return req{target{scheme: scheme, host: host, port: port, sensitiveIdx: -1, requestURI: "/", pin: addr.Unmap()}}
}

// SensitivePath requests entry index of the configured sensitive-path list.
func SensitivePath(svc Service, index int) Request {
	return req{target{scheme: svc.Scheme, host: svc.Host, port: svc.Port, sensitiveIdx: index}}
}

func resolveFrom(resp Response, ref string) (target, error) {
	if resp.origin == nil {
		return target{}, errors.New("response was not produced by egress")
	}
	u, err := resp.origin.base().Parse(ref)
	if err != nil {
		return target{}, err
	}
	if u.User != nil {
		return target{}, errors.New("userinfo is not permitted")
	}
	port := 0
	if ps := u.Port(); ps != "" {
		port, _ = strconv.Atoi(ps)
	} else if u.Scheme == "https" {
		port = 443
	} else {
		port = 80
	}
	return target{scheme: u.Scheme, host: u.Hostname(), port: port, sensitiveIdx: -1, requestURI: u.RequestURI()}, nil
}

// Link requests a link found in a fetched response; it must be on the same host.
func Link(resp Response, href string) (Request, error) {
	t, err := resolveFrom(resp, href)
	if err != nil {
		return nil, err
	}
	if input.NormaliseHost(t.host) != input.NormaliseHost(resp.origin.host) {
		return nil, errors.New("link is not on the same host as the page it was found on")
	}
	return req{t}, nil
}

// Redirect requests the Location of a redirect response. Policy decides whether
// the destination may be contacted.
func Redirect(resp Response) (Request, error) {
	if resp.Location == "" {
		return nil, errors.New("response has no Location")
	}
	t, err := resolveFrom(resp, resp.Location)
	if err != nil {
		return nil, err
	}
	return req{t}, nil
}

// TargetHTTP issues GET and HEAD requests to in-scope services. Credentials,
// cookies, caller-supplied headers and other methods do not exist in this API.
type TargetHTTP interface {
	Get(ctx context.Context, r Request) (HTTPResult, error)
	Head(ctx context.Context, r Request) (HTTPResult, error)
}

type targetHTTP struct{ e *Egress }

func (t *targetHTTP) Get(ctx context.Context, r Request) (HTTPResult, error) {
	return t.do(ctx, http.MethodGet, r)
}

func (t *targetHTTP) Head(ctx context.Context, r Request) (HTTPResult, error) {
	return t.do(ctx, http.MethodHead, r)
}

func (t *targetHTTP) do(ctx context.Context, method string, r Request) (HTTPResult, error) {
	e := t.e
	p := e.policy()
	tg := r.target()
	if r, ok := p.targetRefusal(); ok {
		return r, nil
	}
	host := input.NormaliseHost(tg.host)
	lit, isIP := ipLiteral(host)
	switch {
	case tg.scheme != "http" && tg.scheme != "https":
		return Refused{"scheme " + strconv.Quote(tg.scheme) + " is not http or https"}, nil
	case tg.host == "" || tg.port < 1 || tg.port > 65535 || (!isIP && strings.ContainsAny(tg.host, "@/?#: \\[]%")):
		return Refused{"malformed host or port"}, nil
	}
	if isIP {
		host = lit.String()
		// An address is a web target iff it is in an in-scope netblock and not
		// excluded; a hostname that resolves there is probed by name instead.
		if !p.Scope.InScopeIP(lit) {
			return Refused{"address is not in scope"}, nil
		}
		if ex, why := p.Scope.ExcludedFor(lit, p.isShared(lit)); ex {
			p.reportExcluded(lit.String(), why)
			return Refused{"address is excluded: " + why}, nil
		}
	} else {
		switch c := p.Scope.ClassifyHost(host); c.Class {
		case scope.Excluded:
			return Refused{"host is excluded: " + c.Reason}, nil
		case scope.Candidate:
			return Refused{"host is not in scope"}, nil
		}
	}
	if !p.portAllowed(tg.port, true) {
		return Refused{"port " + strconv.Itoa(tg.port) + " not allowed"}, nil
	}
	uri := tg.requestURI
	if tg.sensitiveIdx >= 0 {
		if tg.sensitiveIdx >= len(p.SensitivePaths) {
			return Refused{"sensitive path index out of range"}, nil
		}
		uri = p.SensitivePaths[tg.sensitiveIdx]
	}
	if !strings.HasPrefix(uri, "/") {
		return Refused{"request path " + strconv.Quote(uri) + " does not start with /"}, nil
	}
	addrs := []netip.Addr{lit}
	if !isIP {
		addrs = p.vetted(host)
	}
	if len(addrs) == 0 {
		return Refused{"no permitted address for " + host}, nil
	}
	if tg.pin.IsValid() {
		if !slices.Contains(addrs, tg.pin) {
			return Refused{"address " + tg.pin.String() + " is not a permitted address of " + host}, nil
		}
		addrs = []netip.Addr{tg.pin}
	}

	// HTTPTimeout runs from when the rate limiter lets the first dial through,
	// so waiting for a token never makes a service look unresponsive.
	parent := ctx
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	deadline := sync.OnceValue(func() *time.Timer {
		return time.AfterFunc(e.opts.HTTPTimeout, func() { cancel(errHTTPTimeout) })
	})
	defer func() { deadline().Stop() }()
	reqURL := (&url.URL{Scheme: tg.scheme, Host: HostPort(tg.scheme, host, strconv.Itoa(tg.port))}).String() + uri
	hreq, err := http.NewRequestWithContext(ctx, method, reqURL, nil)
	if err != nil {
		return Refused{"bad request: " + err.Error()}, nil
	}
	hreq.Header.Set("User-Agent", userAgent)

	tr := &http.Transport{
		Proxy:              nil,
		DisableKeepAlives:  true,
		DisableCompression: true,
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true, ServerName: host},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var last error
			for _, a := range addrs {
				if err := e.hostLimiter(a).Wait(ctx); err != nil {
					return nil, err
				}
				deadline()
				d := net.Dialer{Timeout: e.opts.ConnectTimeout}
				c, err := d.DialContext(ctx, "tcp", e.dialAddr(a, tg.port))
				if err == nil {
					return c, nil
				}
				last = localRoute(err, a, e.routeLookup())
			}
			return nil, last
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(hreq)
	if err != nil {
		switch perr := parent.Err(); {
		case perr != nil && !errors.Is(perr, context.DeadlineExceeded):
			return nil, perr
		case context.Cause(ctx) == errHTTPTimeout:
			return NoService{NoServiceTimeout}, nil
		case localFailure(err):
			return nil, err
		}
		return NoService{classify(err)}, nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTargetBody))
	if err != nil { // a truncated body is not a result; retry it next run
		if perr := parent.Err(); perr != nil {
			return nil, perr
		}
		if context.Cause(ctx) == errHTTPTimeout {
			err = errHTTPTimeout
		}
		return nil, fmt.Errorf("reading response body from %s: %w", host, err)
	}
	if method == http.MethodHead {
		body = nil
	}
	out := Response{
		Status: resp.StatusCode, Header: map[string][]string(resp.Header.Clone()), Body: body,
		Location: resp.Header.Get("Location"),
		origin:   &origin{scheme: tg.scheme, host: host, port: tg.port, uri: uri},
	}
	if resp.TLS != nil {
		out.PeerCerts = resp.TLS.PeerCertificates
		out.CertVerifyErr = verifyChain(host, out.PeerCerts, e.opts.Now())
	}
	return out, nil
}

// vetted returns the addresses a request for host may be sent to: never an
// address in an excluded CIDR, and never an address of an excluded hostname
// unless that address is shared provider infrastructure (D9).
func (p *Policy) vetted(host string) []netip.Addr {
	var out []netip.Addr
	for _, a := range p.Resolutions[host] {
		if ok, why := p.Scope.ExcludedFor(a, p.isShared(a)); ok {
			p.reportExcluded(a.String(), why)
			continue
		}
		out = append(out, a)
	}
	return out
}

func classify(err error) string {
	var ne net.Error
	var rh tls.RecordHeaderError
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return NoServiceRefused
	case errors.As(err, &rh), strings.Contains(err.Error(), "tls:"), strings.Contains(err.Error(), "x509:"),
		strings.Contains(err.Error(), "server gave HTTP response to HTTPS client"):
		return NoServiceTLSFailed
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return NoServiceTimeout
	}
	return NoServiceOther
}

// verifyChain checks the presented chain separately from the connection
// (which skips verification) so expiry and self-signing can be reported.
func verifyChain(host string, certs []*x509.Certificate, now time.Time) string {
	if len(certs) == 0 {
		return "no certificate presented"
	}
	// Validity and hostname are checked here, in the order and wording of Go's
	// own verifier, because on macOS and Windows Verify defers to the platform
	// verifier. That verifier reports a different error for the same
	// certificate (an expired leaf reads as "unknown authority" on macOS), so
	// tls_error would otherwise depend on the operator's OS. Trust is still
	// decided by Verify against the system roots.
	leaf := certs[0]
	if now.Before(leaf.NotBefore) {
		return x509.CertificateInvalidError{Cert: leaf, Reason: x509.Expired, Detail: fmt.Sprintf(
			"current time %s is before %s", now.Format(time.RFC3339), leaf.NotBefore.Format(time.RFC3339))}.Error()
	}
	if now.After(leaf.NotAfter) {
		return x509.CertificateInvalidError{Cert: leaf, Reason: x509.Expired, Detail: fmt.Sprintf(
			"current time %s is after %s", now.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339))}.Error()
	}
	if err := leaf.VerifyHostname(host); err != nil {
		return err.Error()
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter, CurrentTime: now}); err != nil {
		return err.Error()
	}
	return ""
}
