package egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
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

type origin struct {
	scheme, host string
	port         int
}

func (o *origin) base() *url.URL {
	return &url.URL{Scheme: o.scheme, Host: net.JoinHostPort(o.host, strconv.Itoa(o.port)), Path: "/"}
}

// Service identifies a web service for SensitivePath requests.
type Service struct {
	Host, Scheme string
	Port         int
}

// Request is a typed target request. It can only be built with Root,
// SensitivePath, Link or Redirect; there is no way to name an arbitrary URL.
type Request interface{ target() target }

type target struct {
	scheme, host string
	port         int
	sensitiveIdx int // >=0: index into the sensitive-path list
	requestURI   string
}

type req struct{ t target }

func (r req) target() target { return r.t }

// Root requests "/" of a service.
func Root(host, scheme string, port int) Request {
	return req{target{scheme: scheme, host: host, port: port, sensitiveIdx: -1, requestURI: "/"}}
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
	switch {
	case tg.scheme != "http" && tg.scheme != "https":
		return Refused{"scheme " + strconv.Quote(tg.scheme) + " is not http or https"}, nil
	case tg.host == "" || strings.ContainsAny(tg.host, "@/?#: \\[]%") || tg.port < 1 || tg.port > 65535:
		return Refused{"malformed host or port"}, nil
	}
	host := input.NormaliseHost(tg.host)
	switch c := p.Scope.ClassifyHost(host); c.Class {
	case scope.Excluded:
		return Refused{"host is excluded: " + c.Reason}, nil
	case scope.Candidate:
		return Refused{"host is not in scope"}, nil
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
	addrs := p.vetted(host)
	if len(addrs) == 0 {
		return Refused{"no permitted address for " + host}, nil
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
	u := url.URL{Scheme: tg.scheme, Host: net.JoinHostPort(host, strconv.Itoa(tg.port))}
	if (tg.scheme == "http" && tg.port == 80) || (tg.scheme == "https" && tg.port == 443) {
		u.Host = host
	}
	reqURL := u.String() + uri
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
				last = err
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
		origin:   &origin{scheme: tg.scheme, host: host, port: tg.port},
	}
	if resp.TLS != nil {
		out.PeerCerts = resp.TLS.PeerCertificates
		out.CertVerifyErr = verifyChain(host, out.PeerCerts)
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
func verifyChain(host string, certs []*x509.Certificate) string {
	if len(certs) == 0 {
		return "no certificate presented"
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter}); err != nil {
		return err.Error()
	}
	return ""
}
