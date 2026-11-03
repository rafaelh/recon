package egress

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/rafaelh/recon/internal/input"
)

// DNS response codes returned in DNSResult.RCode.
const (
	RCodeSuccess  = dns.RcodeSuccess
	RCodeServFail = dns.RcodeServerFailure
	RCodeNXDomain = dns.RcodeNameError
)

// Answer is one record of a DNS answer.
type Answer struct {
	Name, Type, Value string
	TTL               uint32
}

// DNSResult is the outcome of a DNS query. NXDOMAIN, NODATA and SERVFAIL are
// results, not errors; only a failure to get any response is an error.
type DNSResult struct {
	RCode      int
	Answers    []Answer // CNAME records are reported in CNAMEChain, not here
	CNAMEChain []string
}

// Resolver queries the fixed public resolver set. It has no zone-transfer API.
type Resolver interface {
	Query(ctx context.Context, name string, qtype uint16) (DNSResult, error)
}

type resolver struct{ e *Egress }

func (r *resolver) Query(ctx context.Context, name string, qtype uint16) (DNSResult, error) {
	if qtype == dns.TypeAXFR || qtype == dns.TypeIXFR {
		return DNSResult{}, errors.New("zone transfers are not permitted")
	}
	if err := r.e.dnsLim.Wait(ctx); err != nil {
		return DNSResult{}, err
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true

	addrs := r.e.opts.ResolverAddrs
	start := int(r.e.rr.Add(1)) % len(addrs)
	var last *dns.Msg
	var lastErr error
	for i := range addrs {
		addr := addrs[(start+i)%len(addrs)]
		c := &dns.Client{Timeout: r.e.opts.DNSTimeout}
		resp, _, err := c.ExchangeContext(ctx, m, addr)
		if err == nil && resp.Truncated {
			resp, _, err = (&dns.Client{Net: "tcp", Timeout: r.e.opts.DNSTimeout}).ExchangeContext(ctx, m, addr)
		}
		if err != nil {
			if ctx.Err() != nil {
				return DNSResult{}, ctx.Err()
			}
			lastErr = err
			continue
		}
		if resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused {
			last = resp
			continue
		}
		return toResult(resp, qtype), nil
	}
	if last != nil {
		return toResult(last, qtype), nil
	}
	return DNSResult{}, fmt.Errorf("dns query %s %s: %w", name, dns.TypeToString[qtype], lastErr)
}

func toResult(m *dns.Msg, qtype uint16) DNSResult {
	res := DNSResult{RCode: m.Rcode}
	if m.Rcode == dns.RcodeRefused {
		res.RCode = dns.RcodeServerFailure
	}
	for _, rr := range m.Answer {
		h := rr.Header()
		if cn, ok := rr.(*dns.CNAME); ok {
			res.CNAMEChain = append(res.CNAMEChain, input.NormaliseHost(cn.Target))
			if qtype != dns.TypeCNAME {
				continue
			}
		}
		res.Answers = append(res.Answers, Answer{
			Name: input.NormaliseHost(h.Name), Type: dns.TypeToString[h.Rrtype], Value: rdata(rr), TTL: h.Ttl,
		})
	}
	return res
}

func rdata(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.A:
		return v.A.String()
	case *dns.AAAA:
		return v.AAAA.String()
	case *dns.CNAME:
		return input.NormaliseHost(v.Target)
	case *dns.NS:
		return input.NormaliseHost(v.Ns)
	case *dns.PTR:
		return input.NormaliseHost(v.Ptr)
	case *dns.TXT:
		return strings.Join(v.Txt, "")
	}
	parts := strings.SplitN(rr.String(), "\t", 5)
	if len(parts) == 5 {
		return parts[4]
	}
	return rr.String()
}
