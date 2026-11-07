package dns

import (
	"context"
	"fmt"
	"iter"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/rafaelh/recon/internal/dnsname"
	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/run"
)

// IPOwner finds the origin AS of each address outside the in-scope netblocks
// using Team Cymru's DNS service through the public resolvers.
type IPOwner struct {
	base
	mu      sync.Mutex
	holders map[int]string // cached per ASN for the life of the process
}

// NewIPOwner returns the ipowner stage.
func NewIPOwner() *IPOwner { return &IPOwner{base: base{"ipowner"}, holders: map[int]string{}} }

// Checks yields one check per ip record outside the in-scope netblocks.
func (*IPOwner) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		var ips []string
		for _, rec := range v.Records(kinds.IP) {
			if a, err := netip.ParseAddr(rec.Key); err == nil && !v.Scope().InScopeIP(a) {
				ips = append(ips, a.Unmap().String())
			}
		}
		sort.Strings(ips)
		for _, s := range ips {
			if !yield(run.Check{Key: s, Input: netip.MustParseAddr(s)}, nil) {
				return
			}
		}
	}
}

// Run looks up the origin AS, then the AS holder. An address Cymru does not
// know (NXDOMAIN) is a completed check with no owner; any other failure is
// transient, and leaves the owner unknown.
func (o *IPOwner) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	addr := c.Input.(netip.Addr)
	res, err := e.DNS.Query(ctx, dnsname.CymruOrigin(addr), egress.TypeTXT)
	if err != nil {
		return nil, fmt.Errorf("owner of %s: %w", addr, err)
	}
	switch res.RCode {
	case egress.RCodeSuccess:
	case egress.RCodeNXDomain:
		return nil, nil
	default:
		return nil, fmt.Errorf("owner of %s: resolver answered rcode %d", addr, res.RCode)
	}
	var asn int
	var prefix string
	for _, a := range res.Answers {
		if a.Type != "TXT" {
			continue
		}
		f := fields(a.Value)
		// "13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"; with several origins, take the first.
		if len(f) >= 2 {
			first, _, _ := strings.Cut(f[0], " ")
			if n, err := strconv.Atoi(first); err == nil {
				asn, prefix = n, f[1]
				break
			}
		}
	}
	if asn == 0 {
		return nil, nil
	}
	holder, err := o.holder(ctx, asn, e)
	if err != nil {
		return nil, fmt.Errorf("owner of %s: %w", addr, err)
	}
	return []run.Observation{kinds.IPOwner.Obs(addr.String(), kinds.IPOwnerAttrs{ASN: asn, Prefix: prefix, Holder: holder})}, nil
}

func (o *IPOwner) holder(ctx context.Context, asn int, e egress.Clients) (string, error) {
	o.mu.Lock()
	h, ok := o.holders[asn]
	o.mu.Unlock()
	if ok {
		return h, nil
	}
	res, err := e.DNS.Query(ctx, fmt.Sprintf("AS%d.asn.cymru.com", asn), egress.TypeTXT)
	if err != nil {
		return "", err
	}
	if res.RCode != egress.RCodeSuccess && res.RCode != egress.RCodeNXDomain {
		return "", fmt.Errorf("resolver answered rcode %d for AS%d", res.RCode, asn)
	}
	for _, a := range res.Answers {
		// "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
		if f := fields(a.Value); a.Type == "TXT" && len(f) >= 5 {
			h = trimCountry(strings.TrimSpace(f[4]))
			break
		}
	}
	o.mu.Lock()
	o.holders[asn] = h
	o.mu.Unlock()
	return h, nil
}

func fields(txt string) []string {
	parts := strings.Split(txt, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// trimCountry drops the ", US" country suffix Team Cymru appends to the holder.
func trimCountry(h string) string {
	if i := strings.LastIndex(h, ", "); i > 0 && len(h)-i == 4 {
		return h[:i]
	}
	return h
}
