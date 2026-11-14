// Package providerranges fetches the address ranges that AWS, GCP, Cloudflare,
// Fastly, DigitalOcean, Oracle Cloud and Linode publish, which tell a dedicated
// virtual machine from a CDN or load-balancer address. Azure publishes its
// ranges at a URL that changes, so Azure is recognised by ASN alone.
package providerranges

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/url"
	"slices"
	"strings"

	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/stages/httpsrc"
)

// rangeEntry is one parsed range. prefix is not yet validated.
type rangeEntry struct{ prefix, service, region string }

// list is one published range list, and so one check. key is the check's
// stable name: it never changes, so a list is not fetched again once it is done.
type list struct {
	key, provider, url string
	parse              func([]byte) ([]rangeEntry, error)
}

// lists are the published range lists, in the order their checks run. Cloudflare
// publishes IPv4 and IPv6 as two files, so it has two.
var lists = []list{
	{"aws", "aws", "https://ip-ranges.amazonaws.com/ip-ranges.json", parseAWS},
	{"gcp", "gcp", "https://www.gstatic.com/ipranges/cloud.json", parseGCP},
	{"cloudflare-v4", "cloudflare", "https://www.cloudflare.com/ips-v4", parseLines},
	{"cloudflare-v6", "cloudflare", "https://www.cloudflare.com/ips-v6", parseLines},
	{"fastly", "fastly", "https://api.fastly.com/public-ip-list", parseFastly},
	{"digitalocean", "digitalocean", "https://www.digitalocean.com/geo/google.csv", parseLines},
	{"oracle", "oracle", "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json", parseOracle},
	{"linode", "linode", "https://geoip.linode.com/", parseLines},
}

func listByKey(key string) (list, bool) {
	i := slices.IndexFunc(lists, func(l list) bool { return l.key == key })
	if i < 0 {
		return list{}, false
	}
	return lists[i], true
}

// Stage is the providerranges stage: one check per list, refreshed by --redo providerranges.
type Stage struct{}

// New returns the providerranges stage.
func New() *Stage { return &Stage{} }

func (*Stage) Name() string                      { return "providerranges" }
func (*Stage) Contact() run.Contact              { return run.ThirdParty }
func (*Stage) Configured(run.Env) (bool, string) { return true, "" }

// Sources are the hosts the lists are fetched from.
func (*Stage) Sources() []string {
	var hosts []string
	for _, l := range lists {
		if u, err := url.Parse(l.url); err == nil && !slices.Contains(hosts, u.Host) {
			hosts = append(hosts, u.Host)
		}
	}
	return hosts
}

func (*Stage) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		for _, l := range lists {
			if !yield(run.Check{Key: l.key, Input: l.key}, nil) {
				return
			}
		}
	}
}

// Run downloads and parses one list. A list that cannot be fetched or read, or
// that yields no ranges, is an error: the check is retried on a later run, and
// the ranges of the last successful fetch keep applying meanwhile.
func (*Stage) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	l, ok := listByKey(c.Key)
	if !ok {
		return nil, fmt.Errorf("unknown provider list %q", c.Key)
	}
	body, err := httpsrc.Get(ctx, e, egress.ThirdPartyRequest{Method: "GET", URL: l.url})
	if err != nil {
		return nil, fmt.Errorf("%s ranges: %w", l.provider, err)
	}
	return l.observations(body)
}

// observations parses a list's body into provider_range observations. Entries
// whose prefix does not parse are skipped, and a body with none left is an error.
func (l list) observations(body []byte) ([]run.Observation, error) {
	entries, err := l.parse(body)
	if err != nil {
		return nil, fmt.Errorf("%s ranges: unreadable response: %v", l.provider, err)
	}
	var obs []run.Observation
	for _, e := range entries {
		p, err := input.ParseCIDR(e.prefix)
		if err != nil {
			continue
		}
		prefix := p.String()
		key := l.provider + "|" + prefix + "|" + e.service
		obs = append(obs, kinds.ProviderRange.Obs(key, kinds.ProviderRangeAttrs{Provider: l.provider, Prefix: prefix, Service: e.service, Region: e.region}))
	}
	if len(obs) == 0 {
		return nil, fmt.Errorf("%s ranges: the response holds no ranges", l.provider)
	}
	return obs, nil
}

func parseAWS(body []byte) ([]rangeEntry, error) {
	var doc struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Region   string `json:"region"`
			Service  string `json:"service"`
		} `json:"prefixes"`
		IPv6 []struct {
			IPPrefix string `json:"ipv6_prefix"`
			Region   string `json:"region"`
			Service  string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	var out []rangeEntry
	for _, p := range doc.Prefixes {
		out = append(out, rangeEntry{p.IPPrefix, p.Service, p.Region})
	}
	for _, p := range doc.IPv6 {
		out = append(out, rangeEntry{p.IPPrefix, p.Service, p.Region})
	}
	return out, nil
}

func parseGCP(body []byte) ([]rangeEntry, error) {
	var doc struct {
		Prefixes []struct {
			IPv4  string `json:"ipv4Prefix"`
			IPv6  string `json:"ipv6Prefix"`
			Scope string `json:"scope"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	var out []rangeEntry
	for _, p := range doc.Prefixes {
		prefix := p.IPv4
		if prefix == "" {
			prefix = p.IPv6
		}
		out = append(out, rangeEntry{prefix, "", p.Scope})
	}
	return out, nil
}

// parseLines reads a text list with one range a line: Cloudflare's plain
// prefixes, and the geofeed (RFC 8805) DigitalOcean and Linode publish, whose
// lines are "prefix,country,region,city,postcode". Blank and # lines are
// skipped, and the region is the third field when there is one.
func parseLines(body []byte) ([]rangeEntry, error) {
	lines, err := input.ParseList(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	var out []rangeEntry
	for _, line := range lines {
		f := strings.Split(line, ",")
		e := rangeEntry{prefix: strings.TrimSpace(f[0])}
		if len(f) > 2 {
			e.region = strings.TrimSpace(f[2])
		}
		out = append(out, e)
	}
	return out, nil
}

func parseFastly(body []byte) ([]rangeEntry, error) {
	var doc struct {
		Addresses     []string `json:"addresses"`
		IPv6Addresses []string `json:"ipv6_addresses"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	var out []rangeEntry
	for _, p := range slices.Concat(doc.Addresses, doc.IPv6Addresses) {
		out = append(out, rangeEntry{prefix: p})
	}
	return out, nil
}

// parseOracle reads Oracle's list, which tags each range (OCI, OSN, OBJECT_STORAGE).
// A range with two tags is two entries, one per tag, so each is a service of its own.
func parseOracle(body []byte) ([]rangeEntry, error) {
	var doc struct {
		Regions []struct {
			Region string `json:"region"`
			CIDRs  []struct {
				CIDR string   `json:"cidr"`
				Tags []string `json:"tags"`
			} `json:"cidrs"`
		} `json:"regions"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	var out []rangeEntry
	for _, r := range doc.Regions {
		for _, c := range r.CIDRs {
			tags := c.Tags
			if len(tags) == 0 {
				tags = []string{""}
			}
			for _, t := range tags {
				out = append(out, rangeEntry{c.CIDR, t, r.Region})
			}
		}
	}
	return out, nil
}
