// Package providerranges fetches the published AWS and GCP address ranges, which
// tell a dedicated virtual machine from a CDN or load-balancer address.
// Azure has no stable range URL, so Azure is recognised by ASN alone.
package providerranges

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"

	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/stages/httpsrc"
)

// Stage is the providerranges stage: one check per provider, refreshed by --redo providerranges.
type Stage struct{}

// New returns the providerranges stage.
func New() *Stage { return &Stage{} }

func (*Stage) Name() string                      { return "providerranges" }
func (*Stage) Contact() run.Contact              { return run.ThirdParty }
func (*Stage) Sources() []string                 { return []string{"ip-ranges.amazonaws.com", "www.gstatic.com"} }
func (*Stage) Configured(run.Env) (bool, string) { return true, "" }

func (*Stage) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		for _, p := range []string{"aws", "gcp"} {
			if !yield(run.Check{Key: p, Input: p}, nil) {
				return
			}
		}
	}
}

func rangeObs(provider, prefix, service, region string) (run.Observation, bool) {
	p, err := input.ParseCIDR(prefix)
	if err != nil {
		return run.Observation{}, false
	}
	key := provider + "|" + p.String() + "|" + service
	return run.Observation{Kind: "provider_range", Key: key, Attrs: map[string]any{
		"provider": provider, "prefix": p.String(), "service": service, "region": region}}, true
}

// Run downloads and parses one provider's ranges. A body that is cut off is an error.
func (*Stage) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	var obs []run.Observation
	switch c.Key {
	case "aws":
		body, err := httpsrc.Get(ctx, e, egress.ThirdPartyRequest{Method: "GET", URL: "https://ip-ranges.amazonaws.com/ip-ranges.json"})
		if err != nil {
			return nil, fmt.Errorf("aws ranges: %w", err)
		}
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
			return nil, fmt.Errorf("aws ranges: unreadable response: %v", err)
		}
		for _, p := range doc.Prefixes {
			if o, ok := rangeObs("aws", p.IPPrefix, p.Service, p.Region); ok {
				obs = append(obs, o)
			}
		}
		for _, p := range doc.IPv6 {
			if o, ok := rangeObs("aws", p.IPPrefix, p.Service, p.Region); ok {
				obs = append(obs, o)
			}
		}
	case "gcp":
		body, err := httpsrc.Get(ctx, e, egress.ThirdPartyRequest{Method: "GET", URL: "https://www.gstatic.com/ipranges/cloud.json"})
		if err != nil {
			return nil, fmt.Errorf("gcp ranges: %w", err)
		}
		var doc struct {
			Prefixes []struct {
				IPv4  string `json:"ipv4Prefix"`
				IPv6  string `json:"ipv6Prefix"`
				Scope string `json:"scope"`
			} `json:"prefixes"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, fmt.Errorf("gcp ranges: unreadable response: %v", err)
		}
		for _, p := range doc.Prefixes {
			prefix := p.IPv4
			if prefix == "" {
				prefix = p.IPv6
			}
			if o, ok := rangeObs("gcp", prefix, "", p.Scope); ok {
				obs = append(obs, o)
			}
		}
	default:
		return nil, fmt.Errorf("unknown provider %q", c.Key)
	}
	return obs, nil
}
