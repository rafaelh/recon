// Package asn expands input ASNs into announced netblocks using RIPEstat.
package asn

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/url"
	"strings"

	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/run"
)

// Stage is the asn stage. A netblock it observes under a check for an input
// ASN is in scope.
type Stage struct{}

// New returns the asn stage.
func New() *Stage { return &Stage{} }

func (*Stage) Name() string                      { return "asn" }
func (*Stage) Contact() run.Contact              { return run.ThirdParty }
func (*Stage) Sources() []string                 { return []string{"stat.ripe.net"} }
func (*Stage) Configured(run.Env) (bool, string) { return true, "" }

// Checks yields one check per input ASN, keyed "AS<n>".
func (*Stage) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		for _, a := range v.Inputs().ASNs {
			if !yield(run.Check{Key: a, Input: a}, nil) {
				return
			}
		}
	}
}

type announced struct {
	Status string `json:"status"`
	Data   struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	} `json:"data"`
}

// Run fetches the prefixes announced by the ASN. Anything but a well-formed
// "ok" answer is a transient failure.
func (*Stage) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	asn := c.Key
	q := url.Values{"resource": {asn}, "sourceapp": {"recon"}}
	resp, err := e.ThirdParty.Do(ctx, egress.ThirdPartyRequest{
		Method: "GET", URL: "https://stat.ripe.net/data/announced-prefixes/data.json?" + q.Encode(),
	})
	if err != nil {
		return nil, fmt.Errorf("asn %s: %w", asn, err)
	}
	if resp.Status != 200 {
		return nil, fmt.Errorf("asn %s: RIPEstat answered HTTP %d", asn, resp.Status)
	}
	var body announced
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return nil, fmt.Errorf("asn %s: unreadable RIPEstat response: %v", asn, err)
	}
	if body.Status != "ok" {
		return nil, fmt.Errorf("asn %s: RIPEstat status %q", asn, body.Status)
	}
	var obs []run.Observation
	for _, p := range body.Data.Prefixes {
		if p.Prefix = strings.TrimSpace(p.Prefix); p.Prefix != "" {
			obs = append(obs, run.Observation{Kind: "netblock", Key: p.Prefix, Attrs: map[string]any{"asn": asn}})
		}
	}
	return obs, nil
}
