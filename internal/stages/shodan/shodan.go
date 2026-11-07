// Package shodan finds hostnames for the in-scope netblocks with Shodan's net: search (keyed).
package shodan

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/url"
	"strconv"

	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/stages/httpsrc"
)

// maxPages caps the result pages read per netblock (each page past the first costs a credit).
const maxPages = 10

// Stage is the shodan stage.
type Stage struct{}

// New returns the shodan stage.
func New() *Stage { return &Stage{} }

func (*Stage) Name() string         { return "shodan" }
func (*Stage) Contact() run.Contact { return run.ThirdParty }
func (*Stage) Sources() []string    { return []string{"api.shodan.io"} }

func (*Stage) Configured(e run.Env) (bool, string) { return httpsrc.Configured(e, "shodan", true) }

// Checks yields one check per in-scope netblock, keyed by its CIDR.
func (*Stage) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		for _, p := range v.Scope().Netblocks() {
			if !yield(run.Check{Key: p.Masked().String(), Input: p.Masked().String()}, nil) {
				return
			}
		}
	}
}

type search struct {
	Matches []struct {
		IPStr     string   `json:"ip_str"`
		Hostnames []string `json:"hostnames"`
	} `json:"matches"`
	Total int `json:"total"`
}

// Run searches net:<cidr> and records each address and the hostnames Shodan has for it.
func (*Stage) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	var obs []run.Observation
	seen := map[string]bool{}
	got := 0
	for page := 1; page <= maxPages; page++ {
		q := url.Values{"query": {"net:" + c.Key}, "page": {strconv.Itoa(page)}}
		body, err := httpsrc.Get(ctx, e, egress.ThirdPartyRequest{
			Method: "GET", URL: "https://api.shodan.io/shodan/host/search?" + q.Encode(), KeySource: "shodan", KeyParam: "key",
		})
		if err != nil {
			return nil, fmt.Errorf("shodan %s: %w", c.Key, err)
		}
		var r search
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, fmt.Errorf("shodan %s: unreadable response: %v", c.Key, err)
		}
		for _, m := range r.Matches {
			if m.IPStr != "" && !seen["ip|"+m.IPStr] {
				seen["ip|"+m.IPStr] = true
				obs = append(obs, kinds.IP.Obs(m.IPStr))
			}
			for _, h := range m.Hostnames {
				h = input.NormaliseHost(h)
				if h == "" || seen[m.IPStr+"|"+h] {
					continue
				}
				seen[m.IPStr+"|"+h] = true
				obs = append(obs,
					kinds.Hostname.Obs(h, kinds.HostnameAttrs{}),
					kinds.IPHostname.Obs(m.IPStr+"|"+h, kinds.IPHostnameAttrs{IP: m.IPStr, Hostname: h, Source: "shodan"}))
			}
		}
		got += len(r.Matches)
		if len(r.Matches) == 0 || got >= r.Total {
			break
		}
	}
	return obs, nil
}
