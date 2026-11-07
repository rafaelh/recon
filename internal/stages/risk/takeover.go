package risk

import (
	"context"
	"fmt"
	"iter"

	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/inventory"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/run"
)

// Takeover is the takeover stage: one GET of "/" for each live web service whose
// host is on a provider with an unclaimed-resource fingerprint (Spec 5 D7). DNS
// evidence needs no request and is derived by the findings package.
type Takeover struct{}

// NewTakeover returns the takeover stage.
func NewTakeover() *Takeover { return &Takeover{} }

func (*Takeover) Name() string                      { return "takeover" }
func (*Takeover) Contact() run.Contact              { return run.Target }
func (*Takeover) Sources() []string                 { return nil }
func (*Takeover) Configured(run.Env) (bool, string) { return true, "" }

// RetiresUnlistedChecks: a check of an edited entry supersedes the old one's evidence.
func (*Takeover) RetiresUnlistedChecks() {}

type takeoverInput struct {
	service string // the web_service key
	svc     egress.Service
	ph      inventory.ProviderHost
}

// Checks yields one check per current, visible service and matched fingerprint
// entry. The key carries a hash of the entry only, so editing one fingerprint
// re-checks just the services it matches.
func (*Takeover) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		byHost := map[string][]inventory.ProviderHost{}
		for _, ph := range v.ProviderHosts() {
			if ph.Entry.Body != "" {
				byHost[ph.Hostname] = append(byHost[ph.Hostname], ph)
			}
		}
		if len(byHost) == 0 {
			return
		}
		for _, ws := range v.WebServices() {
			for _, ph := range byHost[ws.Svc.Host] {
				in := takeoverInput{service: ws.Key, svc: ws.Svc, ph: ph}
				if !yield(run.Check{Key: fmt.Sprintf("%s|fp=%s", ws.Key, ph.Entry.Hash()), Input: in}, nil) {
					return
				}
			}
		}
	}
}

// Run requests the service's root. A body matching the fingerprint is a
// takeover_http observation; anything else, including a refusal, completes
// with nothing. A transport error is transient.
func (*Takeover) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	in := c.Input.(takeoverInput)
	res, err := e.HTTP.Get(ctx, egress.Root(in.svc.Host, in.svc.Scheme, in.svc.Port))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.Key, err)
	}
	r, ok := res.(egress.Response)
	if !ok || !in.ph.Entry.BodyMatches(r.Body) {
		return nil, nil
	}
	return []run.Observation{kinds.TakeoverHTTP.Obs(in.service, kinds.TakeoverHTTPAttrs{
		Host: in.svc.Host, URL: in.service + "/", Status: r.Status, Service: in.service,
		Provider: in.ph.Provider, ProviderService: in.ph.Service, CNAME: in.ph.CNAME,
	})}, nil
}
