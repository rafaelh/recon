package risk

import (
	"context"
	"fmt"
	"iter"
	"slices"
	"strconv"

	"github.com/rafaelh/recon/internal/config"
	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/run"
)

// SensitivePaths is the sensitive-paths stage: each configured path is requested
// once per live web service, except services third-party SaaS platforms serve.
// Only a response matching the entry's signature is recorded, and
// its body is never stored.
type SensitivePaths struct{}

// NewSensitivePaths returns the sensitive-paths stage.
func NewSensitivePaths() *SensitivePaths { return &SensitivePaths{} }

func (*SensitivePaths) Name() string                      { return "sensitive-paths" }
func (*SensitivePaths) Contact() run.Contact              { return run.Target }
func (*SensitivePaths) Sources() []string                 { return nil }
func (*SensitivePaths) Configured(run.Env) (bool, string) { return true, "" }

// RetiresUnlistedChecks: a check of an edited entry supersedes the old one's evidence.
func (*SensitivePaths) RetiresUnlistedChecks() {}

type pathInput struct {
	service string // the web_service key
	svc     egress.Service
	index   int
	entry   config.SensitivePath
}

// Budget is the most requests the stage sends in one run.
func (*SensitivePaths) Budget(s config.Settings) int { return s.SensitivePathMaxRequests }

// Checks yields (service, entry) checks entry by entry in severity order (the
// list order within a severity), then by service, so the budget gives every
// service its highest-severity paths first and consecutive requests go to
// different hosts. The key hashes the entry's signature, magic and status; the
// egress index is the entry's position in the configured list.
func (*SensitivePaths) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		var svcs []pathInput
		for _, ws := range v.WebServices() {
			if !v.SaaSServed(ws.Svc.Host) {
				svcs = append(svcs, pathInput{service: ws.Key, svc: ws.Svc})
			}
		}
		entries := v.Settings().SensitivePathEntries
		order := make([]int, len(entries))
		for i := range order {
			order[i] = i
		}
		slices.SortStableFunc(order, func(a, b int) int { return entries[a].SeverityRank() - entries[b].SeverityRank() })
		for _, i := range order {
			entry := entries[i]
			hash := entry.Hash()
			for _, in := range svcs {
				in.index, in.entry = i, entry
				key := fmt.Sprintf("%s|%s|%s", in.service, entry.Path, hash)
				if !yield(run.Check{Key: key, Input: in}, nil) {
					return
				}
			}
		}
	}
}

// Run requests the path. A response with the expected status and signature is a
// sensitive_hit; no match, no service or a refusal complete with nothing.
func (*SensitivePaths) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	in := c.Input.(pathInput)
	res, err := e.HTTP.Get(ctx, egress.SensitivePath(in.svc, in.index))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.Key, err)
	}
	r, ok := res.(egress.Response)
	if !ok {
		return nil, nil
	}
	sig, ok := in.entry.Match(r.Status, r.Body)
	if !ok {
		return nil, nil
	}
	hash := in.entry.Hash()
	return []run.Observation{kinds.SensitiveHit.Obs(in.service+"|"+in.entry.Path+"|"+hash, kinds.SensitiveHitAttrs{
		Service: in.service, Host: in.svc.Host, URL: in.service + in.entry.Path, Path: in.entry.Path,
		Status: r.Status, Size: bodySize(r), Signature: sig, Hash: hash,
	})}, nil
}

// bodySize is the size of the response: its Content-Length when the body may
// have been cut at egress.MaxTargetBody, else the body's length. A cut body
// without a usable Content-Length is "<cap>+".
func bodySize(r egress.Response) kinds.Size {
	if len(r.Body) < egress.MaxTargetBody {
		return kinds.SizeOf(int64(len(r.Body)))
	}
	if vals := r.Header["Content-Length"]; len(vals) > 0 {
		if n, err := strconv.ParseInt(vals[0], 10, 64); err == nil && n >= int64(len(r.Body)) {
			return kinds.SizeOf(n)
		}
	}
	return kinds.Size(fmt.Sprintf("%d+", len(r.Body)))
}
