// Package httpsrc has what every third-party HTTP source stage shares.
package httpsrc

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/run"
)

// Configured is the Configured result for a source: a keyed source needs keys.<name>.
func Configured(e run.Env, name string, keyed bool) (bool, string) {
	if keyed {
		if _, ok := e.Key(name); !ok {
			return false, "no key"
		}
	}
	return true, ""
}

// Crtsh queries crt.sh's JSON API for unexpired, deduplicated certificates
// matching q. crt.sh is slow on large result sets, hence the long timeout.
func Crtsh(ctx context.Context, c egress.Clients, q url.Values) ([]byte, error) {
	q.Set("output", "json")
	q.Set("exclude", "expired")
	q.Set("deduplicate", "Y")
	return Get(ctx, c, egress.ThirdPartyRequest{Method: "GET", URL: "https://crt.sh/?" + q.Encode(), Timeout: 90 * time.Second})
}

// ErrNotFound is a 404. Sources that answer 404 for "no data" treat it as an
// empty result; for the rest it is a transient error like any other status.
var ErrNotFound = errors.New("HTTP 404")

// Get performs a request and maps the failures every source shares. For a
// keyed request a 401, 403 or 429 aborts the stage: the key is bad or the
// quota is spent, so nothing may be recorded as done. A 404 is ErrNotFound.
// A truncated body or any other non-200 status is a transient error.
func Get(ctx context.Context, c egress.Clients, req egress.ThirdPartyRequest) ([]byte, error) {
	return get(ctx, c, req, false)
}

// GetQuota is Get for a source that answers 429 when its free quota is spent:
// the 429 of an unkeyed request, which Get treats as a failed check, returns
// run.ErrQuota, so the stage stops instead of sending the checks that remain.
// Get is left alone because most sources' 429 is no reason to stop the stage
// (one range publisher refusing must not stop the others).
func GetQuota(ctx context.Context, c egress.Clients, req egress.ThirdPartyRequest) ([]byte, error) {
	return get(ctx, c, req, true)
}

func get(ctx context.Context, c egress.Clients, req egress.ThirdPartyRequest, quota bool) ([]byte, error) {
	resp, err := c.ThirdParty.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	switch {
	case req.KeySource != "" && (resp.Status == 401 || resp.Status == 403 || resp.Status == 429):
		return nil, fmt.Errorf("HTTP %d (key rejected or quota exhausted): %w", resp.Status, run.ErrAbortStage)
	case quota && resp.Status == 429:
		return nil, fmt.Errorf("HTTP 429: %w", run.ErrQuota)
	case resp.Status == 404:
		return nil, ErrNotFound
	case resp.Status != 200:
		return nil, fmt.Errorf("HTTP %d", resp.Status)
	case resp.Truncated:
		return nil, errors.New("response was larger than the 10 MiB limit")
	}
	return resp.Body, nil
}

// CleanName returns a name a source reported in canonical form: lower case,
// punycode, with a trailing dot and a leading "*." removed, so a wildcard
// certificate name yields its base name. It returns "" for anything that is not a
// valid hostname: an address, a URL or a public suffix.
func CleanName(n string) string {
	n = strings.TrimPrefix(strings.TrimSpace(n), "*.") // ParseDomain does the rest of the normalising
	d, _ := input.ParseDomain(n)
	return d
}
