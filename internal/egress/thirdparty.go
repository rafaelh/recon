package egress

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/rafaelh/recon/internal/config"
	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/scope"
)

const maxThirdPartyBody = 10 << 20

// ThirdPartyRequest is a request to a third-party source.
type ThirdPartyRequest struct {
	Method      string // GET or POST
	URL         string // https URL whose host matches the calling stage's Sources()
	Body        []byte
	ContentType string
	// KeySource names a configured key to attach, as header KeyHeader and/or
	// query parameter KeyParam. The client attaches it; stages never handle it.
	KeySource, KeyHeader, KeyParam string
}

// ThirdPartyResponse is a response from a third-party source (body capped at 10 MiB).
type ThirdPartyResponse struct {
	Status int
	Header map[string][]string
	Body   []byte
}

// ThirdPartyHTTP talks to the hosts a stage declared in Sources().
type ThirdPartyHTTP interface {
	Do(ctx context.Context, r ThirdPartyRequest) (ThirdPartyResponse, error)
}

type thirdParty struct {
	e       *Egress
	stage   string
	sources []string
}

func matchSource(pattern, host string) bool {
	if rest, ok := strings.CutPrefix(pattern, "*."); ok {
		return strings.HasSuffix(host, "."+rest)
	}
	return host == pattern
}

func (t *thirdParty) Do(ctx context.Context, r ThirdPartyRequest) (ThirdPartyResponse, error) {
	e := t.e
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		return ThirdPartyResponse{}, fmt.Errorf("method %q is not permitted for third-party requests", r.Method)
	}
	u, err := url.Parse(r.URL)
	if err != nil || u.Host == "" {
		return ThirdPartyResponse{}, fmt.Errorf("invalid third-party URL %q", e.opts.Redactor.Redact(r.URL))
	}
	if u.Scheme != "https" || u.User != nil {
		return ThirdPartyResponse{}, errors.New("third-party requests must be https without userinfo")
	}
	host := input.NormaliseHost(u.Hostname())
	pattern := ""
	for _, s := range t.sources {
		if matchSource(s, host) {
			pattern = s
			break
		}
	}
	if pattern == "" {
		return ThirdPartyResponse{}, fmt.Errorf("host %s is not one of this stage's sources", host)
	}
	if p := e.policy(); p != nil {
		if p.Scope != nil {
			if c := p.Scope.ClassifyHost(host); c.Class == scope.InScope || c.Class == scope.Excluded {
				return ThirdPartyResponse{}, fmt.Errorf("host %s is %s; third-party clients never contact it", host, c.Class)
			}
		}
		if p.Candidates[host] {
			return ThirdPartyResponse{}, fmt.Errorf("host %s is a candidate; it is never contacted", host)
		}
	}
	if base, ok := e.opts.SourceBaseURLs[pattern]; ok {
		b, err := url.Parse(base)
		if err != nil {
			return ThirdPartyResponse{}, err
		}
		u.Scheme, u.Host = b.Scheme, b.Host
	}
	var key config.Secret
	if r.KeySource != "" {
		var ok bool
		if key, ok = e.opts.Keys[strings.ToLower(r.KeySource)]; !ok {
			return ThirdPartyResponse{}, fmt.Errorf("no key configured for %s", r.KeySource)
		}
		if r.KeyParam != "" {
			q := u.Query()
			q.Set(r.KeyParam, key.Reveal())
			u.RawQuery = q.Encode()
		}
	}
	if err := e.sourceLimiter(pattern).Wait(ctx); err != nil {
		return ThirdPartyResponse{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, e.opts.HTTPTimeout)
	defer cancel()
	var body io.Reader
	if len(r.Body) > 0 {
		body = bytes.NewReader(r.Body)
	}
	hreq, err := http.NewRequestWithContext(ctx, r.Method, u.String(), body)
	if err != nil {
		return ThirdPartyResponse{}, t.scrub(err)
	}
	hreq.Header.Set("User-Agent", userAgent)
	if r.ContentType != "" {
		hreq.Header.Set("Content-Type", r.ContentType)
	}
	if r.KeySource != "" && r.KeyHeader != "" {
		hreq.Header.Set(r.KeyHeader, key.Reveal())
	}
	resp, err := e.thirdParty.Do(hreq)
	if err != nil {
		return ThirdPartyResponse{}, t.scrub(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxThirdPartyBody))
	if err != nil {
		return ThirdPartyResponse{}, t.scrub(err)
	}
	return ThirdPartyResponse{Status: resp.StatusCode, Header: map[string][]string(resp.Header.Clone()), Body: data}, nil
}

// scrub removes key values from an error, including the URL net/http embeds.
func (t *thirdParty) scrub(err error) error {
	return errors.New(t.e.opts.Redactor.Redact(err.Error()))
}
