package subdomains

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/stages/httpsrc"
)

// The sources here work without a key. Each records hostnames only: the
// addresses, URLs and certificate data they also return are dropped by the
// parsers, and a name outside the queried root by Stage.Run.
//
// A source's 404 means it has nothing for the root, and its 429 means its free
// quota is spent (httpsrc.GetQuota). A body that is not the shape the parser
// expects is an error, never an empty result: an error object sent with status
// 200 must be retried, not recorded as "no names".

// fetchNames GETs u and turns the body into names with parse; a 404 is no names.
func fetchNames(ctx context.Context, c egress.Clients, u string, parse func([]byte) ([]string, error)) (result, error) {
	body, err := httpsrc.GetQuota(ctx, c, egress.ThirdPartyRequest{Method: "GET", URL: u})
	if errors.Is(err, httpsrc.ErrNotFound) {
		return result{}, nil
	}
	if err != nil {
		return result{}, err
	}
	names, err := parse(body)
	return result{names: names}, err
}

// --- AlienVault OTX (passive DNS) ---

func otx(ctx context.Context, in rootInput, c egress.Clients) (result, error) {
	return fetchNames(ctx, c, "https://otx.alienvault.com/api/v1/indicators/domain/"+url.PathEscape(in.root)+"/passive_dns", otxNames)
}

func otxNames(body []byte) ([]string, error) {
	var r struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.PassiveDNS == nil {
		return nil, errors.New("unreadable OTX response")
	}
	names := make([]string, len(r.PassiveDNS))
	for i, p := range r.PassiveDNS {
		names[i] = p.Hostname
	}
	return names, nil
}

// --- HackerTarget (hostsearch) ---

func hackertarget(ctx context.Context, in rootInput, c egress.Clients) (result, error) {
	return fetchNames(ctx, c, "https://api.hackertarget.com/hostsearch/?"+url.Values{"q": {in.root}}.Encode(), hackertargetNames)
}

// hackertargetNames reads "host,address" lines. An empty body (no lines) and its
// two "nothing found" replies are empty; its spent quota is a 200 reply with a
// text body.
func hackertargetNames(body []byte) ([]string, error) {
	text := strings.TrimSpace(string(body))
	switch lower := strings.ToLower(text); {
	case lower == "", lower == "no records found", lower == "error check your search parameter":
		return nil, nil
	case strings.HasPrefix(lower, "api count exceeded"):
		return nil, fmt.Errorf("HackerTarget API count exceeded: %w", run.ErrQuota)
	}
	var names []string
	for line := range strings.SplitSeq(text, "\n") {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		host, _, ok := strings.Cut(line, ",")
		if !ok {
			return nil, errors.New("unreadable HackerTarget response")
		}
		names = append(names, host)
	}
	return names, nil
}

// --- urlscan.io (search) ---

// urlscan reads the first page of search results only; it warns when there are more.
func urlscan(ctx context.Context, in rootInput, c egress.Clients) (result, error) {
	return fetchNames(ctx, c, "https://urlscan.io/api/v1/search/?"+url.Values{"q": {"domain:" + in.root}}.Encode(), func(body []byte) ([]string, error) {
		names, more, err := urlscanNames(body)
		if err == nil && more {
			run.Warnf(ctx, "urlscan %s: result truncated after the first page of search results", in.root)
		}
		return names, err
	})
}

// urlscanNames returns the names in a search answer and whether the answer is
// cut short. Live answers report has_more=false while total exceeds the page, so
// both are read.
func urlscanNames(body []byte) ([]string, bool, error) {
	var r struct {
		HasMore bool `json:"has_more"`
		Total   int  `json:"total"`
		Results []struct {
			Page struct {
				Domain string `json:"domain"`
			} `json:"page"`
			Task struct {
				Domain string `json:"domain"`
			} `json:"task"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.Results == nil {
		return nil, false, errors.New("unreadable urlscan response")
	}
	var names []string
	for _, x := range r.Results {
		names = append(names, x.Page.Domain, x.Task.Domain)
	}
	return names, r.HasMore || r.Total > len(r.Results), nil
}

// --- Anubis (jldc.me) ---

func anubis(ctx context.Context, in rootInput, c egress.Clients) (result, error) {
	return fetchNames(ctx, c, "https://jldc.me/anubis/subdomains/"+url.PathEscape(in.root), anubisNames)
}

func anubisNames(body []byte) ([]string, error) {
	var names []string
	if err := json.Unmarshal(body, &names); err != nil || names == nil {
		return nil, errors.New("unreadable Anubis response")
	}
	return names, nil
}

// --- Cert Spotter (issuances) ---

// certspotter follows the result pages, in.pages at most. The key is optional:
// it raises the rate limit, and is sent only when the check was made with one.
func certspotter(ctx context.Context, in rootInput, c egress.Clients) (result, error) {
	var names []string
	after := ""
	for page := 0; ; page++ {
		if page == in.pages {
			run.Warnf(ctx, "certspotter %s: result truncated after %d pages; raise certspotter.max_pages to read more", in.root, in.pages)
			break
		}
		q := url.Values{"domain": {in.root}, "include_subdomains": {"true"}, "expand": {"dns_names"}}
		if after != "" {
			q.Set("after", after)
		}
		req := egress.ThirdPartyRequest{Method: "GET", URL: "https://api.certspotter.com/v1/issuances?" + q.Encode()}
		if in.keyed {
			req.KeySource, req.KeyHeader, req.KeyPrefix = "certspotter", "Authorization", "Bearer "
		}
		body, err := httpsrc.GetQuota(ctx, c, req)
		if errors.Is(err, httpsrc.ErrNotFound) {
			break
		}
		if err != nil {
			return result{}, err
		}
		var rows []struct {
			ID       string   `json:"id"`
			DNSNames []string `json:"dns_names"`
		}
		if err := json.Unmarshal(body, &rows); err != nil || rows == nil {
			return result{}, errors.New("unreadable Cert Spotter response")
		}
		if len(rows) == 0 {
			break
		}
		for _, r := range rows {
			names = append(names, r.DNSNames...)
		}
		if after = rows[len(rows)-1].ID; after == "" {
			return result{}, errors.New("unreadable Cert Spotter response: an issuance has no id to page from")
		}
	}
	return result{names: names}, nil
}
