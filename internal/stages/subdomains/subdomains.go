// Package subdomains has the per-source stages that list subdomains of an
// in-scope root: crtsh, wayback, commoncrawl, virustotal and securitytrails.
// They share one check and enumeration type; each source is a fetcher.
package subdomains

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"maps"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/stages/httpsrc"
)

// maxPages caps archive and API paging inside one check (D24).
const maxPages = 30

// result is what a fetcher found. Attrs are attached to every hostname.
type result struct {
	names []string
	attrs map[string]any
}

type fetcher func(ctx context.Context, root string, c egress.Clients) (result, error)

// Stage is one subdomain source.
type Stage struct {
	name    string
	sources []string
	keyed   bool
	fetch   fetcher
}

// New returns every subdomain stage in registry order.
func New() []run.Stage {
	return []run.Stage{
		&Stage{name: "crtsh", sources: []string{"crt.sh"}, fetch: crtsh},
		&Stage{name: "wayback", sources: []string{"web.archive.org"}, fetch: wayback},
		&Stage{name: "commoncrawl", sources: []string{"index.commoncrawl.org"}, fetch: commoncrawl},
		&Stage{name: "virustotal", sources: []string{"www.virustotal.com"}, keyed: true, fetch: virustotal},
		&Stage{name: "securitytrails", sources: []string{"api.securitytrails.com"}, keyed: true, fetch: securitytrails},
	}
}

func (s *Stage) Name() string         { return s.name }
func (s *Stage) Contact() run.Contact { return run.ThirdParty }
func (s *Stage) Sources() []string    { return s.sources }

// Configured: keyed sources need keys.<source>.
func (s *Stage) Configured(e run.Env) (bool, string) { return httpsrc.Configured(e, s.name, s.keyed) }

// Checks yields one check per in-scope root.
func (*Stage) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		for _, r := range v.Inputs().Roots {
			if !yield(run.Check{Key: r, Input: r}, nil) {
				return
			}
		}
	}
}

// Run fetches the root's subdomains and records those under it.
func (s *Stage) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	root := c.Key
	res, err := s.fetch(ctx, root, e)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", s.name, root, err)
	}
	seen := map[string]bool{}
	var obs []run.Observation
	for _, n := range res.names {
		n = cleanName(n)
		if n == "" || seen[n] || !(n == root || strings.HasSuffix(n, "."+root)) {
			continue
		}
		seen[n] = true
		obs = append(obs, run.Observation{Kind: "hostname", Key: n, Attrs: res.attrs})
	}
	sort.Slice(obs, func(i, j int) bool { return obs[i].Key < obs[j].Key })
	return obs, nil
}

// cleanName normalises a name from a source; wildcards and non-hostnames are dropped.
func cleanName(n string) string {
	n = input.NormaliseHost(strings.TrimSpace(n))
	if n == "" || strings.ContainsAny(n, "*@/: ") {
		return ""
	}
	if _, err := input.ParseDomain(n); err != nil {
		return ""
	}
	return n
}

// --- crt.sh ---

// crtshNames returns the names in a crt.sh JSON answer: name_value holds one or
// more names separated by newlines.
func crtshNames(body []byte) ([]string, error) {
	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("unreadable crt.sh response: %v", err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, strings.Split(r.NameValue, "\n")...)
	}
	return out, nil
}

func crtsh(ctx context.Context, root string, c egress.Clients) (result, error) {
	body, err := httpsrc.Crtsh(ctx, c, url.Values{"q": {"%." + root}})
	if err != nil {
		return result{}, err
	}
	names, err := crtshNames(body)
	return result{names: names}, err
}

// --- Wayback Machine (CDX) ---

func hostOfURL(raw string) string {
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func wayback(ctx context.Context, root string, c egress.Clients) (result, error) {
	base := url.Values{"url": {root}, "matchType": {"domain"}, "output": {"json"}, "fl": {"original"}, "collapse": {"urlkey"}}
	count := url.Values{"url": {root}, "matchType": {"domain"}, "showNumPages": {"true"}}
	body, err := httpsrc.Get(ctx, c, egress.ThirdPartyRequest{Method: "GET", URL: "https://web.archive.org/cdx/search/cdx?" + count.Encode()})
	if err != nil {
		return result{}, err
	}
	pages, err := strconv.Atoi(strings.TrimSpace(string(body)))
	if err != nil {
		return result{}, fmt.Errorf("unreadable CDX page count: %v", err)
	}
	pages = min(pages, maxPages)
	var names []string
	for p := 0; p < pages; p++ {
		q := maps.Clone(base) // shallow is enough: only Set follows
		q.Set("page", strconv.Itoa(p))
		body, err := httpsrc.Get(ctx, c, egress.ThirdPartyRequest{Method: "GET", URL: "https://web.archive.org/cdx/search/cdx?" + q.Encode()})
		if err != nil {
			return result{}, err
		}
		var rows [][]string
		if err := json.Unmarshal(body, &rows); err != nil {
			return result{}, fmt.Errorf("unreadable CDX page %d: %v", p, err)
		}
		for i, r := range rows {
			if i == 0 && len(r) > 0 && r[0] == "original" || len(r) == 0 {
				continue
			}
			names = append(names, hostOfURL(r[0]))
		}
	}
	return result{names: names}, nil
}

// --- Common Crawl ---

func commoncrawl(ctx context.Context, root string, c egress.Clients) (result, error) {
	body, err := httpsrc.Get(ctx, c, egress.ThirdPartyRequest{Method: "GET", URL: "https://index.commoncrawl.org/collinfo.json"})
	if err != nil {
		return result{}, err
	}
	var colls []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &colls); err != nil || len(colls) == 0 {
		return result{}, errors.New("unreadable Common Crawl collection list")
	}
	id := colls[0].ID
	endpoint := "https://index.commoncrawl.org/" + id + "-index?"
	count := url.Values{"url": {"*." + root}, "output": {"json"}, "showNumPages": {"true"}}
	body, err = httpsrc.Get(ctx, c, egress.ThirdPartyRequest{Method: "GET", URL: endpoint + count.Encode()})
	if err != nil {
		return result{}, err
	}
	var np struct {
		Pages int `json:"pages"`
	}
	if err := json.Unmarshal(body, &np); err != nil {
		return result{}, fmt.Errorf("unreadable Common Crawl page count: %v", err)
	}
	var names []string
	for p := 0; p < min(np.Pages, maxPages); p++ {
		q := url.Values{"url": {"*." + root}, "output": {"json"}, "fl": {"url"}, "page": {strconv.Itoa(p)}}
		body, err := httpsrc.Get(ctx, c, egress.ThirdPartyRequest{Method: "GET", URL: endpoint + q.Encode()})
		// The page count is of index blocks, not matches: a page with no
		// captures answers 404 "No Captures found".
		if errors.Is(err, httpsrc.ErrNotFound) {
			continue
		}
		if err != nil {
			return result{}, err
		}
		for _, line := range strings.Split(string(body), "\n") {
			var row struct {
				URL string `json:"url"`
			}
			if line = strings.TrimSpace(line); line != "" && json.Unmarshal([]byte(line), &row) == nil {
				names = append(names, hostOfURL(row.URL))
			}
		}
	}
	return result{names: names, attrs: map[string]any{"index": id}}, nil
}

// --- VirusTotal ---

func virustotal(ctx context.Context, root string, c egress.Clients) (result, error) {
	var names []string
	cursor := ""
	for page := 0; page < maxPages; page++ {
		q := url.Values{"limit": {"40"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		body, err := httpsrc.Get(ctx, c, egress.ThirdPartyRequest{
			Method: "GET", URL: "https://www.virustotal.com/api/v3/domains/" + url.PathEscape(root) + "/subdomains?" + q.Encode(),
			KeySource: "virustotal", KeyHeader: "x-apikey",
		})
		// VirusTotal answers 404 NotFoundError for a domain it has no data on.
		if errors.Is(err, httpsrc.ErrNotFound) {
			break
		}
		if err != nil {
			return result{}, err
		}
		var r struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
			Meta struct {
				Cursor string `json:"cursor"`
			} `json:"meta"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			return result{}, fmt.Errorf("unreadable VirusTotal response: %v", err)
		}
		for _, d := range r.Data {
			names = append(names, d.ID)
		}
		if cursor = r.Meta.Cursor; cursor == "" {
			break
		}
	}
	return result{names: names}, nil
}

// --- SecurityTrails ---

func securitytrails(ctx context.Context, root string, c egress.Clients) (result, error) {
	body, err := httpsrc.Get(ctx, c, egress.ThirdPartyRequest{
		Method: "GET", URL: "https://api.securitytrails.com/v1/domain/" + url.PathEscape(root) + "/subdomains?children_only=false&include_inactive=true",
		KeySource: "securitytrails", KeyHeader: "APIKEY",
	})
	if err != nil {
		return result{}, err
	}
	var r struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return result{}, fmt.Errorf("unreadable SecurityTrails response: %v", err)
	}
	names := make([]string, len(r.Subdomains))
	for i, l := range r.Subdomains {
		names[i] = l + "." + root
	}
	return result{names: names}, nil
}
