package web

import (
	"context"
	"fmt"
	"iter"
	"maps"
	"net/url"
	"slices"
	"strings"

	"github.com/rafaelh/recon/internal/cloudstorage"
	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/scope"
)

// urlsPerPage caps the URLs one crawl records at this many per page allowed, so
// a calendar or faceted search cannot flood urls.csv (Spec 3 D14).
const urlsPerPage = 20

// Crawl is the crawl stage: a breadth-first walk of one web service's own
// pages with GET only. It never submits a form, never reads robots.txt or
// sitemap.xml, and never leaves the service's origin.
type Crawl struct{}

// NewCrawl returns the crawl stage.
func NewCrawl() *Crawl { return &Crawl{} }

func (*Crawl) Name() string         { return "crawl" }
func (*Crawl) Contact() run.Contact { return run.Target }
func (*Crawl) Sources() []string    { return nil }

// Configured: crawl.max_pages 0 turns the crawl off.
func (*Crawl) Configured(e run.Env) (bool, string) {
	if e.Settings.Crawl.MaxPages == 0 {
		return false, "disabled"
	}
	return true, ""
}

type crawlInput struct {
	sc            *scope.Scope
	host, scheme  string
	port          int
	depth, pages  int
	origin, start string
}

// Checks yields one check per current web service whose host is still in
// scope. The key carries the limits, so changing them creates new checks.
func (*Crawl) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		set := v.Settings().Crawl
		for _, rec := range v.Records(kinds.WebService) { // in key order
			svc, ok := egress.ParseService(rec.Key)
			if !ok || !v.Scope().WebHostInScope(svc.Host) {
				continue
			}
			in := crawlInput{sc: v.Scope(), host: svc.Host, scheme: svc.Scheme, port: svc.Port, depth: set.MaxDepth, pages: set.MaxPages, origin: rec.Key}
			in.start, _ = NormaliseURL(rec.Key + "/")
			key := fmt.Sprintf("%s|depth=%d|pages=%d", rec.Key, set.MaxDepth, set.MaxPages)
			if !yield(run.Check{Key: key, Input: in}, nil) {
				return
			}
		}
	}
}

type recordedURL struct {
	url, host string
	status    int
}

type queued struct {
	url   string
	depth int
}

type crawler struct {
	ctx context.Context
	in  crawlInput
	e   egress.Clients

	gets     int
	visited  map[string]bool
	recorded map[string]int
	urls     []recordedURL
	hosts    map[string]bool
	queue    []queued
	anchor   egress.Response // a same-origin response, the base egress.Link resolves from

	storage     map[string]*storageRef // "page|url" -> reference, for the cloud-storage checks
	storageKeys []string               // in first-seen order
}

// storageRef is a storage URL a page links to or loads (Spec 5 D8).
type storageRef struct {
	ref       cloudstorage.Ref
	url, page string
	via       string // "link" for an <a> or <area>, else "asset"
}

// Run crawls one service. Only an error on the root page fails the check; any
// other page that cannot be fetched is skipped.
func (*Crawl) Run(ctx context.Context, chk run.Check, e egress.Clients) ([]run.Observation, error) {
	in := chk.Input.(crawlInput)
	c := &crawler{ctx: ctx, in: in, e: e, visited: map[string]bool{in.start: true}, recorded: map[string]int{}, hosts: map[string]bool{}, storage: map[string]*storageRef{}}
	c.record(in.start)
	root, scan, err := c.fetchPage(egress.Root(in.host, in.scheme, in.port), in.start)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", chk.Key, err)
	}
	if !scan { // not answering, or the root moved to another origin, which has its own crawl
		return c.observations(), nil
	}
	// egress.Link only needs where the root came from, not its body.
	c.anchor = root
	c.anchor.Body, c.anchor.Header, c.anchor.PeerCerts = nil, nil, nil
	c.scan(root, 0)
	for len(c.queue) > 0 && c.gets < in.pages {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		q := c.queue[0]
		c.queue = c.queue[1:]
		req, err := egress.Link(c.anchor, q.url)
		if err != nil {
			continue
		}
		resp, scan, err := c.fetchPage(req, q.url)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return nil, cerr
			}
			continue
		}
		if scan {
			c.scan(resp, q.depth)
		}
	}
	return c.observations(), nil
}

// fetchPage GETs one page and follows same-origin redirects, each a GET that
// counts toward the page limit. scan is true if a page answered on this
// origin; it is false if nothing answered or the page redirected to another
// origin, which is recorded and not requested.
func (c *crawler) fetchPage(req egress.Request, page string) (resp egress.Response, scan bool, err error) {
	for hop := 0; ; hop++ {
		c.gets++
		res, err := c.e.HTTP.Get(c.ctx, req)
		if err != nil {
			return resp, false, err
		}
		r, live := res.(egress.Response)
		if !live {
			return resp, false, nil
		}
		resp = r
		c.setStatus(page, r.Status)
		if !isRedirect(r.Status) || r.Location == "" || hop >= maxHops {
			return resp, true, nil
		}
		target, tok := redirectTarget(r)
		if !tok {
			return resp, true, nil
		}
		c.record(target)
		if originOf(target) != c.in.origin {
			return resp, false, nil
		}
		if neverRequested(target) || c.visited[target] || c.gets >= c.in.pages {
			return resp, true, nil
		}
		c.visited[target] = true
		if req, err = egress.Redirect(r); err != nil {
			return resp, true, nil
		}
		page = target
	}
}

// scan records the links of an HTML page and queues the followable ones.
func (c *crawler) scan(resp egress.Response, depth int) {
	if resp.ContentType() != "text/html" {
		return
	}
	pg, ok := parsePage(resp.Body)
	if !ok {
		return
	}
	base, err := url.Parse(resp.URL())
	if err != nil {
		return
	}
	l := pg.links()
	if l.base != "" { // as a browser does: <base href> resolves against the page's URL
		if b, err := base.Parse(l.base); err == nil && (b.Scheme == "http" || b.Scheme == "https") {
			base = b
		}
	}
	handle := func(href string, follow bool) {
		t, err := base.Parse(href)
		if err != nil {
			return
		}
		abs, ok := NormaliseURL(t.String())
		if !ok {
			return
		}
		c.record(abs)
		if follow && depth < c.in.depth && originOf(abs) == c.in.origin && !IsStaticAsset(t.Path) && !neverRequested(abs) &&
			!c.visited[abs] && len(c.queue)+c.gets < c.in.pages {
			c.visited[abs] = true
			c.queue = append(c.queue, queued{abs, depth + 1})
		}
	}
	for _, h := range l.follow {
		handle(h, true)
	}
	for _, h := range l.record {
		handle(h, false)
	}
	pageURL, _ := NormaliseURL(resp.URL())
	for _, r := range l.refs {
		c.storageRef(base, r, pageURL)
	}
}

// storageRef records a link or asset that names a cloud-storage bucket, wherever
// it points: the host being off-scope does not make it uninteresting. No request is made.
func (c *crawler) storageRef(base *url.URL, r linkRef, page string) {
	t, err := base.Parse(r.url)
	if err != nil || page == "" {
		return
	}
	abs, ok := NormaliseURL(t.String())
	if !ok {
		return
	}
	ref, ok := cloudstorage.ParseRef(abs)
	if !ok {
		return
	}
	via := "asset"
	if r.tag == "a" || r.tag == "area" {
		via = "link"
	}
	key := page + "|" + abs
	if prev, seen := c.storage[key]; seen {
		if via == "asset" {
			prev.via = via // a browser loading it matters more than a link to it
		}
		return
	}
	c.storage[key] = &storageRef{ref: ref, url: abs, page: page, via: via}
	c.storageKeys = append(c.storageKeys, key)
}

// record notes a URL whose host is in scope (up to the cap) and, if the host is
// another in-scope name, the hostname. Off-scope hosts are ignored.
func (c *crawler) record(abs string) {
	if _, seen := c.recorded[abs]; seen { // its host was handled when it was first recorded
		return
	}
	host := HostOfURL(abs)
	if !c.in.sc.WebHostInScope(host) {
		return
	}
	if len(c.urls) < urlsPerPage*c.in.pages {
		c.recorded[abs] = len(c.urls)
		c.urls = append(c.urls, recordedURL{url: abs, host: host})
	}
	if d, ok := otherHost(host, c.in.host); ok {
		c.hosts[d] = true
	}
}

func (c *crawler) setStatus(page string, status int) {
	if i, ok := c.recorded[page]; ok {
		c.urls[i].status = status
	}
}

func (c *crawler) observations() []run.Observation {
	var out []run.Observation
	for _, u := range c.urls {
		attrs := map[string]any{"url": u.url, "host": u.host}
		if u.status != 0 {
			attrs["status"] = u.status
		}
		out = append(out, run.Observation{Kind: "url", Key: u.url, Attrs: attrs})
	}
	for _, h := range slices.Sorted(maps.Keys(c.hosts)) {
		out = append(out, kinds.Hostname.Obs(h, kinds.HostnameAttrs{}))
	}
	for _, k := range c.storageKeys {
		out = append(out, storageObservation(*c.storage[k]))
	}
	return out
}

// neverRequested is true for robots.txt and sitemap.xml: the crawl may record a
// link to one but does not ask for it, and does not honour robots.txt (D14).
func neverRequested(abs string) bool {
	u, err := url.Parse(abs)
	if err != nil {
		return false
	}
	switch strings.ToLower(u.Path) {
	case "/robots.txt", "/sitemap.xml":
		return true
	}
	return false
}

// originOf is the origin of a normalised absolute URL, in Origin's form.
func originOf(abs string) string {
	u, err := url.Parse(abs)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + egress.HostPort(u.Scheme, strings.ToLower(u.Hostname()), u.Port())
}

// storageObservation is the storage_ref observation of a reference, keyed by
// the page and the URL it references.
func storageObservation(r storageRef) run.Observation {
	return run.Observation{Kind: "storage_ref", Key: r.page + "|" + r.url, Attrs: map[string]any{
		"provider": r.ref.Provider, "name": r.ref.Name, "container": r.ref.Container, "object": r.ref.Object,
		"url": r.url, "page": r.page, "page_host": HostOfURL(r.page), "via": r.via,
	}}
}
