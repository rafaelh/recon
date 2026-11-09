package web

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"net/url"
	"strings"

	"github.com/rafaelh/recon/internal/egress"
)

// readLists fetches robots.txt and the sitemaps (sitemap.xml, those robots.txt
// names and those a sitemap index names) and queues the same-origin URLs they
// list at depth 1, as if the root page linked to them. They are depth-1 items
// themselves, fetched only from the page budget the root's own links leave.
// robots.txt is read for its paths, not obeyed.
func (c *crawler) readLists(robots, sitemap string) {
	if c.in.depth < 1 {
		return
	}
	sitemaps := []string{sitemap}
	addSitemap := func(abs string) {
		if originOf(abs) == c.in.origin && !c.visited[abs] {
			c.visited[abs] = true
			sitemaps = append(sitemaps, abs)
		}
	}
	if body, ok := c.fetchList(robots); ok {
		paths, maps := parseRobots(body)
		for _, p := range paths {
			if abs, ok := resolve(robots, p); ok {
				c.record(abs)
				c.enqueue(abs, 1)
			}
		}
		for _, m := range maps {
			if abs, ok := resolve(robots, m); ok {
				c.record(abs)
				addSitemap(abs)
			}
		}
	}
	for i := 0; i < len(sitemaps); i++ {
		body, ok := c.fetchList(sitemaps[i])
		if !ok {
			continue
		}
		locs, index := parseSitemap(body)
		for _, l := range locs {
			abs, ok := NormaliseURL(l)
			if !ok {
				continue
			}
			c.record(abs)
			if index {
				addSitemap(abs)
			} else {
				c.enqueue(abs, 1)
			}
		}
	}
}

// fetchList GETs a robots.txt or sitemap and returns its body if it answered
// 2xx on this origin. Only then is its URL recorded, so a service without one
// adds no row.
func (c *crawler) fetchList(abs string) ([]byte, bool) {
	if len(c.queue)+c.gets >= c.in.pages {
		return nil, false
	}
	req, err := egress.Link(c.anchor, abs)
	if err != nil {
		return nil, false
	}
	resp, live, err := c.fetchPage(req, abs)
	if err != nil || !live || resp.Status/100 != 2 {
		return nil, false
	}
	if u, ok := NormaliseURL(resp.URL()); ok {
		c.record(u)
		c.setStatus(u, resp.Status)
	}
	return resp.Body, true
}

// resolve resolves ref against base and normalises the result.
func resolve(base, ref string) (string, bool) {
	b, err := url.Parse(base)
	if err != nil {
		return "", false
	}
	t, err := b.Parse(ref)
	if err != nil {
		return "", false
	}
	return NormaliseURL(t.String())
}

// parseRobots returns the paths of a robots.txt's Allow and Disallow lines,
// each cut at its first wildcard ("*" or "$"), and the URLs of its Sitemap lines.
func parseRobots(body []byte) (paths, sitemaps []string) {
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "allow", "disallow":
			if i := strings.IndexAny(val, "*$"); i >= 0 {
				val = val[:i]
			}
			if strings.HasPrefix(val, "/") {
				paths = append(paths, val)
			}
		case "sitemap":
			if val != "" {
				sitemaps = append(sitemaps, val)
			}
		}
	}
	return paths, sitemaps
}

// parseSitemap returns the <loc> values of a sitemap, and whether it is a
// sitemap index (whose locs are further sitemaps rather than pages).
func parseSitemap(body []byte) (locs []string, index bool) {
	d := xml.NewDecoder(bytes.NewReader(body))
	d.Strict = false
	root := ""
	var loc *strings.Builder
	for {
		tok, err := d.Token()
		if err != nil {
			return locs, index
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if root == "" {
				root = t.Name.Local
				index = root == "sitemapindex"
			}
			if t.Name.Local == "loc" {
				loc = &strings.Builder{}
			}
		case xml.CharData:
			if loc != nil {
				loc.Write(t)
			}
		case xml.EndElement:
			if t.Name.Local == "loc" && loc != nil {
				if v := strings.TrimSpace(loc.String()); v != "" {
					locs = append(locs, v)
				}
				loc = nil
			}
		}
	}
}
