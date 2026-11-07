package web

import (
	"bytes"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
)

const maxTitleRunes = 200

// page is a parsed text/html body.
type page struct{ doc *html.Node }

func parsePage(body []byte) (page, bool) {
	doc, err := html.Parse(bytes.NewReader(body))
	return page{doc}, err == nil
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return strings.TrimSpace(a.Val)
		}
	}
	return ""
}

func text(n *html.Node, b *strings.Builder) {
	if n.Type == html.TextNode {
		b.WriteString(n.Data)
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		text(c, b)
	}
}

// title is the first <title>, with whitespace collapsed, invalid UTF-8
// replaced and at most 200 runes.
func (p page) title() string {
	var find func(*html.Node) (string, bool)
	find = func(n *html.Node) (string, bool) {
		if n.Type == html.ElementNode && n.Data == "title" {
			var b strings.Builder
			text(n, &b)
			return b.String(), true
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if t, ok := find(c); ok {
				return t, true
			}
		}
		return "", false
	}
	raw, _ := find(p.doc)
	t := strings.Join(strings.Fields(strings.ToValidUTF8(raw, "�")), " ")
	if utf8.RuneCountInString(t) > maxTitleRunes {
		t = string([]rune(t)[:maxTitleRunes])
	}
	return t
}

// links are the references in a page, in document order. follow holds the ones
// the crawl may fetch (a[href], area[href], iframe[src]); record holds the ones
// it only records (link[href], script[src], form[action]). base is the first
// base[href], which relative references resolve against, or "".
type links struct {
	follow, record []string
	base           string
	// refs is every URL-bearing attribute of an a, area, link, script, img,
	// iframe, source or form element, with its element, for storage references.
	refs []linkRef
}

// linkRef is a URL found in an element of a page.
type linkRef struct{ tag, url string }

func (p page) links() links {
	var l links
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			add := func(dst *[]string, key string) {
				if v := attr(n, key); v != "" {
					*dst = append(*dst, v)
				}
			}
			ref := func(key string) {
				if v := attr(n, key); v != "" {
					l.refs = append(l.refs, linkRef{tag: n.Data, url: v})
				}
			}
			switch n.Data {
			case "base":
				if l.base == "" {
					l.base = attr(n, "href")
				}
			case "a", "area":
				add(&l.follow, "href")
				ref("href")
			case "iframe":
				add(&l.follow, "src")
				ref("src")
			case "link":
				add(&l.record, "href")
				ref("href")
			case "script":
				add(&l.record, "src")
				ref("src")
			case "form":
				add(&l.record, "action")
				ref("action")
			case "img", "source":
				ref("src")
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(p.doc)
	return l
}
