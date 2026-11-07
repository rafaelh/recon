// Package cloudstorage is pure knowledge of the three public object stores
// recon looks at (AWS S3, Google Cloud Storage and Azure Blob Storage): how a
// URL or host names a bucket, which names to guess for a company, and how a
// bucket is keyed and shown. It does no I/O.
package cloudstorage

import (
	"iter"
	"net/url"
	"regexp"
	"strings"

	"github.com/rafaelh/recon/internal/dnsname"
)

// Providers.
const (
	S3    = "s3"
	GCS   = "gcs"
	Azure = "azure"
)

// Providers are the three stores, in the order names are guessed for them.
var Providers = []string{S3, GCS, Azure}

// Ref is what a URL or host says about a bucket. Name is the bucket (S3, GCS)
// or the storage account (Azure); Container is set for Azure only.
type Ref struct {
	Provider, Name, Container, Object string
}

// Reference is a Ref found somewhere in scope. Via says how: "cname" (an in-scope
// name's CNAME chain), "link" (an <a> or <area> to it) or "asset" (anything a
// browser would load). From is the referencing hostname or page.
type Reference struct {
	Ref
	Via, From string
}

// AzureContainers are the containers tried on every existing Azure account.
var AzureContainers = []string{"$web", "$root", "public", "assets", "static", "media", "images", "files", "uploads", "backup", "data", "logs"}

// guessWords are combined with a base name, in this order.
var guessWords = []string{"backup", "backups", "dev", "prod", "staging", "test", "assets", "static", "media", "files", "uploads", "public", "private", "data", "logs", "www", "web", "cdn", "images", "docs"}

var (
	// <bucket>.s3.amazonaws.com, .s3.<region>., .s3-<region>., .s3-website-<region>., .s3-website.<region>.
	s3VirtualHost = regexp.MustCompile(`^(.+)\.s3(?:[.-](?:website[.-]|dualstack\.)?[a-z0-9-]+)?\.amazonaws\.com(?:\.cn)?$`)
	// s3.amazonaws.com, s3.<region>.amazonaws.com, s3-<region>.amazonaws.com (path-style)
	s3PathHost = regexp.MustCompile(`^s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:\.cn)?$`)
	// <acct>.blob.core.windows.net, <acct>.web.core.windows.net and the zoned
	// static-website form <acct>.z<n>.web.core.windows.net
	azureHost  = regexp.MustCompile(`^([a-z0-9]{3,24})\.(?:z[0-9]+\.)?(blob|web)\.core\.windows\.net$`)
	gcsVirtual = regexp.MustCompile(`^(.+)\.storage\.googleapis\.com$`)
)

// ParseRef recognises a storage reference in a URL or a bare host.
func ParseRef(s string) (Ref, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Ref{}, false
	}
	raw := s
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return Ref{}, false
	}
	host := strings.ToLower(u.Hostname())
	path := strings.TrimPrefix(u.EscapedPath(), "/")
	if p, err := url.PathUnescape(path); err == nil {
		path = p
	}
	first, rest, _ := strings.Cut(path, "/")

	switch {
	case host == "storage.googleapis.com" || host == "storage.cloud.google.com":
		if first == "" {
			return Ref{}, false
		}
		return Ref{Provider: GCS, Name: first, Object: rest}, true
	case gcsVirtual.MatchString(host):
		name := gcsVirtual.FindStringSubmatch(host)[1]
		if name == "c" { // c.storage.googleapis.com is the CNAME form, not a bucket named c
			return Ref{}, false
		}
		return Ref{Provider: GCS, Name: name, Object: path}, true
	case s3PathHost.MatchString(host):
		if first == "" {
			return Ref{}, false
		}
		return Ref{Provider: S3, Name: first, Object: rest}, true
	case s3VirtualHost.MatchString(host):
		return Ref{Provider: S3, Name: s3VirtualHost.FindStringSubmatch(host)[1], Object: path}, true
	case azureHost.MatchString(host):
		m := azureHost.FindStringSubmatch(host)
		if m[2] == "web" {
			return Ref{Provider: Azure, Name: m[1], Container: "$web", Object: path}, true
		}
		return Ref{Provider: Azure, Name: m[1], Container: first, Object: rest}, true
	}
	return Ref{}, false
}

// ParseCNAME is ParseRef for a CNAME: alias is the name that points at target.
// The c.storage.googleapis.com target names no bucket; the bucket is the alias.
func ParseCNAME(alias, target string) (Ref, bool) {
	if strings.EqualFold(strings.TrimSuffix(target, "."), "c.storage.googleapis.com") {
		return Ref{Provider: GCS, Name: dnsname.Normalise(alias)}, true
	}
	return ParseRef(strings.TrimSuffix(target, "."))
}

// RootBases are the names guessed from a root: its registrable label, the root
// with dots as dashes, and the root itself.
func RootBases(root string) []string {
	root = dnsname.Normalise(root)
	var label string
	if reg, ok := dnsname.ETLDPlusOne(root); ok {
		label, _, _ = strings.Cut(reg, ".")
	} else {
		label, _, _ = strings.Cut(root, ".")
	}
	return dedupe([]string{label, strings.ReplaceAll(root, ".", "-"), root})
}

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// OrgBases are the names guessed from an organisation name: its words joined
// and joined with dashes.
func OrgBases(org string) []string {
	words := strings.Fields(nonAlnum.ReplaceAllString(strings.ToLower(org), " "))
	if len(words) == 0 {
		return nil
	}
	return dedupe([]string{strings.Join(words, ""), strings.Join(words, "-")})
}

func dedupe(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// Guess returns the names to try for the bases, in priority order, at most cap
// of them: each base, then base-<word> for every base, then <word>-base. The order
// is stable, so raising the cap only adds names.
func Guess(bases []string, cap int) []string {
	var all []string
	all = append(all, bases...)
	for _, b := range bases {
		for _, w := range guessWords {
			all = append(all, b+"-"+w)
		}
	}
	for _, b := range bases {
		for _, w := range guessWords {
			all = append(all, w+"-"+b)
		}
	}
	all = dedupe(all)
	if cap >= 0 && len(all) > cap {
		all = all[:cap]
	}
	return all
}

// InputGuesses yields the guessed buckets of each root and then each
// organisation, with the input that generates it.
func InputGuesses(roots, orgs []string, cap int) iter.Seq2[string, Ref] {
	return func(yield func(string, Ref) bool) {
		for _, set := range []struct {
			inputs []string
			bases  func(string) []string
		}{{roots, RootBases}, {orgs, OrgBases}} {
			for _, in := range set.inputs {
				for _, g := range Guesses(set.bases(in), cap) {
					if !yield(in, g) {
						return
					}
				}
			}
		}
	}
}

// Guesses are Guess's names turned into every provider's form, each name in
// Providers order, skipping the ones a provider cannot use. Name is the bucket
// (S3, GCS) or the account (Azure).
func Guesses(bases []string, cap int) []Ref {
	var out []Ref
	for _, n := range Guess(bases, cap) {
		for _, p := range Providers {
			if pn, ok := ProviderName(p, n); ok {
				out = append(out, Ref{Provider: p, Name: pn})
			}
		}
	}
	return out
}

var (
	bucketName   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	accountName  = regexp.MustCompile(`^[a-z0-9]{3,24}$`)
	accountStrip = strings.NewReplacer("-", "", ".", "")
)

// ProviderName turns a guessed name into one the provider accepts, or reports
// that it cannot be used. S3 and GCS names are 3 to 63 characters of
// [a-z0-9.-] that start and end with a letter or digit and have no "..";
// an Azure account name drops "-" and "." and is 3 to 24 letters and digits.
func ProviderName(provider, name string) (string, bool) {
	switch provider {
	case S3, GCS:
		if !bucketName.MatchString(name) || strings.Contains(name, "..") || strings.Contains(name, ".-") || strings.Contains(name, "-.") {
			return "", false
		}
		return name, true
	case Azure:
		n := accountStrip.Replace(name)
		if !accountName.MatchString(n) {
			return "", false
		}
		return n, true
	}
	return "", false
}

// Key is the storage record key of a bucket (S3, GCS) or of an Azure container.
func Key(provider, name, container string) string {
	if container != "" {
		return provider + "|" + name + "/" + container
	}
	return provider + "|" + name
}

// AccountKey names an Azure account among buckets and containers: the storage
// check of the account, and its entry in the set of missing resources.
func AccountKey(name string) string { return "azure-account|" + name }

// URL is the path-style URL a bucket or container is listed at.
func URL(provider, name, container string) string {
	switch provider {
	case GCS:
		return "https://storage.googleapis.com/" + name
	case Azure:
		u := "https://" + name + ".blob.core.windows.net"
		if container != "" {
			u += "/" + container
		}
		return u
	}
	return "https://s3.amazonaws.com/" + name
}

// PublicState is "yes" if an anonymous HEAD of any known object of the bucket
// succeeded, "no" if every known object refused it, and "unknown" with no
// known object. results holds one entry per checked object.
func PublicState(results []bool) string {
	if len(results) == 0 {
		return "unknown"
	}
	for _, ok := range results {
		if ok {
			return "yes"
		}
	}
	return "no"
}
