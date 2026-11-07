package findings

import (
	"fmt"
	"slices"
	"strings"

	"github.com/rafaelh/recon/internal/cloudstorage"
	"github.com/rafaelh/recon/internal/kinds"
)

// evidence collects every kind of takeover evidence for one target (a hostname,
// or a bucket only a URL references), so it forms one finding.
type evidence struct {
	types   map[string]bool
	details []string
	attrs   map[string]any
}

type evidenceSet map[string]*evidence

func (s evidenceSet) add(target, typ, detail string, attrs map[string]any) {
	e := s[target]
	if e == nil {
		e = &evidence{types: map[string]bool{}, attrs: map[string]any{}}
		s[target] = e
	}
	e.types[typ] = true
	if !slices.Contains(e.details, detail) {
		e.details = append(e.details, detail)
	}
	for k, v := range attrs {
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		if _, set := e.attrs[k]; !set {
			e.attrs[k] = v
		}
	}
}

// takeovers derives the takeover candidates (B2): DNS evidence needs no query
// of its own, so it is derived under --passive too.
func (d *deriver) takeovers() []Finding {
	ev := evidenceSet{}
	d.dnsTakeovers(ev)
	d.httpTakeovers(ev)
	d.missingStorage(ev)
	var out []Finding
	for target, e := range ev {
		var types []string
		for t := range e.types {
			types = append(types, t)
		}
		slices.Sort(types)
		typ := strings.Join(types, ";")
		out = append(out, newFinding(Takeover, typ, Severity(Takeover, typ), target, strings.Join(e.details, "; "), e.attrs))
	}
	return out
}

// dnsTakeovers: a provider host that does not resolve (NXDOMAIN), matching a
// cname entry marked claimable.
func (d *deriver) dnsTakeovers(ev evidenceSet) {
	nx := map[string]bool{}
	for _, r := range d.current(kinds.Unresolved) {
		if kinds.Unresolved.Attrs(r).RCode == "NXDOMAIN" {
			nx[r.Key] = true
		}
	}
	for _, ph := range d.in.Inv.ProviderHosts(d.in.Scope) {
		if ph.Evidence != "cname" || ph.Resolves || !ph.Entry.NXDomain || !nx[ph.Hostname] {
			continue
		}
		ev.add(ph.Hostname, "dns-nxdomain",
			fmt.Sprintf("%s is an alias of %s (%s %s), which does not exist and can be claimed", ph.Hostname, ph.CNAME, ph.Provider, ph.Service),
			map[string]any{"service": ph.Service, "cname": ph.CNAME, "provider": ph.Provider})
	}
}

// httpTakeovers: a provider-hosted service answering with its unclaimed-resource page.
func (d *deriver) httpTakeovers(ev evidenceSet) {
	svcs := d.services()
	for _, r := range d.current(kinds.TakeoverHTTP) {
		a := kinds.TakeoverHTTP.Attrs(r)
		if _, ok := svcs[a.Service]; !ok {
			continue
		}
		ev.add(a.Host, "http-fingerprint",
			fmt.Sprintf("%s serves the page of an unclaimed %s resource (HTTP %d)", a.Service, a.ProviderService, a.Status),
			map[string]any{"service": a.ProviderService, "cname": a.CNAME, "provider": a.Provider})
	}
}

// missingStorage: an attributed bucket or account that does not exist. Evidence
// goes to each hostname whose CNAME names it; a bucket only URLs name is its own
// finding, low when every reference is a plain link.
func (d *deriver) missingStorage(ev evidenceSet) {
	refs := d.references()
	missing := d.missingResources()
	if len(missing) == 0 {
		return
	}
	type use struct {
		cname []string // hostnames whose CNAME names it
		asset bool     // a page loads it, rather than only linking to it
	}
	uses := map[string]*use{}
	for _, ref := range refs {
		key := refKey(ref)
		if !missing[key] {
			continue
		}
		u := uses[key]
		if u == nil {
			u = &use{}
			uses[key] = u
		}
		switch ref.Via {
		case "cname":
			u.cname = append(u.cname, ref.From)
		case "link":
		default:
			u.asset = true
		}
	}
	for key, u := range uses {
		label := strings.Replace(key, "|", ":", 1)
		detail := fmt.Sprintf("%s does not exist and can be claimed", label)
		if len(u.cname) > 0 {
			for _, h := range u.cname {
				ev.add(h, "storage-missing", fmt.Sprintf("%s is an alias of %s", h, detail), nil)
			}
			continue
		}
		typ := "storage-missing"
		if !u.asset {
			typ = "storage-missing-link"
		}
		ev.add(label, typ, detail, nil)
	}
}

// refKey is the storage key whose absence makes a reference claimable: the
// bucket, or for Azure the account. A missing container in an existing account
// is not: only the account's owner can create it.
func refKey(ref cloudstorage.Reference) string {
	if ref.Provider != cloudstorage.Azure {
		return cloudstorage.Key(ref.Provider, ref.Name, "")
	}
	return cloudstorage.AccountKey(ref.Name)
}

// missingResources are the storage keys known not to exist: a bucket, a
// container, or an Azure account (cloudstorage.AccountKey).
func (d *deriver) missingResources() map[string]bool {
	out := map[string]bool{}
	for _, r := range d.current(kinds.Storage) {
		if e := kinds.Storage.Attrs(r).Exists; e != nil && !*e { // known not to exist, not merely unknown
			out[r.Key] = true
		}
	}
	for _, r := range d.current(kinds.StorageAccount) {
		if e := kinds.StorageAccount.Attrs(r).Exists; e != nil && !*e { // known not to exist
			out[cloudstorage.AccountKey(r.Key)] = true
		}
	}
	return out
}
