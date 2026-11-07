// Package findings derives the severity-ranked list of obvious exposures from
// the evidence the stages stored (Spec 5). Derivation is pure: stages store only
// evidence, and findings are computed on read from it, the Scope, the
// Inventory, the settings and today's date, so a finding that is no longer true
// (a port excluded later, a certificate renewed, the clock moving on) is simply
// not derived any more and none can go stale (Spec 1 D16).
package findings

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/rafaelh/recon/internal/cloudstorage"
	"github.com/rafaelh/recon/internal/config"
	"github.com/rafaelh/recon/internal/inventory"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/scope"
	"github.com/rafaelh/recon/internal/store"
)

// Input is everything Derive reads. Records returns the records of a kind
// (derivation uses only the current ones), and is called only for the kinds
// derivation needs. Roots and Orgs are the engagement's stored scope inputs.
type Input struct {
	Scope       *scope.Scope
	Inv         *inventory.Inventory
	Settings    config.Settings
	Today       string // YYYY-MM-DD
	Records     func(kinds.Named) []store.Record
	Roots, Orgs []string
}

// Finding is one derived exposure. Attrs holds every attribute of its stored
// record: category, type, severity, target and detail, plus the columns of the
// category's file.
type Finding struct {
	Category, Type, Severity, Target, Detail string
	Attrs                                    map[string]any
}

func newFinding(category, typ, severity, target, detail string, attrs map[string]any) Finding {
	a := map[string]any{"category": category, "type": typ, "severity": severity, "target": target, "detail": detail}
	for k, v := range attrs {
		a[k] = v
	}
	return Finding{Category: category, Type: typ, Severity: severity, Target: target, Detail: detail, Attrs: a}
}

// Derive computes every finding, sorted by key.
func Derive(in Input) []Finding { return newDeriver(in).findings() }

// DeriveAll computes the findings and the storage Attribution together, so the
// references, guesses and public states they share are computed once.
func DeriveAll(in Input) ([]Finding, map[string]StorageAttr) {
	d := newDeriver(in)
	return d.findings(), d.attribution()
}

func (d *deriver) findings() []Finding {
	var out []Finding
	out = append(out, d.takeovers()...)
	out = append(out, d.storage()...)
	out = append(out, d.sensitivePaths()...)
	out = append(out, d.email()...)
	out = append(out, d.ports()...)
	out = append(out, d.certificates()...)
	slices.SortStableFunc(out, func(a, b Finding) int { return strings.Compare(a.Key(), b.Key()) })
	return slices.CompactFunc(out, func(a, b Finding) bool { return a.Key() == b.Key() })
}

type deriver struct {
	in   Input
	vis  *kinds.Visibility
	refs []cloudstorage.Reference // see references
	svcs map[string]store.Record  // see services

	public map[string][]bool // see publicStates
}

func newDeriver(in Input) *deriver {
	return &deriver{in: in, vis: kinds.NewVisibility(in.Scope, in.Inv)}
}

// current is the current records of a kind.
func (d *deriver) current(k kinds.Named) []store.Record {
	var out []store.Record
	for _, r := range d.in.Records(k) {
		if r.Current {
			out = append(out, r)
		}
	}
	return out
}

// services indexes the current, visible web services by key.
func (d *deriver) services() map[string]store.Record {
	if d.svcs != nil {
		return d.svcs
	}
	d.svcs = map[string]store.Record{}
	for _, r := range d.current(kinds.WebService) {
		if d.vis.Shown(kinds.WebService, r) {
			d.svcs[r.Key] = r
		}
	}
	return d.svcs
}

// isTrue reads an attribute that may be unknown: only a known true is true.
func isTrue(b *bool) bool { return b != nil && *b }

func (d *deriver) sensitivePaths() []Finding {
	svcs := d.services()
	severity := map[string]string{} // path|hash -> the entry's severity
	for _, e := range d.in.Settings.SensitivePathEntries {
		if k := e.Path + "|" + e.Hash(); severity[k] == "" {
			severity[k] = e.Severity
		}
	}
	var out []Finding
	for _, r := range d.current(kinds.SensitiveHit) {
		a := kinds.SensitiveHit.Attrs(r)
		if _, ok := svcs[a.Service]; !ok {
			continue
		}
		sev := cmp.Or(severity[a.Path+"|"+a.Hash], Medium)
		out = append(out, newFinding(SensitivePaths, a.Path, sev, a.URL,
			fmt.Sprintf("%s answered %d with %q", a.URL, a.Status, a.Signature),
			map[string]any{"url": a.URL, "path": a.Path, "status": a.Status, "size": a.Size, "signature": a.Signature}))
	}
	return out
}

func (d *deriver) email() []Finding {
	var out []Finding
	for _, r := range d.current(kinds.EmailPosture) {
		if !d.vis.Shown(kinds.EmailPosture, r) {
			continue
		}
		root := r.Key
		add := func(typ, detail string) {
			out = append(out, newFinding(Email, typ, Severity(Email, typ), root, detail, map[string]any{"root": root}))
		}
		a := kinds.EmailPosture.Attrs(r)
		spf := a.SPF
		invalid := a.SPFError != "" || a.SPFRecords > 1
		switch {
		case invalid:
			add("spf-invalid", "SPF is invalid: "+a.SPFError)
		case spf == "":
			add("spf-missing", "no SPF record")
		default:
			if n := a.SPFLookups; n > 10 {
				add("spf-lookups", fmt.Sprintf("SPF needs %d DNS lookups (the limit is 10)", n))
			}
		}
		// The record's own "all" is reported even when an include made it invalid:
		// a +all says so whatever the rest of the record does.
		switch a.SPFAll {
		case "+all":
			add("spf-all-plus", "SPF allows anyone to send: "+spf)
		case "?all":
			add("spf-all-neutral", "SPF ends in ?all: "+spf)
		}
		if a.DMARC == "" {
			add("dmarc-missing", "no DMARC record")
		} else if a.DMARCPolicy == "none" {
			add("dmarc-none", "the applicable DMARC policy is none: "+a.DMARC)
		}
		if a.MX == "" && !strings.EqualFold(strings.Join(strings.Fields(spf), " "), "v=spf1 -all") {
			add("no-mx-spf", "no MX record, and the domain does not say it sends no mail (v=spf1 -all)")
		}
	}
	return out
}

func (d *deriver) ports() []Finding {
	risky := map[int]bool{}
	for _, p := range d.in.Settings.RiskyPorts {
		risky[p] = true
	}
	var hostnames map[netip.Addr][]string
	var out []Finding
	for _, r := range d.current(kinds.OpenPort) {
		ap, err := netip.ParseAddrPort(r.Key)
		if err != nil || !risky[int(ap.Port())] || !d.vis.Shown(kinds.OpenPort, r) {
			continue
		}
		if hostnames == nil {
			hostnames = d.in.Inv.HostnamesByIP(d.in.Scope)
		}
		addr := netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		out = append(out, newFinding(Ports, "risky-port", Severity(Ports, "risky-port"), addr.String(),
			fmt.Sprintf("port %d is open on %s", ap.Port(), addr.Addr()),
			map[string]any{"ip": addr.Addr().String(), "port": int(ap.Port()), "banner": kinds.OpenPort.Attrs(r).Banner,
				"hostnames": strings.Join(hostnames[addr.Addr()], ";")}))
	}
	return out
}

func (d *deriver) certificates() []Finding {
	today, err := time.Parse(time.DateOnly, d.in.Today)
	if err != nil {
		return nil
	}
	horizon := today.AddDate(0, 0, d.in.Settings.CertExpiryDays).Format(time.DateOnly)
	var out []Finding
	for _, r := range d.current(kinds.WebService) {
		if !d.vis.Shown(kinds.WebService, r) {
			continue
		}
		a := kinds.WebService.Attrs(r)
		var types []string
		expiry := a.TLSExpiry
		switch {
		case expiry == "":
		case expiry < d.in.Today:
			types = append(types, "expired")
		case expiry < horizon:
			types = append(types, "expiring")
		}
		if isTrue(a.TLSSelfSigned) {
			types = append(types, "self-signed")
		}
		if len(types) == 0 {
			continue
		}
		typ := strings.Join(types, ";") // "expired", "expiring" sort before "self-signed"
		out = append(out, newFinding(Certificates, typ, Severity(Certificates, typ), r.Key,
			fmt.Sprintf("%s certificate (%s), expires %s", typ, a.TLSSubject, expiry),
			map[string]any{"url": r.Key, "tls_subject": a.TLSSubject, "tls_issuer": a.TLSIssuer, "tls_expiry": expiry}))
	}
	return out
}
