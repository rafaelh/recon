package findings

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/rafaelh/recon/internal/cloudstorage"
	"github.com/rafaelh/recon/internal/output"
	"github.com/rafaelh/recon/internal/scope"
)

// References are the buckets and containers something in scope points at: the
// CNAME chain of an in-scope, non-wildcard-only hostname, and the storage_ref
// observations of pages whose host is in scope. Sorted and without duplicates.
// A bucket is attributed iff it has a reference.
func References(in Input) []cloudstorage.Reference {
	return newDeriver(in).references()
}

// references computes References once per deriver.
func (d *deriver) references() []cloudstorage.Reference {
	if d.refs != nil {
		return d.refs
	}
	out := []cloudstorage.Reference{}
	wildcardOnly := d.in.Inv.WildcardOnly()
	for _, r := range d.current("resolution") {
		if r.Str("type") != "CNAME" {
			continue
		}
		name := r.Str("name")
		if wildcardOnly[name] || d.in.Scope.ClassifyHost(name).Class != scope.InScope {
			continue
		}
		if ref, ok := cloudstorage.ParseCNAME(name, r.Str("value")); ok {
			out = append(out, cloudstorage.Reference{Ref: ref, Via: "cname", From: name})
		}
	}
	for _, r := range d.current("storage_ref") {
		if !d.in.Scope.WebHostInScope(r.Str("page_host")) {
			continue
		}
		out = append(out, cloudstorage.Reference{
			Ref: cloudstorage.Ref{Provider: r.Str("provider"), Name: r.Str("name"), Container: r.Str("container"), Object: r.Str("object")},
			Via: r.Str("via"), From: r.Str("page"),
		})
	}
	slices.SortFunc(out, refCompare)
	d.refs = slices.Compact(out)
	return d.refs
}

func refCompare(a, b cloudstorage.Reference) int {
	return cmp.Or(cmp.Compare(a.Provider, b.Provider), cmp.Compare(a.Name, b.Name), cmp.Compare(a.Container, b.Container),
		cmp.Compare(a.Object, b.Object), cmp.Compare(a.Via, b.Via), cmp.Compare(a.From, b.From))
}

// Attribution maps each storage record key to its attribution, public state
// and, for an unattributed bucket, the severity it is listed with.
func Attribution(in Input) map[string]output.StorageAttr { return newDeriver(in).attribution() }

func (d *deriver) attribution() map[string]output.StorageAttr {
	attributed, guessed, public := attributedSet(d.references()), d.guessed(), d.publicStates()
	out := map[string]output.StorageAttr{}
	for _, r := range d.in.Records["storage"] {
		k := bucketKey(r.Str("provider"), r.Str("name"))
		a := output.StorageAttr{Attributed: attributed[k], GeneratedFrom: guessed[k], Public: cloudstorage.PublicState(public[r.Key])}
		if typ := storageType(flag(r, "listable"), a.Public, a.Attributed); typ != "" && !a.Attributed {
			a.Severity = Severity(StorageUnattributed, typ)
		}
		out[r.Key] = a
	}
	return out
}

// bucketKey is the attribution key of a bucket: provider and bucket (the account
// for Azure, so every container of a referenced account is attributed).
func bucketKey(provider, name string) string { return cloudstorage.Key(provider, name, "") }

// attributedSet is the set of referenced buckets, by bucketKey.
func attributedSet(refs []cloudstorage.Reference) map[string]bool {
	set := map[string]bool{}
	for _, r := range refs {
		set[bucketKey(r.Provider, r.Name)] = true
	}
	return set
}

// guessed lists, per guessed bucketKey, the inputs that generate it.
func (d *deriver) guessed() map[string][]string {
	if d.guesses != nil {
		return d.guesses
	}
	out := map[string][]string{}
	capN := d.in.Settings.Storage.MaxNames
	add := func(input string, bases []string) {
		for _, g := range cloudstorage.Guesses(bases, capN) {
			k := bucketKey(g.Provider, g.Name)
			if !slices.Contains(out[k], input) {
				out[k] = append(out[k], input)
			}
		}
	}
	for _, root := range d.in.Roots {
		add(root, cloudstorage.RootBases(root))
	}
	for _, org := range d.in.Orgs {
		add(org, cloudstorage.OrgBases(org))
	}
	d.guesses = out
	return out
}

// publicStates maps a storage record key to the results of the anonymous HEADs
// of its known objects (the storage_object records), for cloudstorage.PublicState.
func (d *deriver) publicStates() map[string][]bool {
	if d.public != nil {
		return d.public
	}
	d.public = map[string][]bool{}
	for _, r := range d.current("storage_object") {
		b := r.Str("bucket")
		d.public[b] = append(d.public[b], flag(r, "public"))
	}
	return d.public
}

// storageType is the finding type of an existing bucket, or "" when it is not a
// finding (a private guessed bucket).
func storageType(listable bool, public string, attributed bool) string {
	switch {
	case listable:
		return "listable"
	case public == "yes":
		return "public"
	case attributed:
		return "exists"
	}
	return ""
}

// storage derives the attributed and unattributed storage findings (the
// takeovers of missing buckets are takeovers()).
func (d *deriver) storage() []Finding {
	refs := d.references()
	attributed := attributedSet(refs)
	public := d.publicStates()
	referencedBy := map[string][]string{}
	for _, r := range refs {
		k := bucketKey(r.Provider, r.Name)
		if !slices.Contains(referencedBy[k], r.From) {
			referencedBy[k] = append(referencedBy[k], r.From)
		}
	}
	var out []Finding
	for _, r := range d.current("storage") {
		if !flag(r, "exists") {
			continue
		}
		provider, name, container := r.Str("provider"), r.Str("name"), r.Str("container")
		listable := flag(r, "listable")
		pub := cloudstorage.PublicState(public[r.Key])
		attr := attributed[bucketKey(provider, name)]
		typ := storageType(listable, pub, attr)
		if typ == "" {
			continue
		}
		category := Storage
		if !attr {
			category = StorageUnattributed
		}
		url := cloudstorage.URL(provider, name, container)
		by := referencedBy[bucketKey(provider, name)]
		if len(by) > 5 {
			by = by[:5]
		}
		keys := strs(r, "first_keys")
		out = append(out, newFinding(category, typ, Severity(category, typ), url,
			fmt.Sprintf("%s bucket %s is %s", provider, url, typ),
			map[string]any{
				"provider": provider, "name": name, "url": url, "exists": "true", "public": pub, "listable": fmt.Sprint(listable),
				"object_count": r.Str("object_count"), "first_keys": strings.Join(keys, ";"), "referenced_by": strings.Join(by, ";"),
			}))
	}
	return out
}
