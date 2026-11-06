package risk

import (
	"context"
	"encoding/xml"
	"fmt"
	"iter"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/rafaelh/recon/internal/cloudstorage"
	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/run"
)

// Storage checks cloud storage (Spec 5 D8 to D10): buckets and accounts that
// in-scope names and pages reference, and names guessed from the roots and
// organisations. It lists a bucket anonymously, HEADs one object, and never
// fetches object contents. Everything it asks is a public provider endpoint,
// so it runs under --passive.
type Storage struct{}

// NewStorage returns the storage stage.
func NewStorage() *Storage { return &Storage{} }

func (*Storage) Name() string         { return "storage" }
func (*Storage) Contact() run.Contact { return run.ThirdParty }
func (*Storage) Sources() []string {
	return []string{"s3.amazonaws.com", "s3.*.amazonaws.com", "storage.googleapis.com", "*.blob.core.windows.net"}
}
func (*Storage) Configured(run.Env) (bool, string) { return true, "" }

// CandidateExemptSources: a redirect from an in-scope page may have recorded any
// of the provider endpoints (an Azure account host, or the path-style
// s3.amazonaws.com, s3.<region>.amazonaws.com and storage.googleapis.com) as
// a candidate hostname. They are provider endpoints, not target systems.
func (s *Storage) CandidateExemptSources() []string { return s.Sources() }

type storageInput struct {
	kind                              string // bucket, account, container or object
	provider, name, container, object string
	region                            string // S3: where the bucket's listing said it lives
}

var (
	safeName      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{1,254}$`)
	safeContainer = regexp.MustCompile(`^[A-Za-z0-9$][A-Za-z0-9_-]{0,62}$`)
	regionRE      = regexp.MustCompile(`^[a-z0-9-]+$`)
)

// Checks yields the checks of this pass; a later pass picks up what these
// found (an existing Azure account's containers, a listed bucket's first key).
func (*Storage) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		emit := func(key string, in storageInput) bool { return yield(run.Check{Key: key, Input: in}, nil) }
		bucket := func(provider, name string) bool {
			if !safeName.MatchString(name) {
				return true
			}
			if provider == cloudstorage.Azure {
				return emit(cloudstorage.AccountKey(name), storageInput{kind: "account", provider: provider, name: name})
			}
			return emit(cloudstorage.Key(provider, name, ""), storageInput{kind: "bucket", provider: provider, name: name})
		}

		refs := v.StorageRefs()
		for _, r := range refs {
			if !bucket(r.Provider, r.Name) {
				return
			}
		}
		capN := v.Settings().Storage.MaxNames
		guess := func(bases []string) bool {
			for _, g := range cloudstorage.Guesses(bases, capN) {
				if !bucket(g.Provider, g.Name) {
					return false
				}
			}
			return true
		}
		in := v.Inputs()
		for _, root := range in.Roots {
			if !guess(cloudstorage.RootBases(root)) {
				return
			}
		}
		for _, org := range in.Orgs {
			if !guess(cloudstorage.OrgBases(org)) {
				return
			}
		}

		// Containers of Azure accounts known to exist: the fixed list, and every one a reference names.
		var accounts []string
		for _, rec := range v.Records("storage_account") {
			if ok, _ := rec.Attrs["exists"].(bool); ok {
				accounts = append(accounts, rec.Key)
			}
		}
		for _, acct := range accounts {
			containers := slices.Clone(cloudstorage.AzureContainers)
			for _, r := range refs {
				if r.Provider == cloudstorage.Azure && r.Name == acct && r.Container != "" && !slices.Contains(containers, r.Container) {
					containers = append(containers, r.Container)
				}
			}
			for _, c := range containers {
				if safeContainer.MatchString(c) && !emit("azure|"+acct+"/"+c, storageInput{kind: "container", provider: cloudstorage.Azure, name: acct, container: c}) {
					return
				}
			}
		}

		// One HEAD for the first listed key and for every referenced object of a bucket that exists.
		existing := map[string]storageInput{} // object inputs without the object
		objs := map[string]storageInput{}
		for _, rec := range v.Records("storage") {
			if ok, _ := rec.Attrs["exists"].(bool); !ok {
				continue
			}
			b := storageInput{kind: "object", provider: rec.Str("provider"), name: rec.Str("name"), container: rec.Str("container"), region: rec.Str("region")}
			existing[rec.Key] = b
			if keys, _ := rec.Attrs["first_keys"].([]any); len(keys) > 0 {
				if k, _ := keys[0].(string); k != "" {
					b.object = k
					objs[rec.Key+"/"+k] = b
				}
			}
		}
		for _, r := range refs {
			key := cloudstorage.Key(r.Provider, r.Name, r.Container)
			if b, ok := existing[key]; ok && r.Object != "" {
				b.object = r.Object
				objs[key+"/"+r.Object] = b
			}
		}
		for _, key := range slices.Sorted(maps.Keys(objs)) {
			if !emit(strings.Replace(key, "|", "-obj|", 1), objs[key]) {
				return
			}
		}
	}
}

// Run performs one check.
func (s *Storage) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	in := c.Input.(storageInput)
	var obs []run.Observation
	var err error
	switch in.kind {
	case "account":
		obs, err = account(ctx, e, in)
	case "object":
		obs, err = object(ctx, e, in)
	default:
		obs, err = list(ctx, e, in)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.Key, err)
	}
	return obs, nil
}

// account looks the account's host up in DNS: a name that exists is a storage account.
func account(ctx context.Context, e egress.Clients, in storageInput) ([]run.Observation, error) {
	res, err := e.DNS.Query(ctx, in.name+".blob.core.windows.net", egress.TypeA)
	if err != nil {
		return nil, err
	}
	var exists bool
	switch res.RCode {
	case egress.RCodeSuccess:
		exists = len(res.Answers) > 0 || len(res.CNAMEs) > 0
	case egress.RCodeNXDomain:
	default:
		return nil, fmt.Errorf("DNS rcode %d", res.RCode)
	}
	return []run.Observation{{Kind: "storage_account", Key: in.name, Attrs: map[string]any{"exists": exists}}}, nil
}

// escapePath escapes each segment of an object key.
func escapePath(parts ...string) string {
	var segs []string
	for _, p := range parts {
		for _, s := range strings.Split(p, "/") {
			segs = append(segs, url.PathEscape(s))
		}
	}
	return "/" + strings.Join(segs, "/")
}

// listURL is where a bucket or container is listed anonymously.
func listURL(in storageInput, region string) string {
	switch in.provider {
	case cloudstorage.GCS:
		return "https://storage.googleapis.com" + escapePath(in.name) + "?max-keys=1000"
	case cloudstorage.Azure:
		return "https://" + in.name + ".blob.core.windows.net" + escapePath(in.container) + "?restype=container&comp=list&maxresults=1000"
	}
	return "https://" + s3Host(region) + escapePath(in.name) + "?list-type=2&max-keys=1000"
}

func s3Host(region string) string {
	if region == "" {
		return "s3.amazonaws.com"
	}
	return "s3." + region + ".amazonaws.com"
}

// objectURL is the URL of an object, for a HEAD.
func objectURL(in storageInput, region string) string {
	switch in.provider {
	case cloudstorage.GCS:
		return "https://storage.googleapis.com" + escapePath(in.name, in.object)
	case cloudstorage.Azure:
		return "https://" + in.name + ".blob.core.windows.net" + escapePath(in.container, in.object)
	}
	return "https://" + s3Host(region) + escapePath(in.name, in.object)
}

// request sends one request and, for S3, follows a 301 to the bucket's region once.
func request(ctx context.Context, e egress.Clients, method string, in storageInput, build func(region string) string) (egress.ThirdPartyResponse, string, error) {
	region := in.region
	resp, err := e.ThirdParty.Do(ctx, egress.ThirdPartyRequest{Method: method, URL: build(region)})
	if err != nil {
		return resp, region, err
	}
	if in.provider == cloudstorage.S3 && (resp.Status == 301 || resp.Status == 307) {
		r := redirectRegion(resp)
		if r == region || !regionRE.MatchString(r) {
			return resp, region, fmt.Errorf("redirect to an unusable region %q", r)
		}
		region = r
		resp, err = e.ThirdParty.Do(ctx, egress.ThirdPartyRequest{Method: method, URL: build(region)})
	}
	return resp, region, err
}

// s3RegionHost captures the region of an S3 endpoint host: s3.<region>,
// s3-<region> or s3.dualstack.<region>, optionally after the bucket.
var s3RegionHost = regexp.MustCompile(`(?:^|\.)s3[.-](?:dualstack\.)?([a-z]{2}(?:-[a-z]+)+-[0-9]+)\.amazonaws\.com$`)

// redirectRegion is the region an S3 redirect points at: the
// x-amz-bucket-region header, else the host of the Location header (a 307 for
// a new bucket may carry only that), else the <Endpoint> of the error body.
func redirectRegion(resp egress.ThirdPartyResponse) string {
	if vals := resp.Header["X-Amz-Bucket-Region"]; len(vals) > 0 && vals[0] != "" {
		return vals[0]
	}
	var hosts []string
	if vals := resp.Header["Location"]; len(vals) > 0 {
		if u, err := url.Parse(vals[0]); err == nil {
			hosts = append(hosts, u.Hostname())
		}
	}
	var body struct {
		Endpoint string `xml:"Endpoint"`
	}
	if xml.Unmarshal(resp.Body, &body) == nil && body.Endpoint != "" {
		hosts = append(hosts, body.Endpoint)
	}
	for _, h := range hosts {
		if m := s3RegionHost.FindStringSubmatch(strings.ToLower(h)); m != nil {
			return m[1]
		}
	}
	return ""
}

type listing struct {
	Truncated  string   `xml:"IsTruncated"`
	Keys       []string `xml:"Contents>Key"`
	Blobs      []string `xml:"Blobs>Blob>Name"`
	NextMarker string   `xml:"NextMarker"`
}

// list lists a bucket or container anonymously and records whether it exists,
// is listable, how many objects it has and its first keys.
func list(ctx context.Context, e egress.Clients, in storageInput) ([]run.Observation, error) {
	resp, region, err := request(ctx, e, "GET", in, func(r string) string { return listURL(in, r) })
	if err != nil {
		return nil, err
	}
	if resp.Truncated {
		return nil, fmt.Errorf("listing larger than the 10 MiB limit")
	}
	attrs := map[string]any{"provider": in.provider, "name": in.name, "container": in.container}
	body := string(resp.Body)
	switch {
	case resp.Status == 200:
		var l listing
		if err := xml.Unmarshal(resp.Body, &l); err != nil {
			return nil, fmt.Errorf("unreadable listing: %w", err)
		}
		keys := append(l.Keys, l.Blobs...)
		count := fmt.Sprint(len(keys))
		if strings.EqualFold(l.Truncated, "true") || l.NextMarker != "" {
			count += "+"
		}
		first := make([]any, 0, 5)
		for _, k := range keys[:min(5, len(keys))] {
			first = append(first, k)
		}
		attrs["exists"], attrs["listable"], attrs["object_count"], attrs["first_keys"] = true, true, count, first
	case resp.Status == 404 && (strings.Contains(body, "NoSuchBucket") || strings.Contains(body, "ContainerNotFound")):
		attrs["exists"] = false
	case resp.Status == 401 || resp.Status == 403:
		attrs["exists"], attrs["listable"] = true, false
	case in.provider == cloudstorage.Azure && (resp.Status == 404 && strings.Contains(body, "ResourceNotFound") ||
		resp.Status == 409 && strings.Contains(body, "PublicAccessNotPermitted")):
		// Azure answers an anonymous request this way for a private container and
		// for a missing one alike (and 409 for every container once the account
		// disallows public access), so whether it exists is unknown: it is not
		// listable, and is neither reported as existing nor as claimable.
		attrs["listable"] = false
	default:
		return nil, fmt.Errorf("HTTP %d", resp.Status)
	}
	if region != "" {
		attrs["region"] = region
	}
	return []run.Observation{{Kind: "storage", Key: cloudstorage.Key(in.provider, in.name, in.container), Attrs: attrs}}, nil
}

// object sends one anonymous HEAD for an object: it is public if that succeeds.
func object(ctx context.Context, e egress.Clients, in storageInput) ([]run.Observation, error) {
	resp, _, err := request(ctx, e, "HEAD", in, func(r string) string { return objectURL(in, r) })
	if err != nil {
		return nil, err
	}
	var public bool
	switch {
	case resp.Status == 200:
		public = true
	case resp.Status == 401 || resp.Status == 403 || resp.Status == 404:
	default:
		return nil, fmt.Errorf("HTTP %d", resp.Status)
	}
	bucket := cloudstorage.Key(in.provider, in.name, in.container)
	return []run.Observation{{Kind: "storage_object", Key: bucket + "/" + in.object, Attrs: map[string]any{
		"bucket": bucket, "provider": in.provider, "name": in.name, "container": in.container, "object": in.object,
		"public": public, "url": objectURL(in, in.region),
	}}}, nil
}
