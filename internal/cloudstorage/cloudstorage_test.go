package cloudstorage_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/recon/internal/cloudstorage"
)

// ParseRef recognises S3, GCS and Azure hosts and URLs.
func TestParseRef(t *testing.T) {
	cases := []struct {
		in   string
		want cloudstorage.Ref
	}{
		{"https://acme-assets.s3.amazonaws.com/img/a.png", cloudstorage.Ref{Provider: "s3", Name: "acme-assets", Object: "img/a.png"}},
		{"acme-assets.s3.amazonaws.com", cloudstorage.Ref{Provider: "s3", Name: "acme-assets"}},
		{"https://my.dotted.bucket.s3.amazonaws.com/x", cloudstorage.Ref{Provider: "s3", Name: "my.dotted.bucket", Object: "x"}},
		{"https://acme.s3.eu-west-1.amazonaws.com/k", cloudstorage.Ref{Provider: "s3", Name: "acme", Object: "k"}},
		{"https://acme.s3-eu-west-1.amazonaws.com/k", cloudstorage.Ref{Provider: "s3", Name: "acme", Object: "k"}},
		{"http://acme.s3-website-us-east-1.amazonaws.com/", cloudstorage.Ref{Provider: "s3", Name: "acme"}},
		{"http://acme.s3-website.eu-west-2.amazonaws.com/", cloudstorage.Ref{Provider: "s3", Name: "acme"}},
		{"https://s3.amazonaws.com/acme/dir/file.js", cloudstorage.Ref{Provider: "s3", Name: "acme", Object: "dir/file.js"}},
		{"https://s3.us-west-2.amazonaws.com/acme/f", cloudstorage.Ref{Provider: "s3", Name: "acme", Object: "f"}},
		{"https://s3-us-west-2.amazonaws.com/acme", cloudstorage.Ref{Provider: "s3", Name: "acme"}},
		{"https://storage.googleapis.com/acme-gcs/a/b.js", cloudstorage.Ref{Provider: "gcs", Name: "acme-gcs", Object: "a/b.js"}},
		{"https://acme-gcs.storage.googleapis.com/a.js", cloudstorage.Ref{Provider: "gcs", Name: "acme-gcs", Object: "a.js"}},
		{"https://storage.cloud.google.com/acme-gcs/a.js", cloudstorage.Ref{Provider: "gcs", Name: "acme-gcs", Object: "a.js"}},
		{"https://acmeacct.blob.core.windows.net/media/x/y.png", cloudstorage.Ref{Provider: "azure", Name: "acmeacct", Container: "media", Object: "x/y.png"}},
		{"acmeacct.blob.core.windows.net", cloudstorage.Ref{Provider: "azure", Name: "acmeacct"}},
		{"https://acmeacct.web.core.windows.net/index.html", cloudstorage.Ref{Provider: "azure", Name: "acmeacct", Container: "$web", Object: "index.html"}},
		{"https://acmeacct.z13.web.core.windows.net/index.html", cloudstorage.Ref{Provider: "azure", Name: "acmeacct", Container: "$web", Object: "index.html"}},
	}
	for _, c := range cases {
		got, ok := cloudstorage.ParseRef(c.in)
		if !ok || got != c.want {
			t.Errorf("ParseRef(%q) = %+v %v, want %+v", c.in, got, ok, c.want)
		}
	}
	for _, in := range []string{
		"https://example.com/s3.amazonaws.com", "https://s3.amazonaws.com/", "https://s3.amazonaws.com",
		"https://notamazonaws.com/b", "https://evil.s3.amazonaws.com.example.net/x", "https://storage.googleapis.com/",
		"https://blob.core.windows.net/x", "https://acct.blob.core.windows.net.evil.test/x", "", "not a url at all",
		"https://ec2-1-2-3-4.compute-1.amazonaws.com/", "https://abc.execute-api.us-east-1.amazonaws.com/",
	} {
		if got, ok := cloudstorage.ParseRef(in); ok {
			t.Errorf("ParseRef(%q) = %+v, want no reference", in, got)
		}
	}
}

// The c.storage.googleapis.com CNAME takes the bucket from the alias name.
func TestParseCNAME(t *testing.T) {
	got, ok := cloudstorage.ParseCNAME("assets.example.com", "c.storage.googleapis.com")
	if !ok || got != (cloudstorage.Ref{Provider: "gcs", Name: "assets.example.com"}) {
		t.Errorf("gcs alias = %+v %v", got, ok)
	}
	got, ok = cloudstorage.ParseCNAME("static.example.com", "acme-assets.s3.amazonaws.com")
	if !ok || got != (cloudstorage.Ref{Provider: "s3", Name: "acme-assets"}) {
		t.Errorf("s3 = %+v %v", got, ok)
	}
	if _, ok := cloudstorage.ParseCNAME("www.example.com", "d111.cloudfront.net"); ok {
		t.Error("cloudfront is not storage")
	}
}

// Bases, order, cap and provider rules.
func TestBases(t *testing.T) {
	if got := cloudstorage.RootBases("example.com"); !slices.Equal(got, []string{"example", "example-com", "example.com"}) {
		t.Errorf("RootBases = %v", got)
	}
	if got := cloudstorage.OrgBases("Acme Corp"); !slices.Equal(got, []string{"acmecorp", "acme-corp"}) {
		t.Errorf("OrgBases = %v", got)
	}
	if got := cloudstorage.OrgBases("Acme"); !slices.Equal(got, []string{"acme"}) {
		t.Errorf("single word org = %v", got)
	}
}

func TestGuessOrderAndCap(t *testing.T) {
	bases := cloudstorage.RootBases("example.com")
	all := cloudstorage.Guess(bases, 1000)
	if !slices.Equal(all[:3], bases) {
		t.Errorf("bases come first: %v", all[:3])
	}
	i1 := slices.Index(all, "example-backup")
	i2 := slices.Index(all, "backup-example")
	if i1 < 3 || i2 < 0 || i1 > i2 {
		t.Errorf("base-<word> precede <word>-base: %d %d", i1, i2)
	}
	seen := map[string]bool{}
	for _, n := range all {
		if seen[n] {
			t.Errorf("duplicate %q", n)
		}
		seen[n] = true
	}
	capped := cloudstorage.Guess(bases, 7)
	if len(capped) != 7 || !slices.Equal(capped, all[:7]) {
		t.Errorf("cap 7 = %v, want the first 7 of %v", capped, all[:7])
	}
	// Raising the cap keeps the earlier names: only new checks appear.
	if wider := cloudstorage.Guess(bases, 12); !slices.Equal(wider[:7], capped) {
		t.Errorf("raising the cap reorders names: %v vs %v", wider, capped)
	}
}

func TestProviderName(t *testing.T) {
	cases := []struct {
		provider, name, want string
		ok                   bool
	}{
		{"s3", "example-com", "example-com", true},
		{"s3", "example.com", "example.com", true},
		{"s3", "ab", "", false},
		{"s3", strings.Repeat("a", 64), "", false},
		{"s3", "-bad", "", false},
		{"s3", "bad-", "", false},
		{"s3", "a..b", "", false},
		{"gcs", "Example", "", false},
		{"gcs", "example_x", "", false},
		{"azure", "example-com", "examplecom", true},
		{"azure", "example.com", "examplecom", true},
		{"azure", "ab", "", false},
		{"azure", "averyveryverylongexampleaccountname", "", false},
	}
	for _, c := range cases {
		got, ok := cloudstorage.ProviderName(c.provider, c.name)
		if ok != c.ok || got != c.want {
			t.Errorf("ProviderName(%s, %q) = %q %v, want %q %v", c.provider, c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestKeyAndURL(t *testing.T) {
	if k := cloudstorage.Key("s3", "b", ""); k != "s3|b" {
		t.Errorf("key = %q", k)
	}
	if k := cloudstorage.Key("azure", "acct", "media"); k != "azure|acct/media" {
		t.Errorf("azure key = %q", k)
	}
	if u := cloudstorage.URL("s3", "b", ""); u != "https://s3.amazonaws.com/b" {
		t.Errorf("s3 url = %q", u)
	}
	if u := cloudstorage.URL("gcs", "b", ""); u != "https://storage.googleapis.com/b" {
		t.Errorf("gcs url = %q", u)
	}
	if u := cloudstorage.URL("azure", "acct", "media"); u != "https://acct.blob.core.windows.net/media" {
		t.Errorf("azure url = %q", u)
	}
	if !slices.Contains(cloudstorage.AzureContainers, "$web") || len(cloudstorage.AzureContainers) != 12 {
		t.Errorf("fixed containers = %v", cloudstorage.AzureContainers)
	}
}

// "public" is an anonymous HEAD of a known object succeeding; unknown without one.
func TestPublicState(t *testing.T) {
	if got := cloudstorage.PublicState(nil); got != "unknown" {
		t.Errorf("no objects = %q", got)
	}
	if got := cloudstorage.PublicState([]bool{false}); got != "no" {
		t.Errorf("one private object = %q", got)
	}
	if got := cloudstorage.PublicState([]bool{false, true}); got != "yes" {
		t.Errorf("one public object = %q", got)
	}
}
