package providerranges

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/provider"
	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/store"
)

var wantKeys = []string{"aws", "gcp", "cloudflare-v4", "cloudflare-v6", "fastly", "digitalocean", "oracle", "linode"}

func listFor(t *testing.T, key string) list {
	t.Helper()
	l, ok := listByKey(key)
	if !ok {
		t.Fatalf("no list with key %q", key)
	}
	return l
}

// Every list's provider has a classification rule, or its ranges would be
// fetched and stored and then ignored.
func TestLists_EveryProviderHasARule(t *testing.T) {
	for _, l := range lists {
		if !provider.HasRangeRule(l.provider) {
			t.Errorf("list %s: provider %q has no classification rule", l.key, l.provider)
		}
	}
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// rng is the attributes of one observation, for comparison.
type rng struct{ provider, prefix, service, region string }

func got(t *testing.T, obs []run.Observation) []rng {
	t.Helper()
	var out []rng
	for _, o := range obs {
		if o.Kind != kinds.ProviderRange.Name() {
			t.Errorf("observation kind = %q, want %q", o.Kind, kinds.ProviderRange.Name())
		}
		a := kinds.ProviderRange.Attrs(store.Record{Attrs: o.Attrs})
		out = append(out, rng{a.Provider, a.Prefix, a.Service, a.Region})
	}
	return out
}

func TestParsers_RecordedSamples(t *testing.T) {
	cases := []struct {
		key, file string
		n         int
		first     rng
		last      rng
	}{
		{"cloudflare-v4", "cloudflare-v4.txt", 15,
			rng{"cloudflare", "173.245.48.0/20", "", ""}, rng{"cloudflare", "131.0.72.0/22", "", ""}},
		{"cloudflare-v6", "cloudflare-v6.txt", 7,
			rng{"cloudflare", "2400:cb00::/32", "", ""}, rng{"cloudflare", "2c0f:f248::/32", "", ""}},
		{"fastly", "fastly.json", 8,
			rng{"fastly", "23.235.32.0/20", "", ""}, rng{"fastly", "2a04:4e44::/32", "", ""}},
		// A published region is kept; the "None" some DigitalOcean lines carry is not a region.
		{"digitalocean", "digitalocean.csv", 4,
			rng{"digitalocean", "5.101.96.0/21", "", "NL-NH"}, rng{"digitalocean", "2604:a880:9:1::/64", "", ""}},
		// Comment lines are skipped.
		{"linode", "linode.txt", 4,
			rng{"linode", "72.14.177.0/24", "", "US-TX"}, rng{"linode", "2600:3c01::/32", "", "US-CA"}},
		// One observation per tag, so a range tagged for two services is two records.
		{"oracle", "oracle.json", 5,
			rng{"oracle", "40.233.0.0/19", "OCI", "mx-monterrey-1"}, rng{"oracle", "129.146.0.0/21", "OCI", "us-phoenix-1"}},
	}
	for _, c := range cases {
		t.Run(c.key, func(t *testing.T) {
			obs, err := listFor(t, c.key).observations(fixture(t, c.file))
			if err != nil {
				t.Fatal(err)
			}
			g := got(t, obs)
			if len(g) != c.n {
				t.Fatalf("got %d ranges, want %d", len(g), c.n)
			}
			if g[0] != c.first || g[len(g)-1] != c.last {
				t.Errorf("first %+v, last %+v\nwant  %+v, last %+v", g[0], g[len(g)-1], c.first, c.last)
			}
			seen := map[string]bool{}
			for _, o := range obs {
				if seen[o.Key] {
					t.Errorf("duplicate observation key %q", o.Key)
				}
				seen[o.Key] = true
			}
		})
	}
}

func TestParsers_OracleTagsBecomeServices(t *testing.T) {
	obs, err := listFor(t, "oracle").observations(fixture(t, "oracle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var tagged []string
	for _, r := range got(t, obs) {
		if r.prefix == "134.70.200.0/23" {
			tagged = append(tagged, r.service)
		}
	}
	slices.Sort(tagged)
	if !slices.Equal(tagged, []string{"OBJECT_STORAGE", "OSN"}) {
		t.Errorf("134.70.200.0/23 services = %v, want OBJECT_STORAGE and OSN", tagged)
	}
}

func TestParsers_AWSAndGCPUnchanged(t *testing.T) {
	aws, err := listFor(t, "aws").observations([]byte(`{"prefixes":[{"ip_prefix":"203.0.113.0/24","region":"eu-west-1","service":"EC2"}],
		"ipv6_prefixes":[{"ipv6_prefix":"2001:db8::/32","region":"us-east-1","service":"AMAZON"}]}`))
	if err != nil || !slices.Equal(got(t, aws), []rng{{"aws", "203.0.113.0/24", "EC2", "eu-west-1"}, {"aws", "2001:db8::/32", "AMAZON", "us-east-1"}}) {
		t.Errorf("aws: %+v %v", got(t, aws), err)
	}
	gcp, err := listFor(t, "gcp").observations([]byte(`{"prefixes":[{"ipv4Prefix":"100.64.0.0/16","service":"Google Cloud","scope":"europe-west1"},{"ipv6Prefix":"2001:db8:1::/48","scope":"us-east1"}]}`))
	if err != nil || !slices.Equal(got(t, gcp), []rng{{"gcp", "100.64.0.0/16", "", "europe-west1"}, {"gcp", "2001:db8:1::/48", "", "us-east1"}}) {
		t.Errorf("gcp: %+v %v", got(t, gcp), err)
	}
}

// A body with no usable range is an error, not an empty success: an empty check
// would be recorded as done and the list would never be fetched again.
func TestParsers_EmptyAndMalformedBodiesFail(t *testing.T) {
	bodies := map[string][]string{
		"aws":           {``, `not json`, `{"prefixes":[]}`, `{"prefixes":[{"ip_prefix":"nope","service":"EC2"}]}`, `{"prefixes":[`},
		"gcp":           {``, `not json`, `{"prefixes":[]}`, `{"prefixes":[{"scope":"x"}]}`},
		"cloudflare-v4": {``, "\n\n", "<html>Access denied</html>", "# only a comment\n"},
		"cloudflare-v6": {``, "\n", "Error 1015", "not-a-prefix\n"},
		"fastly":        {``, `not json`, `{}`, `{"addresses":[],"ipv6_addresses":[]}`, `{"addresses":["x"]}`, `{"addresses":[`},
		"digitalocean":  {``, "\n", "<html>moved</html>", ",,,\n", "# comment\n"},
		"oracle":        {``, `not json`, `{}`, `{"regions":[]}`, `{"regions":[{"region":"r","cidrs":[]}]}`, `{"regions":[{"region":"r","cidrs":[{"cidr":"nope","tags":["OCI"]}]}]}`, `{"regions":[`},
		"linode":        {``, "# a comment\n# another\n", "<html></html>", "Not Found"},
	}
	if len(bodies) != len(wantKeys) {
		t.Fatalf("table covers %d lists, want %d", len(bodies), len(wantKeys))
	}
	for key, bs := range bodies {
		l := listFor(t, key)
		for _, b := range bs {
			obs, err := l.observations([]byte(b))
			if err == nil {
				t.Errorf("%s: body %q gave %d ranges and no error", key, b, len(obs))
				continue
			}
			if !strings.Contains(err.Error(), l.provider) {
				t.Errorf("%s: error %q does not name the provider %q", key, err, l.provider)
			}
		}
	}
}

// A malformed line among good ones is skipped; the rest of the list applies.
func TestParsers_SkipsUnparseableLines(t *testing.T) {
	obs, err := listFor(t, "cloudflare-v4").observations([]byte("173.245.48.0/20\nnonsense\n\n104.16.0.0/13\n"))
	if err != nil || len(obs) != 2 {
		t.Errorf("got %d observations, %v; want 2 and no error", len(obs), err)
	}
}

func TestStage_OneCheckPerList(t *testing.T) {
	var keys []string
	for c, err := range New().Checks(context.Background(), run.View{}) {
		if err != nil {
			t.Fatal(err)
		}
		if c.Key != c.Input {
			t.Errorf("check %q has input %q; the key is the stable name", c.Key, c.Input)
		}
		keys = append(keys, c.Key)
	}
	if !slices.Equal(keys, wantKeys) {
		t.Errorf("checks = %v, want %v", keys, wantKeys)
	}
}

// The URLs are the published ones, each an https URL on a host the stage declares,
// and nothing is fetched for Azure, whose published list moves.
func TestSources_NamesEveryPublisherAndNoAzure(t *testing.T) {
	declared := New().Sources()
	for _, key := range wantKeys {
		u, err := url.Parse(listFor(t, key).url)
		if err != nil || u.Scheme != "https" {
			t.Errorf("%s: url %q", key, listFor(t, key).url)
			continue
		}
		if !slices.Contains(declared, u.Host) {
			t.Errorf("%s: host %s is not in Sources() %v", key, u.Host, declared)
		}
	}
	for _, h := range declared {
		if strings.Contains(h, "microsoft") || strings.Contains(h, "azure") {
			t.Errorf("Sources() names %s; Azure is classified by ASN only", h)
		}
	}
	if len(declared) != 7 {
		t.Errorf("Sources() = %v, want the seven publishers", declared)
	}
}
