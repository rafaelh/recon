package inventory_test

import (
	"net/netip"
	"testing"

	"github.com/rafaelh/recon/internal/inventory"
	"github.com/rafaelh/recon/internal/provider"
)

// D5: SaaSServed is true when a CNAME on the chain, an address's ASN or an address range is SaaS.
func TestSaaSServed(t *testing.T) {
	var d inventory.Data
	d.Resolutions = []inventory.Resolution{
		{Name: "help.example.com", Type: "CNAME", Value: "acme.zendesk.com"},
		{Name: "help.example.com", Type: "A", Value: "203.0.113.20"},
		{Name: "shop.example.com", Type: "A", Value: "23.227.38.65"},
		{Name: "pages.example.com", Type: "A", Value: "185.199.108.153"},
		{Name: "cdn.example.com", Type: "CNAME", Value: "d1.cloudfront.net"},
		{Name: "cdn.example.com", Type: "A", Value: "203.0.113.21"},
		{Name: "www.example.com", Type: "A", Value: "203.0.113.22"},
		{Name: "app.example.com", Type: "CNAME", Value: "acme.herokuapp.com"},
		{Name: "app.example.com", Type: "A", Value: "203.0.113.23"},
	}
	for _, n := range []string{"help", "shop", "pages", "cdn", "www", "app"} {
		d.Hosts = append(d.Hosts, inventory.Host{Name: n + ".example.com", Stages: []string{"crtsh"}})
	}
	d.Owners = map[netip.Addr]provider.Owner{netip.MustParseAddr("23.227.38.65"): {ASN: 62679, Holder: "SHOPIFY", Known: true}}
	inv := inventory.New(d, provider.Default())
	for host, want := range map[string]bool{
		"help.example.com":  true,  // CNAME chain
		"shop.example.com":  true,  // ASN
		"pages.example.com": true,  // address range, no CNAME (apex)
		"cdn.example.com":   false, // a CDN is not SaaS
		"www.example.com":   false,
		"app.example.com":   false, // PaaS: the company's own app
		"unknown.test":      false,
		"185.199.108.153":   true, // an IP literal in a SaaS range
		"203.0.113.22":      false,
	} {
		if got := inv.SaaSServed(host); got != want {
			t.Errorf("SaaSServed(%s) = %v, want %v", host, got, want)
		}
	}
}

// D5: ProviderHosts carries the matched entry, with its fingerprint.
func TestProviderHostEntry(t *testing.T) {
	var d inventory.Data
	d.Hosts = []inventory.Host{{Name: "shop.example.com", Stages: []string{"crtsh"}}, {Name: "app.example.com", Stages: []string{"crtsh"}}}
	d.Resolutions = []inventory.Resolution{
		{Name: "shop.example.com", Type: "CNAME", Value: "gone.cloudapp.net"},
		{Name: "app.example.com", Type: "CNAME", Value: "acme.herokuapp.com"},
		{Name: "app.example.com", Type: "A", Value: "203.0.113.23"},
	}
	inv := inventory.New(d, provider.Default())
	sc := newScope(inv, d)
	got := map[string]inventory.ProviderHost{}
	for _, ph := range inv.ProviderHosts(sc) {
		got[ph.Hostname] = ph
	}
	if e := got["shop.example.com"].Entry; !e.NXDomain || e.Provider != "azure" || e.Body != "" {
		t.Errorf("shop entry = %+v", e)
	}
	if e := got["app.example.com"].Entry; e.Body == "" || e.Provider != "heroku" || e.Hash() == "" {
		t.Errorf("app entry = %+v", e)
	}
}
