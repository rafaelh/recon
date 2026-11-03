package asn_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/scope"
	"github.com/rafaelh/recon/internal/stages/asn"
)

func clients(t *testing.T, h http.HandlerFunc) (egress.Clients, *string) {
	t.Helper()
	var uri string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { uri = r.URL.RequestURI(); h(w, r) }))
	t.Cleanup(srv.Close)
	eg := egress.New(egress.Options{SourceBaseURLs: map[string]string{"stat.ripe.net": srv.URL}, RatePerSource: 1000})
	eg.SetPolicy(&egress.Policy{Scope: scope.New(scope.Config{})})
	s := asn.New()
	return eg.Clients(s.Name(), false, s.Sources()), &uri
}

func TestContract(t *testing.T) {
	s := asn.New()
	if s.Name() != "asn" || s.Contact() != run.ThirdParty || len(s.Sources()) != 1 || s.Sources()[0] != "stat.ripe.net" {
		t.Errorf("%s %v %v", s.Name(), s.Contact(), s.Sources())
	}
	if ok, _ := s.Configured(run.Env{}); !ok {
		t.Error("asn needs no key")
	}
}

func TestRun(t *testing.T) {
	c, uri := clients(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"prefixes":[{"prefix":"1.1.1.0/24"},{"prefix":"2606:4700::/32"}]}}`))
	})
	obs, err := asn.New().Run(context.Background(), run.Check{Key: "AS13335", Input: "AS13335"}, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 2 || obs[0].Kind != "netblock" || obs[0].Key != "1.1.1.0/24" || obs[0].Attrs["asn"] != "AS13335" || obs[1].Key != "2606:4700::/32" {
		t.Errorf("obs = %+v", obs)
	}
	for _, w := range []string{"/data/announced-prefixes/data.json", "resource=AS13335", "sourceapp=recon"} {
		if !strings.Contains(*uri, w) {
			t.Errorf("request %q missing %q", *uri, w)
		}
	}
}

// D7: a non-ok body status is a transient failure (an error), not an empty result.
func TestRunErrors(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"status":   func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"status":"error","data":{}}`)) },
		"http 500": func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", 500) },
		"bad json": func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`<html>`)) },
		"http 429": func(w http.ResponseWriter, r *http.Request) { http.Error(w, "slow down", 429) },
	} {
		c, _ := clients(t, h)
		if obs, err := asn.New().Run(context.Background(), run.Check{Key: "AS1", Input: "AS1"}, c); err == nil {
			t.Errorf("%s: want error, got %+v", name, obs)
		}
	}
}

func TestZeroPrefixesIsAResult(t *testing.T) {
	c, _ := clients(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"prefixes":[]}}`))
	})
	obs, err := asn.New().Run(context.Background(), run.Check{Key: "AS1", Input: "AS1"}, c)
	if err != nil || len(obs) != 0 {
		t.Errorf("%+v %v", obs, err)
	}
}
