package asn_test

import (
	"context"
	"errors"
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
		_, _ = w.Write([]byte(`{"status":"ok","data":{"prefixes":[{"prefix":"1.1.1.0/24"},{"prefix":"2606:4700::/32"}]}}`))
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

// A non-ok body status or HTTP status is a transient failure (an error), not
// an empty result. A 429 does not abort the stage: the source is keyless.
func TestRunErrors(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"status":   func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"status":"error","data":{}}`)) },
		"http 500": func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", 500) },
		"http 404": func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) },
		"bad json": func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`<html>`)) },
		"http 429": func(w http.ResponseWriter, r *http.Request) { http.Error(w, "slow down", http.StatusTooManyRequests) },
	} {
		c, _ := clients(t, h)
		obs, err := asn.New().Run(context.Background(), run.Check{Key: "AS1", Input: "AS1"}, c)
		if err == nil {
			t.Errorf("%s: want error, got %+v", name, obs)
		} else if errors.Is(err, run.ErrAbortStage) {
			t.Errorf("%s: want a transient error, got an abort: %v", name, err)
		}
	}
}

func TestZeroPrefixesIsAResult(t *testing.T) {
	c, _ := clients(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","data":{"prefixes":[]}}`))
	})
	obs, err := asn.New().Run(context.Background(), run.Check{Key: "AS1", Input: "AS1"}, c)
	if err != nil || len(obs) != 0 {
		t.Errorf("%+v %v", obs, err)
	}
}
