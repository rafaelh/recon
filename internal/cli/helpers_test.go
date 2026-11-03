package cli_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/stages/asn"
)

func newASN() run.Stage { return asn.New() }

// newPrefixServer answers RIPEstat announced-prefixes with the current *prefix.
func newPrefixServer(t *testing.T, prefix *string) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"status":"ok","data":{"prefixes":[{"prefix":%q}]}}`, *prefix)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}
