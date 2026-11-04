package kinds_test

import (
	"testing"

	"github.com/rafaelh/recon/internal/kinds"
)

// Spec 3 D17/D18: web_service and url name the attribute holding their host so
// the summary and the CSVs filter them identically; http_port is internal.
func TestWebKinds(t *testing.T) {
	r := kinds.Default()
	for _, name := range []string{"web_service", "url"} {
		k, ok := r.Get(name)
		if !ok || k.HostAttr != "host" {
			t.Errorf("%s = %+v, want HostAttr \"host\"", name, k)
		}
	}
	if k, _ := r.Get("web_service"); !k.Printed {
		t.Error("web_service is printed")
	}
	if k, _ := r.Get("url"); !k.Counted || k.Printed {
		t.Error("url is counted and never printed")
	}
	k, ok := r.Get("http_port")
	if !ok {
		t.Fatal("http_port is not registered")
	}
	if k.Category != "" || k.Printed || k.Counted || k.Entity {
		t.Errorf("http_port = %+v, want an internal kind with no category", k)
	}
	if k, _ := r.Get("open_port"); k.HostAttr != "" {
		t.Error("open_port has no host attribute")
	}
}
