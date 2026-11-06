package kinds_test

import (
	"testing"

	"github.com/rafaelh/recon/internal/kinds"
)

// D17: the evidence kinds are internal, with no category, so totals count findings only.
func TestSpec5Kinds(t *testing.T) {
	r := kinds.Default()
	for _, name := range []string{"takeover_http", "storage", "storage_account", "storage_object", "storage_ref", "sensitive_hit", "email_posture"} {
		k, ok := r.Get(name)
		if !ok {
			t.Errorf("kind %s not registered", name)
			continue
		}
		if k.Category != "" || k.Printed || k.Counted || k.Entity || k.HostAttr != "" || k.PortKey {
			t.Errorf("%s = %+v, want an internal kind with no category", name, k)
		}
	}
	if k, _ := r.Get("finding"); !k.Printed || k.Category != "findings" {
		t.Errorf("finding = %+v", k)
	}
}
