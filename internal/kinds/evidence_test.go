package kinds_test

import (
	"testing"

	"github.com/rafaelh/recon/internal/kinds"
)

// The evidence kinds are internal, with no category, so totals count findings only.
func TestEvidenceKinds(t *testing.T) {
	for _, name := range []string{"takeover_http", "storage", "storage_account", "storage_object", "storage_ref", "sensitive_hit", "email_posture", "web_posture"} {
		k, ok := kinds.Get(name)
		if !ok {
			t.Errorf("kind %s not registered", name)
			continue
		}
		if k.Category != "" || k.Printed || k.Counted || k.Entity {
			t.Errorf("%s = %+v, want an internal kind with no category", name, k)
		}
	}
	// Evidence keyed by a page or a root is shown only while that is in scope.
	if k, _ := kinds.Get("storage_ref"); k.HostAttr != "page_host" {
		t.Errorf("storage_ref = %+v, want HostAttr \"page_host\"", k)
	}
	if k, _ := kinds.Get("email_posture"); !k.HostKey {
		t.Errorf("email_posture = %+v, want HostKey", k)
	}
	// Web posture is keyed by its service and shown while the service's host is in scope.
	if k, _ := kinds.Get("web_posture"); k.HostAttr != "host" {
		t.Errorf("web_posture = %+v, want HostAttr \"host\"", k)
	}
	if k, _ := kinds.Get("finding"); !k.Printed || k.Category != "findings" {
		t.Errorf("finding = %+v", k)
	}
}
