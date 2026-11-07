package kinds_test

import (
	"testing"

	"github.com/rafaelh/recon/internal/kinds"
)

// D26: the new kinds and which of them are counted.
func TestSpec2Kinds(t *testing.T) {
	want := map[string]struct {
		category string
		counted  bool
	}{
		"ip": {"ips", true}, "unresolved": {"unresolved names", true},
		"wildcard": {"", false}, "ip_owner": {"", false}, "ip_hostname": {"", false}, "provider_range": {"", false},
		"resolution": {"", false},
	}
	for name, w := range want {
		k, ok := kinds.Get(name)
		if !ok {
			t.Errorf("kind %s not registered", name)
			continue
		}
		if k.Category != w.category || k.Counted != w.counted || k.Printed || k.Entity {
			t.Errorf("%s = %+v, want category %q counted %v, not printed, not an entity", name, k, w.category, w.counted)
		}
	}
	if k, _ := kinds.Get("hostname"); !k.Printed {
		t.Error("hostname still prints")
	}
}
