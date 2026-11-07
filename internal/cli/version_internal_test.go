package cli

import (
	"runtime/debug"
	"testing"
)

// The version string comes from the build info; "" (no version)
// is turned into "devel" by Execute, which TestVersionFlagZeroDeps covers.
func TestVersionString(t *testing.T) {
	const pseudo = "v0.0.0-20261106032157-7e34c1b8d74f+dirty"
	cases := []struct {
		name string
		info *debug.BuildInfo
		ok   bool
		want string
	}{
		{"pseudo-version as is", &debug.BuildInfo{Main: debug.Module{Version: pseudo}}, true, pseudo},
		{"tagged version as is", &debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}}, true, "v1.2.3"},
		{"devel build", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, true, ""},
		{"empty version", &debug.BuildInfo{}, true, ""},
		{"no build info", nil, false, ""},
		{"build info flagged missing", &debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}}, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := versionString(c.info, c.ok); got != c.want {
				t.Errorf("versionString = %q, want %q", got, c.want)
			}
		})
	}
}
