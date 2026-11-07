package sanitize_test

import (
	"strings"
	"testing"

	"github.com/rafaelh/recon/internal/sanitize"
)

func TestText(t *testing.T) {
	in := "ok\x1b[31m red\x1b]0;title\x07 \x00bell\x07 tab\there ‮ bidi"
	got := sanitize.Text(in)
	for _, bad := range []string{"\x1b", "\x07", "\x00", "\t", "‮", "[31m", "title"} {
		if strings.Contains(got, bad) {
			t.Errorf("%q survived in %q", bad, got)
		}
	}
	for _, want := range []string{"ok", "red", "bell", "tab here", "bidi"} {
		if !strings.Contains(got, want) {
			t.Errorf("visible text %q lost: %q", want, got)
		}
	}
}
