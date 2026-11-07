// Package sanitize strips target-supplied text of anything that could act on
// a terminal or viewer rather than display as text.
package sanitize

import (
	"regexp"
	"strings"
	"unicode"
)

var (
	ansiCSI = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
	ansiOSC = regexp.MustCompile(`\x1b\][^\x07\x1b]*(\x07|\x1b\\)?`)
)

// Text removes terminal escape sequences, control characters and bidi
// overrides, and turns tabs into spaces.
func Text(s string) string {
	s = ansiOSC.ReplaceAllString(s, "")
	s = ansiCSI.ReplaceAllString(s, "")
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t':
			return ' '
		case unicode.IsControl(r), r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069, r == 0x200E, r == 0x200F:
			return -1
		}
		return r
	}, s)
}
