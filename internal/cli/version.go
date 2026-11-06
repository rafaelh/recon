package cli

import "runtime/debug"

const develVersion = "devel"

// versionString is the module version recorded in the build, or "" when there
// is none; Execute alone turns "" into develVersion. Builds from a checkout and
// `go install @latest` both record a VCS pseudo-version (with +dirty for local
// changes), so it is used as is.
func versionString(info *debug.BuildInfo, ok bool) string {
	if !ok || info == nil || info.Main.Version == "(devel)" {
		return ""
	}
	return info.Main.Version
}
