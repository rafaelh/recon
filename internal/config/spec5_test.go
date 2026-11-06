package config_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/recon/internal/config"
)

func pathsFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "paths.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// D15: storage.max_names (default 50, > 0) and cert_expiry_days (default 30, >= 0).
func TestSpec5Settings(t *testing.T) {
	clearEnv(t)
	s, err := load(t, "")
	if err != nil {
		t.Fatal(err)
	}
	if s.Storage.MaxNames != 50 || s.CertExpiryDays != 30 {
		t.Errorf("defaults: max_names %d, cert_expiry_days %d", s.Storage.MaxNames, s.CertExpiryDays)
	}
	if s, err = load(t, "", "--storage-max-names", "9", "--cert-expiry-days", "0"); err != nil || s.Storage.MaxNames != 9 || s.CertExpiryDays != 0 {
		t.Errorf("flags: %+v %v", s, err)
	}
	if s, err = load(t, writeFile(t, "storage:\n  max_names: 12\ncert_expiry_days: 90\n")); err != nil || s.Storage.MaxNames != 12 || s.CertExpiryDays != 90 {
		t.Errorf("file: %+v %v", s, err)
	}
	t.Setenv("RECON_STORAGE_MAX_NAMES", "4")
	if s, err = load(t, ""); err != nil || s.Storage.MaxNames != 4 {
		t.Errorf("env: %+v %v", s, err)
	}
	os.Unsetenv("RECON_STORAGE_MAX_NAMES")
	for _, args := range [][]string{{"--storage-max-names", "0"}, {"--cert-expiry-days", "-1"}} {
		if _, err := load(t, "", args...); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
	fs := newFlagSetForHelp()
	for _, name := range []string{"storage-max-names", "cert-expiry-days"} {
		if fs.Lookup(name) == nil {
			t.Errorf("flag --%s missing", name)
		}
	}
}

// D11: the built-in list is about 20 entries, each with a signature or magic.
func TestBuiltinSensitivePaths(t *testing.T) {
	clearEnv(t)
	s, err := load(t, "")
	if err != nil {
		t.Fatal(err)
	}
	if n := len(s.SensitivePathEntries); n < 18 || n > 30 {
		t.Errorf("built-in entries = %d, want about 20", n)
	}
	paths := map[string]bool{}
	for _, e := range s.SensitivePathEntries {
		if e.Signature == "" && len(e.Magic) == 0 {
			t.Errorf("%s has neither signature nor magic", e.Path)
		}
		if e.Status == 0 || e.Severity == "" {
			t.Errorf("%s: defaults not applied: %+v", e.Path, e)
		}
		paths[e.Path] = true
	}
	for _, want := range []string{"/.git/config", "/.env", "/.DS_Store", "/server-status", "/phpinfo.php", "/actuator/env", "/.aws/credentials", "/wp-config.php.bak", "/.svn/entries", "/.htpasswd"} {
		if !paths[want] {
			t.Errorf("built-in list lacks %s", want)
		}
	}
	if label := config.BuiltinSensitivePathsLabel(); !strings.Contains(label, "built-in (") || strings.Contains(label, "(0 ") {
		t.Errorf("label = %q", label)
	}
}

// D11: entry format, defaults and matching.
func TestSensitivePathEntries(t *testing.T) {
	clearEnv(t)
	file := pathsFile(t, `
- path: /.git/config
  signature: '\[core\]'
  severity: high
- path: /backup.zip
  magic: 504b0304
  status: 206
- path: /both
  signature: 'world'
  magic: '68656c'
`)
	s, err := load(t, "", "--sensitive-paths", file)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range s.SensitivePathEntries {
		got = append(got, e.Path)
	}
	if !slices.Equal(got, []string{"/.git/config", "/backup.zip", "/both"}) {
		t.Fatalf("entries = %+v", s.SensitivePathEntries)
	}
	git, zip, both := s.SensitivePathEntries[0], s.SensitivePathEntries[1], s.SensitivePathEntries[2]
	if git.Status != 200 || git.Severity != "high" || zip.Severity != "medium" || zip.Status != 206 {
		t.Errorf("defaults: %+v %+v", git, zip)
	}
	if sig, ok := git.Match(200, []byte("[core]\n\trepositoryformatversion = 0")); !ok || sig == "" {
		t.Error("signature should match")
	}
	if _, ok := git.Match(200, []byte("<html>catch-all page</html>")); ok {
		t.Error("a catch-all 200 must not match")
	}
	if _, ok := git.Match(404, []byte("[core]")); ok {
		t.Error("wrong status must not match")
	}
	if _, ok := zip.Match(206, []byte{0x50, 0x4b, 0x03, 0x04, 0x00}); !ok {
		t.Error("magic prefix should match")
	}
	if _, ok := zip.Match(206, []byte{0x00, 0x50, 0x4b, 0x03, 0x04}); ok {
		t.Error("magic is a prefix match only")
	}
	if _, ok := both.Match(200, []byte("hello world")); !ok {
		t.Error("both hold")
	}
	if _, ok := both.Match(200, []byte("hello there")); ok {
		t.Error("when both are given, the signature must hold too")
	}
	if _, ok := both.Match(200, []byte("say world")); ok {
		t.Error("when both are given, the magic must hold too")
	}
	if git.Hash() == zip.Hash() || len(git.Hash()) != 8 {
		t.Errorf("hashes: %q %q", git.Hash(), zip.Hash())
	}
}

// D11: invalid entries fail validation (exit 2 in the CLI).
func TestSensitivePathValidation(t *testing.T) {
	clearEnv(t)
	cases := map[string]string{
		"plain string":      "- /admin\n",
		"no signature":      "- path: /admin\n",
		"relative path":     "- path: admin/.env\n  signature: x\n",
		"bad regex":         "- path: /a\n  signature: '(['\n",
		"bad magic":         "- path: /a\n  magic: zz\n",
		"bad severity":      "- path: /a\n  signature: x\n  severity: critical\n",
		"bad status":        "- path: /a\n  signature: x\n  status: 99\n",
		"missing path":      "- signature: x\n",
		"not a list":        "path: /a\n",
		"unknown field":     "- path: /a\n  signature: x\n  sig: y\n",
		"empty magic bytes": "- path: /a\n  magic: ''\n",
	}
	for name, body := range cases {
		_, err := load(t, "", "--sensitive-paths", pathsFile(t, body))
		if err == nil || !strings.Contains(err.Error(), "sensitive_paths") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestDKIMSelectors(t *testing.T) {
	sel := config.DKIMSelectors()
	for _, want := range []string{"google", "selector1", "selector2", "k1", "k2", "default", "dkim", "mail", "s1", "s2", "smtp", "mandrill"} {
		if !slices.Contains(sel, want) {
			t.Errorf("selector %q missing", want)
		}
	}
	if config.DKIMSelectorHash() == "" || len(config.DKIMSelectorHash()) != 8 {
		t.Errorf("hash = %q", config.DKIMSelectorHash())
	}
}
