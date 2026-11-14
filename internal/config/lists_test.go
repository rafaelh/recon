package config_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/rafaelh/recon/internal/config"
	"github.com/rafaelh/recon/internal/dnsname"
)

// The built-in wordlist is big enough to use without a list of one's own, and
// every entry is something a permutation can use.
func TestBuiltinWordlist(t *testing.T) {
	clearEnv(t)
	s, err := load(t, "")
	if err != nil {
		t.Fatal(err)
	}
	words := s.WordlistWords
	if len(words) < 2000 || len(words) > 5000 {
		t.Fatalf("built-in wordlist has %d entries, want 2000 to 5000", len(words))
	}
	seen := map[string]bool{}
	for _, w := range words {
		if w != strings.ToLower(w) {
			t.Errorf("%q is not lower case", w)
		}
		if !dnsname.ValidLabel(w) {
			t.Errorf("%q is not a valid DNS label", w)
		}
		if seen[w] {
			t.Errorf("%q is listed twice", w)
		}
		seen[w] = true
	}
	// Most common first: the per-seed cap takes words from the front.
	for i, want := range []string{"www", "mail", "ns2", "ns1"} {
		if words[i] != want {
			t.Errorf("word %d = %q, want %q", i, words[i], want)
		}
	}
	if got := config.BuiltinWordlistLabel(); got != fmt.Sprintf("built-in (%d entries)", len(words)) {
		t.Errorf("label = %q", got)
	}
}

// The wordlist's source and licence are credited in the file itself.
func TestBuiltinWordlistAttribution(t *testing.T) {
	b, err := os.ReadFile("builtin/wordlist.txt")
	if err != nil {
		t.Fatal(err)
	}
	header := strings.SplitN(string(b), "\n\n", 2)[0]
	for _, want := range []string{"SecLists", "MIT", "Daniel Miessler", "subdomains-top1million-5000"} {
		if !strings.Contains(header, want) {
			t.Errorf("wordlist header does not mention %q:\n%s", want, header)
		}
	}
	for _, line := range strings.Split(header, "\n") {
		if !strings.HasPrefix(line, "#") {
			t.Errorf("header line %q is not a comment", line)
		}
	}
}

// The README credits SecLists, says what a run costs, and gives the request
// formula for the sensitive paths.
func TestREADMEStatesListsAndVolume(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	readme := string(b)
	clearEnv(t)
	s, err := load(t, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"SecLists", "MIT",
		fmt.Sprintf("%d lookups per root", len(s.WordlistWords)),
		"services × entries", "sensitive_path_max_requests", "permutations.max_names",
		fmt.Sprintf("%d entries", len(s.SensitivePathEntries)),
	} {
		if !strings.Contains(readme, want) {
			t.Errorf("README does not mention %q", want)
		}
	}
}

// sampleName is the testdata file holding a real example of the path's file.
func sampleName(path string) string {
	return strings.ReplaceAll(strings.TrimPrefix(path, "/"), "/", "__")
}

func sample(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "sensitive", name))
	if err != nil {
		t.Fatalf("sample missing: %v", err)
	}
	return b
}

// Every built-in path is explicit about its severity, matches a sample of the
// real file, and does not match a catch-all 200 page or a soft 404.
func TestBuiltinSensitivePathsSamples(t *testing.T) {
	clearEnv(t)
	s, err := load(t, "")
	if err != nil {
		t.Fatal(err)
	}
	entries := s.SensitivePathEntries
	if len(entries) < 150 {
		t.Fatalf("built-in sensitive paths: %d entries, want at least 150", len(entries))
	}
	raw, err := os.ReadFile("builtin/sensitive_paths.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var rawEntries []map[string]any
	if err := yaml.Unmarshal(raw, &rawEntries); err != nil {
		t.Fatal(err)
	}
	if len(rawEntries) != len(entries) {
		t.Fatalf("%d raw entries, %d parsed", len(rawEntries), len(entries))
	}
	generic, soft404 := sample(t, "_generic-200.html"), sample(t, "_soft-404.html")
	seen := map[string]bool{}
	for i, e := range entries {
		if seen[e.Path] {
			t.Errorf("%s is listed twice", e.Path)
		}
		seen[e.Path] = true
		if sev, _ := rawEntries[i]["severity"].(string); sev != "high" && sev != "medium" && sev != "low" {
			t.Errorf("%s: severity %q is not explicit (high, medium or low)", e.Path, sev)
		}
		body := sample(t, sampleName(e.Path))
		if _, ok := e.Match(e.Status, body); !ok {
			t.Errorf("%s: does not match its sample", e.Path)
		}
		if _, ok := e.Match(e.Status+1, body); ok {
			t.Errorf("%s: matches its sample under the wrong status", e.Path)
		}
		if _, ok := e.Match(200, generic); ok {
			t.Errorf("%s: matches a generic 200 page", e.Path)
		}
		if _, ok := e.Match(200, soft404); ok {
			t.Errorf("%s: matches a soft 404", e.Path)
		}
		if _, ok := e.Match(404, soft404); ok {
			t.Errorf("%s: matches a 404 page", e.Path)
		}
	}
	if got := config.BuiltinSensitivePathsLabel(); got != fmt.Sprintf("built-in (%d entries)", len(entries)) {
		t.Errorf("label = %q", got)
	}
}

// Every sample belongs to an entry, so a removed entry leaves nothing behind.
func TestSensitiveSamplesHaveEntries(t *testing.T) {
	clearEnv(t)
	s, err := load(t, "")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"_generic-200.html": true, "_soft-404.html": true}
	for _, e := range s.SensitivePathEntries {
		want[sampleName(e.Path)] = true
	}
	files, err := os.ReadDir(filepath.Join("testdata", "sensitive"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if !want[f.Name()] {
			t.Errorf("sample %s belongs to no entry", f.Name())
		}
	}
}

// goldenEntries are the built-in entries of the release before the list grew,
// as path|hash. Their hash is part of every check key, so changing one would
// repeat its checks on every engagement and strand its hits.
var goldenEntries = []string{
	"/.git/config|eb95cb36",
	"/.git/HEAD|82193961",
	"/.env|af1fcec4",
	"/.aws/credentials|cec353cf",
	"/.htpasswd|fc51f1f5",
	"/wp-config.php.bak|a01438d9",
	"/.svn/entries|57e4114a",
	"/.hg/hgrc|70a2119c",
	"/.DS_Store|3726b3b2",
	"/server-status|20465484",
	"/server-info|4cf91c54",
	"/phpinfo.php|872a54c5",
	"/info.php|872a54c5",
	"/actuator/env|e93c71f3",
	"/actuator/heapdump|4ba95696",
	"/.npmrc|cf2a6649",
	"/.docker/config.json|e4a42bad",
	"/id_rsa|fd3134f5",
	"/backup.zip|500b5a03",
	"/backup.tar.gz|bbb9b6b8",
	"/backup.sql|00a6c0c2",
	"/dump.sql|00a6c0c2",
	"/WEB-INF/web.xml|ab5a08d0",
}

func TestBuiltinSensitivePathsKeepExistingEntries(t *testing.T) {
	clearEnv(t)
	s, err := load(t, "")
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, e := range s.SensitivePathEntries {
		have[e.Path+"|"+e.Hash()] = true
	}
	for _, g := range goldenEntries {
		if !have[g] {
			t.Errorf("existing entry %s is gone or changed", g)
		}
	}
}

// The per-run caps default as designed, take a flag, the environment and the
// config file in that order of precedence, and must be at least 1.
func TestPerRunCapSettings(t *testing.T) {
	for _, c := range []struct {
		name, flag, env, key string
		yaml                 func(n int) string
		def                  int
		get                  func(config.Settings) int
	}{
		{"permutations.max_names", "--permutations-max-names", "RECON_PERMUTATIONS_MAX_NAMES", "permutations.max_names",
			func(n int) string { return fmt.Sprintf("permutations:\n  max_names: %d\n", n) }, 200000,
			func(s config.Settings) int { return s.Permutations.MaxNames }},
		{"sensitive_path_max_requests", "--sensitive-path-max-requests", "RECON_SENSITIVE_PATH_MAX_REQUESTS", "sensitive_path_max_requests",
			func(n int) string { return fmt.Sprintf("sensitive_path_max_requests: %d\n", n) }, 50000,
			func(s config.Settings) int { return s.SensitivePathMaxRequests }},
	} {
		t.Run(c.name, func(t *testing.T) {
			clearEnv(t)
			if s, err := load(t, ""); err != nil || c.get(s) != c.def {
				t.Fatalf("default = %d, %v; want %d", c.get(s), err, c.def)
			}
			if s, err := load(t, writeFile(t, c.yaml(70))); err != nil || c.get(s) != 70 {
				t.Errorf("file: %d %v", c.get(s), err)
			}
			t.Setenv(c.env, "80")
			if s, err := load(t, writeFile(t, c.yaml(70))); err != nil || c.get(s) != 80 {
				t.Errorf("env over file: %d %v", c.get(s), err)
			}
			if s, err := load(t, "", c.flag, "90"); err != nil || c.get(s) != 90 {
				t.Errorf("flag over env: %d %v", c.get(s), err)
			}
			clearEnv(t)
			for _, bad := range []string{"0", "-1"} {
				if _, err := load(t, "", c.flag, bad); err == nil || !strings.Contains(err.Error(), c.key) {
					t.Errorf("%s %s: error %v should name %s", c.flag, bad, err, c.key)
				}
			}
			if _, err := load(t, writeFile(t, c.yaml(0))); err == nil {
				t.Error("a zero cap in the file must be invalid")
			}
		})
	}
}

// sensitive_path_max_requests is a top-level key, not part of the sensitive_paths file setting.
func TestSensitivePathMaxRequestsIsNotNested(t *testing.T) {
	clearEnv(t)
	if _, err := load(t, writeFile(t, "sensitive_paths:\n  max_requests: 5\n")); err == nil {
		t.Error("max_requests must not be accepted nested under sensitive_paths")
	}
}

// --permutations-max stays the per-seed cap and does not touch the per-run one.
func TestPermutationsMaxIsStillPerSeed(t *testing.T) {
	clearEnv(t)
	if s, err := load(t, "", "--permutations-max", "11"); err != nil || s.Permutations.MaxPerSeed != 11 || s.Permutations.MaxNames != 200000 {
		t.Errorf("%+v %v", s.Permutations, err)
	}
}

// A custom wordlist or sensitive-path file replaces the built-in list outright.
func TestCustomListsReplaceBuiltin(t *testing.T) {
	clearEnv(t)
	wl := filepath.Join(t.TempDir(), "w.txt")
	if err := os.WriteFile(wl, []byte("alpha\nbeta\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sp := pathsFile(t, "- path: /x\n  signature: 'x'\n")
	s, err := load(t, "", "--wordlist", wl, "--sensitive-paths", sp)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.WordlistWords) != 2 || len(s.SensitivePathEntries) != 1 {
		t.Errorf("%d words, %d entries", len(s.WordlistWords), len(s.SensitivePathEntries))
	}
}
