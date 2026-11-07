package config_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/rafaelh/recon/internal/config"
)

func load(t *testing.T, cfgPath string, args ...string) (config.Settings, error) {
	t.Helper()
	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	config.RegisterFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return config.Load(fs, cfgPath)
}

func writeFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func clearEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "RECON_") {
			t.Setenv(strings.SplitN(kv, "=", 2)[0], "")
			os.Unsetenv(strings.SplitN(kv, "=", 2)[0])
		}
	}
}

// Defaults.
func TestDefaults(t *testing.T) {
	clearEnv(t)
	s, err := load(t, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Ports) != 105 {
		t.Errorf("default ports = %d, want 105 (the nmap top 100 plus five risky ports)", len(s.Ports))
	}
	if got := config.FormatPorts(s.RiskyPorts); got != "21,23,445,1433,1521,3306,3389,5432,5900,6379,9200,11211,27017" {
		t.Errorf("risky ports = %s", got)
	}
	if s.Concurrency != 10 || s.Rate.PerHost != 5 || s.Rate.PerSource != 1 || s.Rate.DNS != 50 {
		t.Errorf("concurrency/rates = %d %+v", s.Concurrency, s.Rate)
	}
	if s.Crawl.MaxDepth != 2 || s.Crawl.MaxPages != 100 {
		t.Errorf("crawl = %+v", s.Crawl)
	}
	if s.OutputDir != "." || s.NetblockLimit != 4096 {
		t.Errorf("output_dir=%q netblock_limit=%d", s.OutputDir, s.NetblockLimit)
	}
	if s.SensitivePaths != "" || s.Wordlist != "" {
		t.Errorf("file defaults should be empty (built-in): %q %q", s.SensitivePaths, s.Wordlist)
	}
}

// File < env < flag for a scalar and a list.
func TestPrecedence(t *testing.T) {
	clearEnv(t)
	cfg := writeFile(t, "concurrency: 2\nports: [80, 443]\n")

	s, err := load(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.Concurrency != 2 || config.FormatPorts(s.Ports) != "80,443" {
		t.Fatalf("file: %d %v", s.Concurrency, s.Ports)
	}

	t.Setenv("RECON_CONCURRENCY", "3")
	t.Setenv("RECON_PORTS", "8080,8081")
	s, err = load(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.Concurrency != 3 || config.FormatPorts(s.Ports) != "8080-8081" {
		t.Fatalf("env: %d %v", s.Concurrency, s.Ports)
	}

	s, err = load(t, cfg, "--concurrency", "7", "--ports", "9000,9001-9003")
	if err != nil {
		t.Fatal(err)
	}
	if s.Concurrency != 7 || config.FormatPorts(s.Ports) != "9000-9003" {
		t.Fatalf("flag: %d %v", s.Concurrency, s.Ports)
	}
}

func TestNestedSettings(t *testing.T) {
	clearEnv(t)
	cfg := writeFile(t, "rate:\n  per_host: 2\ncrawl:\n  max_depth: 4\n")
	t.Setenv("RECON_RATE_DNS", "10")
	s, err := load(t, cfg, "--crawl-pages", "7")
	if err != nil {
		t.Fatal(err)
	}
	if s.Rate.PerHost != 2 || s.Rate.DNS != 10 || s.Crawl.MaxDepth != 4 || s.Crawl.MaxPages != 7 {
		t.Fatalf("%+v %+v", s.Rate, s.Crawl)
	}
}

// Keys from file and env only; never a flag; never formatted.
func TestKeys(t *testing.T) {
	clearEnv(t)
	cfg := writeFile(t, "keys:\n  shodan: filesecret123\n")
	t.Setenv("RECON_KEYS_CENSYS", "envsecret456")
	s, err := load(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.Keys["shodan"].Reveal() != "filesecret123" || s.Keys["censys"].Reveal() != "envsecret456" {
		t.Fatalf("keys not loaded: %v", s.Keys)
	}
	for _, out := range []string{
		fmt.Sprintf("%v", s.Keys["shodan"]), fmt.Sprintf("%s", s.Keys["shodan"]),
		fmt.Sprintf("%+v", s), fmt.Sprintf("%#v", s), fmt.Sprint(s.Keys),
	} {
		if strings.Contains(out, "secret") {
			t.Errorf("secret leaked in %q", out)
		}
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "secret") {
		t.Errorf("secret leaked in JSON %s", b)
	}
	kv := s.KeyValues()
	if len(kv) != 2 {
		t.Errorf("KeyValues = %v", kv)
	}

	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	config.RegisterFlags(fs)
	fs.VisitAll(func(f *pflag.Flag) {
		if strings.Contains(f.Name, "key") {
			t.Errorf("flag --%s exists; keys must not be settable by flag", f.Name)
		}
	})
}

// Invalid config values name the key and the value.
func TestValidation(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	relPaths := filepath.Join(dir, "rel.yaml")
	if err := os.WriteFile(relPaths, []byte("- path: /ok\n  signature: x\n- path: admin/.env\n  signature: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, file string
		env        map[string]string
		args       []string
		wantKey    string
		wantVal    string
	}{
		{"port high", "ports: [70000]\n", nil, nil, "ports", "70000"},
		{"port zero flag", "", nil, []string{"--ports", "0"}, "ports", "0"},
		{"port range reversed", "", nil, []string{"--ports", "90-80"}, "ports", "90-80"},
		{"risky port", "", nil, []string{"--risky-ports", "99999"}, "risky_ports", "99999"},
		{"concurrency zero", "concurrency: 0\n", nil, nil, "concurrency", "0"},
		{"concurrency env text", "", map[string]string{"RECON_CONCURRENCY": "lots"}, nil, "concurrency", "lots"},
		{"rate negative", "", nil, []string{"--rate-per-host", "-1"}, "rate.per_host", "-1"},
		{"rate dns zero", "rate:\n  dns: 0\n", nil, nil, "rate.dns", "0"},
		{"unknown key", "concurency: 3\n", nil, nil, "concurency", "concurency"},
		{"unreadable wordlist", "", nil, []string{"--wordlist", filepath.Join(dir, "nope.txt")}, "wordlist", "nope.txt"},
		{"wordlist is a directory", "", nil, []string{"--wordlist", dir}, "wordlist", dir},
		{"unreadable paths", "", nil, []string{"--sensitive-paths", filepath.Join(dir, "nope.yaml")}, "sensitive_paths", "nope.yaml"},
		{"relative sensitive path", "", nil, []string{"--sensitive-paths", relPaths}, "sensitive_paths", "admin/.env"},
		{"crawl depth negative", "", nil, []string{"--crawl-depth", "-2"}, "crawl.max_depth", "-2"},
		{"netblock zero", "", nil, []string{"--netblock-limit", "0"}, "netblock_limit", "0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clearEnv(t)
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			cfg := ""
			if c.file != "" {
				cfg = writeFile(t, c.file)
			}
			_, err := load(t, cfg, c.args...)
			if err == nil {
				t.Fatal("want error")
			}
			if !strings.Contains(err.Error(), c.wantKey) || !strings.Contains(err.Error(), c.wantVal) {
				t.Errorf("error %q should name %q and %q", err, c.wantKey, c.wantVal)
			}
		})
	}
}

func TestExplicitConfigMissing(t *testing.T) {
	clearEnv(t)
	if _, err := load(t, filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Fatal("explicit missing config file should be an error")
	}
}

func TestDefaultConfigPath(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/xdg")
	if got := config.DefaultConfigPath(); got != "/xdg/recon/config.yaml" {
		t.Errorf("got %s", got)
	}
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "/home/u")
	if got := config.DefaultConfigPath(); got != "/home/u/.config/recon/config.yaml" {
		t.Errorf("got %s", got)
	}
}

func TestDefaultConfigPathWithoutHome(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	if got := config.DefaultConfigPath(); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestLoadWithoutHomeIgnoresWorkingDirectoryConfig(t *testing.T) {
	clearEnv(t)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".config", "recon"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".config", "recon", "config.yaml"), []byte("not: [valid"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	if _, err := load(t, ""); err != nil {
		t.Fatalf("config under the working directory should not be read: %v", err)
	}
}

func TestPortsRoundTrip(t *testing.T) {
	p, err := config.ParsePorts("443, 21-23,80,22")
	if err != nil {
		t.Fatal(err)
	}
	if got := config.FormatPorts(p); got != "21-23,80,443" {
		t.Errorf("got %s", got)
	}
}

func TestRedactor(t *testing.T) {
	r := config.NewRedactor("s3cr3t", "")
	if got := r.Redact("url?key=s3cr3t&x=s3cr3t"); got != "url?key=****&x=****" {
		t.Errorf("got %q", got)
	}
	m := r.Any(map[string]any{"a": "s3cr3t", "b": []any{"x s3cr3t"}, "c": 3}).(map[string]any)
	if m["a"] != "****" || m["b"].([]any)[0] != "x ****" || m["c"] != 3 {
		t.Errorf("got %v", m)
	}
	// net/http errors embed query-parameter keys percent-encoded.
	enc := config.NewRedactor("abc+def/ghi=")
	if got := enc.Redact(`Get "https://h/?key=abc%2Bdef%2Fghi%3D": timeout`); got != `Get "https://h/?key=****": timeout` {
		t.Errorf("got %q", got)
	}
	var nilR *config.Redactor
	if nilR.Redact("x") != "x" {
		t.Error("nil redactor must pass through")
	}
}

func newFlagSetForHelp() *pflag.FlagSet {
	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	config.RegisterFlags(fs)
	return fs
}

// A leading ~ in a path setting is the home directory, not a directory named "~".
func TestHomeExpansion(t *testing.T) {
	clearEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg := writeFile(t, "output_dir: ~/engagements\n")
	s, err := load(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, "engagements"); s.OutputDir != want {
		t.Errorf("output_dir = %q, want %q", s.OutputDir, want)
	}
	for _, c := range []struct{ in, want string }{
		{"~", home}, {"./~/x", "./~/x"}, {"~other/x", "~other/x"},
	} {
		s, err := load(t, "", "--output-dir="+c.in)
		if err != nil {
			t.Fatal(err)
		}
		if s.OutputDir != c.want {
			t.Errorf("--output-dir=%s: got %q, want %q", c.in, s.OutputDir, c.want)
		}
	}
}
