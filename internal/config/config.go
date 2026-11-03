// Package config loads and validates recon settings from a YAML file,
// environment variables and flags (file < env < flag).
package config

import (
	"bytes"
	"embed"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.yaml.in/yaml/v3"

	"github.com/rafaelh/recon/internal/input"
)

//go:embed builtin/wordlist.txt builtin/sensitive_paths.yaml
var builtin embed.FS

// Rate holds the request-rate limits.
type Rate struct {
	PerHost   float64 // per dialled target IP
	PerSource float64 // per third-party source
	DNS       float64 // queries/s across the public resolvers
}

// Crawl holds the crawl limits.
type Crawl struct{ MaxDepth, MaxPages int }

// Settings are the validated settings for a run.
type Settings struct {
	Keys           map[string]Secret
	Ports          []int
	RiskyPorts     []int
	SensitivePaths string // file path; empty means the built-in list
	// SensitivePathList is the parsed list from SensitivePaths (or the built-in list).
	SensitivePathList []string
	Wordlist          string // file path; empty means the built-in list
	Concurrency       int
	Rate              Rate
	Crawl             Crawl
	OutputDir         string
	NetblockLimit     int // IPv4 addresses
}

// Defaults returns the default settings.
func Defaults() Settings {
	return Settings{
		Keys:          map[string]Secret{},
		Ports:         DefaultPorts(),
		RiskyPorts:    append([]int(nil), defaultRisky...),
		Concurrency:   10,
		Rate:          Rate{PerHost: 5, PerSource: 1, DNS: 50},
		Crawl:         Crawl{MaxDepth: 2, MaxPages: 100},
		OutputDir:     ".",
		NetblockLimit: 4096,
	}
}

// KeyValues returns the configured key values, for building a Redactor.
func (s Settings) KeyValues() []string {
	var out []string
	for _, n := range slices.Sorted(maps.Keys(s.Keys)) {
		out = append(out, s.Keys[n].Reveal())
	}
	return out
}

// BuiltinWordlistLabel is "built-in (N entries)".
func BuiltinWordlistLabel() string {
	b, _ := builtin.ReadFile("builtin/wordlist.txt")
	list, _ := input.ParseList(bytes.NewReader(b))
	return fmt.Sprintf("built-in (%d entries)", len(list))
}

// BuiltinSensitivePathsLabel is "built-in (N entries)".
func BuiltinSensitivePathsLabel() string {
	return fmt.Sprintf("built-in (%d entries)", len(builtinSensitivePaths()))
}

func builtinSensitivePaths() []string {
	b, _ := builtin.ReadFile("builtin/sensitive_paths.yaml")
	list, _ := parseSensitivePaths(b)
	return list
}

// parseSensitivePaths reads a YAML list whose entries are a path or {path: ...}.
// Each path is appended to a service's origin, so it must be an absolute path.
func parseSensitivePaths(b []byte) ([]string, error) {
	var raw []any
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("not a valid YAML list: %w", err)
	}
	var out []string
	for _, e := range raw {
		var p string
		switch v := e.(type) {
		case string:
			p = v
		case map[string]any:
			var ok bool
			if p, ok = v["path"].(string); !ok {
				continue
			}
		default:
			continue
		}
		if _, err := url.ParseRequestURI(p); err != nil || !strings.HasPrefix(p, "/") {
			return nil, fmt.Errorf("entry %q is not a path starting with /", p)
		}
		out = append(out, p)
	}
	return out, nil
}

// DefaultConfigPath is $XDG_CONFIG_HOME/recon/config.yaml, or ~/.config/recon/config.yaml.
func DefaultConfigPath() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = filepath.Join(os.Getenv("HOME"), ".config")
	}
	return filepath.Join(base, "recon", "config.yaml")
}

// setting binds a flag to its config key.
type setting struct{ flag, key string }

var settingTable = []setting{
	{"ports", "ports"}, {"risky-ports", "risky_ports"}, {"sensitive-paths", "sensitive_paths"},
	{"wordlist", "wordlist"}, {"concurrency", "concurrency"}, {"rate-per-host", "rate.per_host"},
	{"rate-per-source", "rate.per_source"}, {"rate-dns", "rate.dns"}, {"crawl-depth", "crawl.max_depth"},
	{"crawl-pages", "crawl.max_pages"}, {"output-dir", "output_dir"}, {"netblock-limit", "netblock_limit"},
}

// RegisterFlags adds one flag per setting to fs. There is deliberately no flag for API keys.
func RegisterFlags(fs *pflag.FlagSet) {
	d := Defaults()
	portsRaw, riskyRaw := FormatPorts(d.Ports), FormatPorts(d.RiskyPorts)
	var pt, rt bool
	fs.Var(portsFlag{&portsRaw, &pt}, "ports", "TCP ports to check (comma-separated ports and ranges)")
	fs.Var(portsFlag{&riskyRaw, &rt}, "risky-ports", "ports whose being open is reported as a risk")
	fs.String("sensitive-paths", "", "YAML file of sensitive paths to request (default: "+BuiltinSensitivePathsLabel()+")")
	fs.String("wordlist", "", "subdomain wordlist file (default: "+BuiltinWordlistLabel()+")")
	fs.Int("concurrency", d.Concurrency, "workers per stage")
	fs.Float64("rate-per-host", d.Rate.PerHost, "requests per second per dialled target IP (HTTP requests and TCP connects)")
	fs.Float64("rate-per-source", d.Rate.PerSource, "requests per second per third-party source")
	fs.Float64("rate-dns", d.Rate.DNS, "DNS queries per second in total across public resolvers")
	fs.Int("crawl-depth", d.Crawl.MaxDepth, "maximum crawl depth")
	fs.Int("crawl-pages", d.Crawl.MaxPages, "maximum pages crawled per web service")
	fs.String("output-dir", d.OutputDir, "directory in which engagement directories are created")
	fs.Int("netblock-limit", d.NetblockLimit, "IPv4 address count above which the run stops unless --allow-large-netblocks is given")
}

type rawSettings struct {
	Keys           map[string]string `mapstructure:"keys"`
	Ports          []string          `mapstructure:"ports"`
	RiskyPorts     []string          `mapstructure:"risky_ports"`
	SensitivePaths string            `mapstructure:"sensitive_paths"`
	Wordlist       string            `mapstructure:"wordlist"`
	Concurrency    string            `mapstructure:"concurrency"`
	Rate           struct {
		PerHost   string `mapstructure:"per_host"`
		PerSource string `mapstructure:"per_source"`
		DNS       string `mapstructure:"dns"`
	} `mapstructure:"rate"`
	Crawl struct {
		MaxDepth string `mapstructure:"max_depth"`
		MaxPages string `mapstructure:"max_pages"`
	} `mapstructure:"crawl"`
	OutputDir     string `mapstructure:"output_dir"`
	NetblockLimit string `mapstructure:"netblock_limit"`
}

// Load merges defaults, the config file, RECON_* environment variables and the
// flags in fs that were set (flags win over env, env over file). configPath
// "" means the default location, which is optional; an explicit path must exist.
func Load(fs *pflag.FlagSet, configPath string) (Settings, error) {
	d := Defaults()
	v := viper.New()
	v.SetEnvPrefix("RECON")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	defaults := map[string]any{
		"ports": FormatPorts(d.Ports), "risky_ports": FormatPorts(d.RiskyPorts),
		"sensitive_paths": "", "wordlist": "", "concurrency": d.Concurrency,
		"rate.per_host": d.Rate.PerHost, "rate.per_source": d.Rate.PerSource, "rate.dns": d.Rate.DNS,
		"crawl.max_depth": d.Crawl.MaxDepth, "crawl.max_pages": d.Crawl.MaxPages,
		"output_dir": d.OutputDir, "netblock_limit": d.NetblockLimit,
	}
	for k, val := range defaults {
		v.SetDefault(k, val)
	}

	path, explicit := configPath, configPath != ""
	if !explicit {
		path = DefaultConfigPath()
	}
	if _, err := os.Stat(path); err == nil || explicit {
		v.SetConfigFile(path)
		v.SetConfigType("yaml")
		if err := v.ReadInConfig(); err != nil {
			return Settings{}, fmt.Errorf("config file %s: %w", path, err)
		}
	}
	if fs != nil {
		for _, s := range settingTable {
			if f := fs.Lookup(s.flag); f != nil {
				if err := v.BindPFlag(s.key, f); err != nil {
					return Settings{}, err
				}
			}
		}
	}

	var raw rawSettings
	if err := v.UnmarshalExact(&raw); err != nil {
		return Settings{}, fmt.Errorf("config: %w", err)
	}

	s := d
	s.Keys = map[string]Secret{}
	for name, val := range raw.Keys {
		s.Keys[strings.ToLower(name)] = Secret(val)
	}
	for _, kv := range os.Environ() {
		name, val, _ := strings.Cut(kv, "=")
		if src, ok := strings.CutPrefix(name, "RECON_KEYS_"); ok && val != "" {
			s.Keys[strings.ToLower(src)] = Secret(val)
		}
	}

	var errs []string
	bad := func(key, val string, why string) {
		errs = append(errs, fmt.Sprintf("%s: invalid value %q: %s", key, val, why))
	}
	ports := func(key string, items []string, dst *[]int) {
		ps, err := parsePortItems(items)
		if err != nil {
			bad(key, strings.Join(items, ","), err.Error())
			return
		}
		*dst = ps
	}
	ports("ports", raw.Ports, &s.Ports)
	ports("risky_ports", raw.RiskyPorts, &s.RiskyPorts)
	posInt := func(key, val string, min int, dst *int) {
		n, err := strconv.Atoi(strings.TrimSpace(val))
		if err != nil {
			bad(key, val, "not an integer")
		} else if n < min {
			bad(key, val, fmt.Sprintf("must be at least %d", min))
		} else {
			*dst = n
		}
	}
	posFloat := func(key, val string, dst *float64) {
		f, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
		if err != nil {
			bad(key, val, "not a number")
		} else if f <= 0 {
			bad(key, val, "must be greater than 0")
		} else {
			*dst = f
		}
	}
	posInt("concurrency", raw.Concurrency, 1, &s.Concurrency)
	posFloat("rate.per_host", raw.Rate.PerHost, &s.Rate.PerHost)
	posFloat("rate.per_source", raw.Rate.PerSource, &s.Rate.PerSource)
	posFloat("rate.dns", raw.Rate.DNS, &s.Rate.DNS)
	posInt("crawl.max_depth", raw.Crawl.MaxDepth, 0, &s.Crawl.MaxDepth)
	posInt("crawl.max_pages", raw.Crawl.MaxPages, 0, &s.Crawl.MaxPages)
	posInt("netblock_limit", raw.NetblockLimit, 1, &s.NetblockLimit)
	s.OutputDir = raw.OutputDir
	if s.OutputDir == "" {
		bad("output_dir", "", "must not be empty")
	}
	s.Wordlist, s.SensitivePaths = raw.Wordlist, raw.SensitivePaths
	if s.Wordlist != "" {
		if f, err := os.Open(s.Wordlist); err != nil {
			bad("wordlist", s.Wordlist, "cannot read file: "+errText(err))
		} else {
			f.Close()
		}
	}
	s.SensitivePathList = builtinSensitivePaths()
	if s.SensitivePaths != "" {
		b, err := os.ReadFile(s.SensitivePaths)
		if err != nil {
			bad("sensitive_paths", s.SensitivePaths, "cannot read file: "+errText(err))
		} else if s.SensitivePathList, err = parseSensitivePaths(b); err != nil {
			bad("sensitive_paths", s.SensitivePaths, err.Error())
		}
	}
	if len(errs) > 0 {
		return Settings{}, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return s, nil
}

func errText(err error) string {
	if pe, ok := err.(*os.PathError); ok {
		return pe.Err.Error()
	}
	return err.Error()
}
