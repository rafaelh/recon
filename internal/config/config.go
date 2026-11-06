// Package config loads and validates recon settings from a YAML file,
// environment variables and flags (file < env < flag).
package config

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"

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

// Archive holds the limits on URLs taken from public archives.
type Archive struct{ MaxURLs int }

// Permutations holds the subdomain-permutation settings.
type Permutations struct {
	Enabled    bool
	MaxPerSeed int
}

// Storage holds the cloud-storage settings.
type Storage struct {
	// MaxNames caps the bucket names guessed per root and per organisation.
	MaxNames int
}

// Settings are the validated settings for a run.
type Settings struct {
	Keys                 map[string]Secret
	Ports                []int
	RiskyPorts           []int
	SensitivePaths       string // file path; empty means the built-in list
	SensitivePathEntries []SensitivePath
	Wordlist             string // file path; empty means the built-in list
	// WordlistWords is the parsed list from Wordlist (or the built-in list) and
	// WordlistHash identifies its content, so a changed list creates new checks.
	WordlistWords []string
	WordlistHash  string
	Permutations  Permutations
	Concurrency   int
	// PortConcurrency is the number of workers of the ports stage, which is
	// slow per check (a silent port costs the connect timeout) and so needs more.
	PortConcurrency int
	Rate            Rate
	Crawl           Crawl
	Archive         Archive
	Storage         Storage
	// CertExpiryDays is how many days ahead a certificate expiry is reported.
	CertExpiryDays int
	OutputDir      string
	NetblockLimit  int // IPv4 addresses
}

// Defaults returns the default settings.
func Defaults() Settings {
	return Settings{
		Keys:            map[string]Secret{},
		Ports:           DefaultPorts(),
		RiskyPorts:      append([]int(nil), defaultRisky...),
		Concurrency:     10,
		PortConcurrency: 100,
		Rate:            Rate{PerHost: 5, PerSource: 1, DNS: 50},
		Crawl:           Crawl{MaxDepth: 2, MaxPages: 100},
		Archive:         Archive{MaxURLs: 20000},
		Storage:         Storage{MaxNames: 50},
		CertExpiryDays:  30,
		OutputDir:       ".",
		NetblockLimit:   4096,
		Permutations:    Permutations{Enabled: true, MaxPerSeed: 200},
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

func builtinWordlist() []string {
	b, _ := builtin.ReadFile("builtin/wordlist.txt")
	list, _ := input.ParseList(bytes.NewReader(b))
	return list
}

// BuiltinWordlistLabel is "built-in (N entries)".
func BuiltinWordlistLabel() string {
	return fmt.Sprintf("built-in (%d entries)", len(builtinWordlist()))
}

// BuiltinSensitivePathsLabel is "built-in (N entries)".
func BuiltinSensitivePathsLabel() string {
	return fmt.Sprintf("built-in (%d entries)", len(builtinSensitivePaths()))
}

// dkimSelectors are the DKIM selectors looked up for every root.
var dkimSelectors = []string{"google", "selector1", "selector2", "k1", "k2", "k3", "default", "dkim", "mail", "s1", "s2", "smtp", "mandrill", "mxvault", "everlytickey1", "everlytickey2", "zendesk1", "zendesk2", "cm", "sig1", "scph1", "mte1"}

// DKIMSelectors are the selectors the email stage looks up.
func DKIMSelectors() []string { return slices.Clone(dkimSelectors) }

// DKIMSelectorHash identifies the selector list, so a changed list creates new email checks.
func DKIMSelectorHash() string {
	sum := sha256.Sum256([]byte(strings.Join(dkimSelectors, ",")))
	return hex.EncodeToString(sum[:4])
}

func builtinSensitivePaths() []SensitivePath {
	b, _ := builtin.ReadFile("builtin/sensitive_paths.yaml")
	list, err := parseSensitivePaths(b)
	if err != nil {
		panic("config: built-in sensitive_paths.yaml: " + err.Error())
	}
	return list
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
	{"wordlist", "wordlist"}, {"concurrency", "concurrency"}, {"port-concurrency", "port_concurrency"}, {"rate-per-host", "rate.per_host"},
	{"rate-per-source", "rate.per_source"}, {"rate-dns", "rate.dns"}, {"crawl-depth", "crawl.max_depth"},
	{"crawl-pages", "crawl.max_pages"}, {"output-dir", "output_dir"}, {"netblock-limit", "netblock_limit"},
	{"permutations-max", "permutations.max_per_seed"}, {"archive-max-urls", "archive.max_urls"},
	{"storage-max-names", "storage.max_names"}, {"cert-expiry-days", "cert_expiry_days"},
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
	fs.Int("concurrency", d.Concurrency, "workers per stage (ports: --port-concurrency)")
	fs.Int("port-concurrency", d.PortConcurrency, "workers for the port sweep, whose silent ports each wait out the connect timeout")
	fs.Float64("rate-per-host", d.Rate.PerHost, "requests per second per dialled target IP (HTTP requests and TCP connects)")
	fs.Float64("rate-per-source", d.Rate.PerSource, "requests per second per third-party source")
	fs.Float64("rate-dns", d.Rate.DNS, "DNS queries per second in total across public resolvers")
	fs.Int("crawl-depth", d.Crawl.MaxDepth, "maximum crawl depth")
	fs.Int("crawl-pages", d.Crawl.MaxPages, "maximum pages crawled per web service (0 disables the crawl)")
	fs.Int("archive-max-urls", d.Archive.MaxURLs, "maximum archived URLs recorded per root from Wayback and Common Crawl")
	fs.Int("storage-max-names", d.Storage.MaxNames, "cloud-storage bucket names guessed per root and per organisation (checked on AWS, Azure and GCP)")
	fs.Int("cert-expiry-days", d.CertExpiryDays, "report certificates that expire within this many days")
	fs.String("output-dir", d.OutputDir, "directory in which engagement directories are created")
	fs.Bool("no-permutations", false, "do not resolve permutations of discovered subdomain labels (default: on, including with --passive)")
	fs.Int("permutations-max", d.Permutations.MaxPerSeed, "maximum permutations generated per discovered subdomain label")
	fs.Int("netblock-limit", d.NetblockLimit, "IPv4 address count above which the run stops unless --allow-large-netblocks is given")
}

type rawSettings struct {
	Keys            map[string]string `mapstructure:"keys"`
	Ports           []string          `mapstructure:"ports"`
	RiskyPorts      []string          `mapstructure:"risky_ports"`
	SensitivePaths  string            `mapstructure:"sensitive_paths"`
	Wordlist        string            `mapstructure:"wordlist"`
	Concurrency     string            `mapstructure:"concurrency"`
	PortConcurrency string            `mapstructure:"port_concurrency"`
	Rate            struct {
		PerHost   string `mapstructure:"per_host"`
		PerSource string `mapstructure:"per_source"`
		DNS       string `mapstructure:"dns"`
	} `mapstructure:"rate"`
	Crawl struct {
		MaxDepth string `mapstructure:"max_depth"`
		MaxPages string `mapstructure:"max_pages"`
	} `mapstructure:"crawl"`
	Archive struct {
		MaxURLs string `mapstructure:"max_urls"`
	} `mapstructure:"archive"`
	Storage struct {
		MaxNames string `mapstructure:"max_names"`
	} `mapstructure:"storage"`
	CertExpiryDays string `mapstructure:"cert_expiry_days"`
	OutputDir      string `mapstructure:"output_dir"`
	NetblockLimit  string `mapstructure:"netblock_limit"`
	Permutations   struct {
		Enabled    string `mapstructure:"enabled"`
		MaxPerSeed string `mapstructure:"max_per_seed"`
	} `mapstructure:"permutations"`
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
		"port_concurrency": d.PortConcurrency,
		"rate.per_host":    d.Rate.PerHost, "rate.per_source": d.Rate.PerSource, "rate.dns": d.Rate.DNS,
		"crawl.max_depth": d.Crawl.MaxDepth, "crawl.max_pages": d.Crawl.MaxPages, "archive.max_urls": d.Archive.MaxURLs,
		"output_dir": d.OutputDir, "netblock_limit": d.NetblockLimit,
		"storage.max_names": d.Storage.MaxNames, "cert_expiry_days": d.CertExpiryDays,
		"permutations.enabled": d.Permutations.Enabled, "permutations.max_per_seed": d.Permutations.MaxPerSeed,
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
	posInt("port_concurrency", raw.PortConcurrency, 1, &s.PortConcurrency)
	posFloat("rate.per_host", raw.Rate.PerHost, &s.Rate.PerHost)
	posFloat("rate.per_source", raw.Rate.PerSource, &s.Rate.PerSource)
	posFloat("rate.dns", raw.Rate.DNS, &s.Rate.DNS)
	posInt("crawl.max_depth", raw.Crawl.MaxDepth, 0, &s.Crawl.MaxDepth)
	posInt("crawl.max_pages", raw.Crawl.MaxPages, 0, &s.Crawl.MaxPages)
	posInt("archive.max_urls", raw.Archive.MaxURLs, 1, &s.Archive.MaxURLs)
	posInt("netblock_limit", raw.NetblockLimit, 1, &s.NetblockLimit)
	posInt("storage.max_names", raw.Storage.MaxNames, 1, &s.Storage.MaxNames)
	posInt("cert_expiry_days", raw.CertExpiryDays, 0, &s.CertExpiryDays)
	posInt("permutations.max_per_seed", raw.Permutations.MaxPerSeed, 1, &s.Permutations.MaxPerSeed)
	if enabled, err := strconv.ParseBool(strings.TrimSpace(raw.Permutations.Enabled)); err != nil {
		bad("permutations.enabled", raw.Permutations.Enabled, "not true or false")
	} else {
		s.Permutations.Enabled = enabled
	}
	if fs != nil {
		if f := fs.Lookup("no-permutations"); f != nil && f.Changed && f.Value.String() == "true" {
			s.Permutations.Enabled = false
		}
	}
	s.OutputDir = raw.OutputDir
	if s.OutputDir == "" {
		bad("output_dir", "", "must not be empty")
	}
	s.Wordlist, s.SensitivePaths = raw.Wordlist, raw.SensitivePaths
	if s.Wordlist != "" {
		if f, err := os.Open(s.Wordlist); err != nil {
			bad("wordlist", s.Wordlist, "cannot read file: "+errText(err))
		} else {
			if s.WordlistWords, err = input.ParseList(f); err != nil {
				bad("wordlist", s.Wordlist, "cannot read file: "+errText(err))
			}
			f.Close()
		}
	} else {
		s.WordlistWords = builtinWordlist()
	}
	sum := sha256.Sum256([]byte(strings.Join(s.WordlistWords, "\n")))
	s.WordlistHash = hex.EncodeToString(sum[:6])
	s.SensitivePathEntries = builtinSensitivePaths()
	if s.SensitivePaths != "" {
		b, err := os.ReadFile(s.SensitivePaths)
		if err != nil {
			bad("sensitive_paths", s.SensitivePaths, "cannot read file: "+errText(err))
		} else if s.SensitivePathEntries, err = parseSensitivePaths(b); err != nil {
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
