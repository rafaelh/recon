package config_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/rafaelh/recon/internal/config"
)

// Every default risky port is scanned by default.
func TestDefaultPortsCoverRiskyPorts(t *testing.T) {
	clearEnv(t)
	s, err := load(t, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range s.RiskyPorts {
		if !slices.Contains(s.Ports, p) {
			t.Errorf("risky port %d is not in the default scan list", p)
		}
	}
}

// port_concurrency, default 100, > 0, from flag, env or file.
func TestPortConcurrency(t *testing.T) {
	clearEnv(t)
	s, err := load(t, "")
	if err != nil {
		t.Fatal(err)
	}
	if s.PortConcurrency != 100 {
		t.Errorf("default port concurrency = %d, want 100", s.PortConcurrency)
	}
	if s.Concurrency != 10 {
		t.Errorf("concurrency = %d, want 10 (unchanged)", s.Concurrency)
	}
	if s, err = load(t, "", "--port-concurrency", "7"); err != nil || s.PortConcurrency != 7 {
		t.Errorf("flag: %d, %v", s.PortConcurrency, err)
	}
	if s, err = load(t, writeFile(t, "port_concurrency: 33\n")); err != nil || s.PortConcurrency != 33 {
		t.Errorf("file: %d, %v", s.PortConcurrency, err)
	}
	t.Setenv("RECON_PORT_CONCURRENCY", "44")
	if s, err = load(t, ""); err != nil || s.PortConcurrency != 44 {
		t.Errorf("env: %d, %v", s.PortConcurrency, err)
	}
	t.Setenv("RECON_PORT_CONCURRENCY", "")
	for _, bad := range []string{"0", "-3"} {
		if _, err := load(t, "", "--port-concurrency", bad); err == nil || !strings.Contains(err.Error(), "port_concurrency") {
			t.Errorf("--port-concurrency %s: err = %v, want an error naming port_concurrency", bad, err)
		}
	}
	if _, err := load(t, writeFile(t, "port_concurrency: many\n")); err == nil || !strings.Contains(err.Error(), "port_concurrency") {
		t.Errorf("non-integer: err = %v", err)
	}
}

// Both flags are in --help, and --concurrency says it does not bound the port sweep.
func TestPortConcurrencyHelp(t *testing.T) {
	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	config.RegisterFlags(fs)
	pc := fs.Lookup("port-concurrency")
	if pc == nil || pc.DefValue != "100" {
		t.Fatalf("--port-concurrency = %+v", pc)
	}
	if c := fs.Lookup("concurrency"); c == nil || c.Usage != "workers per stage (ports: --port-concurrency)" {
		t.Errorf("--concurrency usage = %+v", c)
	}
}
