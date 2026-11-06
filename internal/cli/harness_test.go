package cli_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/rafaelh/recon/internal/cli"
	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/run"
)

// harness drives cli.Execute in-process with fakes.
type harness struct {
	t         *testing.T
	out       string
	stages    []run.Stage
	stdin     string
	stdinTTY  bool
	stdoutTTY bool
	eopts     egress.Options
	now       time.Time
	version   string

	stdout, stderr bytes.Buffer

	// Network canaries: anything reaching them means a request was made.
	udpHits, httpHits, tcpHits atomic.Int32
}

func newHarness(t *testing.T, stages ...run.Stage) *harness {
	t.Helper()
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "RECON_") {
			os.Unsetenv(strings.SplitN(kv, "=", 2)[0])
		}
	}
	cfgHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfgHome)
	t.Setenv("HOME", cfgHome)
	h := &harness{t: t, out: t.TempDir(), stages: stages, now: time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 512)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			h.udpHits.Add(1)
		}
	}()
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.httpHits.Add(1) }))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			h.tcpHits.Add(1)
			c.Close()
		}
	}()
	t.Cleanup(func() { pc.Close(); hs.Close(); ln.Close() })
	h.eopts = egress.Options{
		ResolverAddrs:  []string{pc.LocalAddr().String()},
		DNSTimeout:     200 * time.Millisecond,
		ConnectTimeout: 300 * time.Millisecond,
		BannerWait:     50 * time.Millisecond,
		HTTPTimeout:    time.Second,
	}
	return h
}

func (h *harness) deps() cli.Deps {
	return cli.Deps{
		Stages:      h.stages,
		Egress:      h.eopts,
		Stdin:       strings.NewReader(h.stdin),
		Stdout:      &h.stdout,
		Stderr:      &h.stderr,
		StdinIsTTY:  func() bool { return h.stdinTTY },
		StdoutIsTTY: func() bool { return h.stdoutTTY },
		Clock:       func() time.Time { return h.now },
		Version:     h.version,
	}
}

// exec runs recon with --output-dir pointing at the temp dir.
func (h *harness) exec(args ...string) int {
	return h.execCtx(context.Background(), args...)
}

func (h *harness) execCtx(ctx context.Context, args ...string) int {
	h.t.Helper()
	h.stdout.Reset()
	h.stderr.Reset()
	full := append([]string{"--output-dir", h.out}, args...)
	return cli.Execute(ctx, full, h.deps())
}

func (h *harness) network() int32 { return h.udpHits.Load() + h.httpHits.Load() + h.tcpHits.Load() }

func (h *harness) eng(name string) string { return filepath.Join(h.out, name) }

func (h *harness) readOut(name, file string) string {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join(h.out, name, file))
	if os.IsNotExist(err) {
		return "" // a file with no rows is not written
	}
	if err != nil {
		h.t.Fatal(err)
	}
	return string(b)
}

type event map[string]any

func (e event) str(k string) string { s, _ := e[k].(string); return s }
func (e event) num(k string) int    { f, _ := e[k].(float64); return int(f) }

// events parses stdout as JSON lines, failing on anything else.
func (h *harness) events() []event {
	h.t.Helper()
	var out []event
	for _, line := range strings.Split(strings.TrimSpace(h.stdout.String()), "\n") {
		if line == "" {
			continue
		}
		var e event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			h.t.Fatalf("stdout line is not JSON: %q (%v)", line, err)
		}
		out = append(out, e)
	}
	return out
}

func ofType(evs []event, typ string) []event {
	var out []event
	for _, e := range evs {
		if e.str("type") == typ {
			out = append(out, e)
		}
	}
	return out
}

func stageEvents(evs []event, name string) []event {
	var out []event
	for _, e := range ofType(evs, "stage") {
		if e.str("name") == name {
			out = append(out, e)
		}
	}
	return out
}

func lastState(evs []event, name string) event {
	se := stageEvents(evs, name)
	if len(se) == 0 {
		return nil
	}
	return se[len(se)-1]
}

func (h *harness) openDB(name string) *sql.DB {
	h.t.Helper()
	return openDB(h.t, filepath.Join(h.out, name, ".recon", "state.db"))
}

func openDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func queryStrings(t *testing.T, db *sql.DB, q string, args ...any) []string {
	t.Helper()
	rows, err := db.Query(q, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func (h *harness) inputs(name, kind string) []string {
	return queryStrings(h.t, h.openDB(name), "SELECT value FROM inputs WHERE kind=?", kind)
}

func (h *harness) completed(name, stage string) []string {
	return queryStrings(h.t, h.openDB(name), "SELECT key FROM checks WHERE stage=?", stage)
}

func (h *harness) meta(name, key string) (string, bool) {
	v := queryStrings(h.t, h.openDB(name), "SELECT value FROM meta WHERE key=?", key)
	if len(v) == 0 {
		return "", false
	}
	return v[0], true
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
