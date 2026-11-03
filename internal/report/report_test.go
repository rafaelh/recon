package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/recon/internal/config"
	"github.com/rafaelh/recon/internal/report"
)

var clk = func() time.Time { return time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC) }

func TestSanitize(t *testing.T) {
	in := "ok\x1b[31m red\x1b]0;title\x07 \x00bell\x07 tab\there ‮ bidi"
	got := report.Sanitize(in)
	for _, bad := range []string{"\x1b", "\x07", "\x00"} {
		if strings.Contains(got, bad) {
			t.Errorf("%q survived in %q", bad, got)
		}
	}
	if !strings.Contains(got, "ok") || !strings.Contains(got, "red") {
		t.Errorf("visible text lost: %q", got)
	}
}

// B19: JSON mode is one object per line, unstyled, with type and RFC 3339 time.
func TestJSONRenderer(t *testing.T) {
	var buf bytes.Buffer
	em := report.NewJSON(&buf, clk)
	em.Emit(report.Event{Type: "found", Fields: map[string]any{"category": "host", "value": "a.example.com\x1b[31m"}})
	em.Emit(report.Event{Type: "count", Fields: map[string]any{"category": "host", "n": 1}})
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %q", lines)
	}
	for _, l := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not JSON: %q", l)
		}
		if m["type"] == nil {
			t.Errorf("no type: %q", l)
		}
		if _, err := time.Parse(time.RFC3339, m["time"].(string)); err != nil {
			t.Errorf("time: %v", err)
		}
	}
	if strings.Contains(buf.String(), "\x1b") {
		t.Error("escape in JSON output")
	}
}

// B19 + safety: console styling toggles, and target-supplied escapes never reach the terminal.
func TestConsoleStyling(t *testing.T) {
	ev := report.Event{Type: "found", Fields: map[string]any{"category": "finding", "value": "http://x/\x1b[2J evil\x1b]0;pwn\x07", "severity": "high"}}
	var plain, styled bytes.Buffer
	report.NewConsole(&plain, false, clk).Emit(ev)
	report.NewConsole(&styled, true, clk).Emit(ev)
	if strings.Contains(plain.String(), "\x1b") {
		t.Errorf("unstyled console contains ESC: %q", plain.String())
	}
	if !strings.Contains(styled.String(), "\x1b[") {
		t.Errorf("styled console should contain ANSI: %q", styled.String())
	}
	for _, s := range []string{plain.String(), styled.String()} {
		if strings.Contains(s, "[2J") && strings.Contains(s, "\x1b[2J") || strings.Contains(s, "\x07") || strings.Contains(s, "]0;pwn\x07") {
			t.Errorf("injected escape reached output: %q", s)
		}
	}
	if strings.Count(plain.String(), "\n") != 1 {
		t.Errorf("one event, one line: %q", plain.String())
	}
}

// B17: stage lines.
func TestConsoleStageLines(t *testing.T) {
	var buf bytes.Buffer
	c := report.NewConsole(&buf, false, clk)
	c.Emit(report.Event{Type: "stage", Fields: map[string]any{"name": "ports", "state": "not-configured", "reason": "passive-only"}})
	c.Emit(report.Event{Type: "stage", Fields: map[string]any{"name": "asn", "state": "done", "checks": 3, "failed": 1}})
	out := buf.String()
	for _, w := range []string{"ports", "not-configured", "passive-only", "asn", "done", "3", "1"} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in %q", w, out)
		}
	}
}

// B18: summary shows totals, failed counts, and each high/medium finding.
func TestConsoleSummary(t *testing.T) {
	var buf bytes.Buffer
	c := report.NewConsole(&buf, false, clk)
	c.Emit(report.Event{Type: "summary", Fields: map[string]any{
		"totals": map[string]int{"hosts": 12, "open ports": 5, "urls": 340},
		"failed": map[string]int{"asn": 2},
		"findings": []map[string]any{
			{"category": "exposed-admin", "severity": "high", "target": "https://a.example.com/admin", "detail": "login page"},
			{"category": "banner", "severity": "medium", "target": "10.0.0.1:21", "detail": "ftp"},
		},
	}})
	out := buf.String()
	for _, w := range []string{"hosts", "12", "open ports", "340", "asn", "2", "exposed-admin", "https://a.example.com/admin", "high", "10.0.0.1:21", "medium"} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in\n%s", w, out)
		}
	}
}

// B24: the redactor wrapper scrubs every string in an event, including nested ones.
func TestRedactingEmitter(t *testing.T) {
	var buf bytes.Buffer
	em := report.WithRedactor(report.NewJSON(&buf, clk), config.NewRedactor("SEKRET"))
	em.Emit(report.Event{Type: "warning", Fields: map[string]any{"message": "GET /?k=SEKRET failed", "extra": []map[string]any{{"x": "SEKRET"}}}})
	if strings.Contains(buf.String(), "SEKRET") {
		t.Errorf("leaked: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "****") {
		t.Errorf("expected mask: %s", buf.String())
	}
}
