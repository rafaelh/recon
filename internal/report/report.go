// Package report turns run events into console lines or JSON lines.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/rafaelh/recon/internal/config"
	"github.com/rafaelh/recon/internal/sanitize"
)

// Event is one thing that happened in a run. Types: run_start, stage, found,
// count, warning, error, summary, run_end.
type Event struct {
	Type   string
	Time   string // RFC 3339; filled in by the emitter if empty
	Fields map[string]any
}

// Emitter receives events. Implementations are safe for concurrent use.
type Emitter interface{ Emit(Event) }

func timestamp(ev Event, clock func() time.Time) string {
	if ev.Time != "" {
		return ev.Time
	}
	if clock == nil {
		clock = time.Now
	}
	return clock().UTC().Format(time.RFC3339)
}

// JSONEmitter writes one JSON object per line.
type JSONEmitter struct {
	mu    sync.Mutex
	w     io.Writer
	clock func() time.Time
}

// NewJSON returns the JSON renderer.
func NewJSON(w io.Writer, clock func() time.Time) *JSONEmitter {
	return &JSONEmitter{w: w, clock: clock}
}

// Emit writes the event as a JSON line.
func (j *JSONEmitter) Emit(ev Event) {
	m := make(map[string]any, len(ev.Fields)+2)
	for k, v := range ev.Fields {
		m[k] = v
	}
	m["type"], m["time"] = ev.Type, timestamp(ev, j.clock)
	b, err := json.Marshal(m)
	if err != nil {
		b, _ = json.Marshal(map[string]any{"type": "warning", "time": m["time"], "message": "cannot encode " + ev.Type + " event"})
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	_, _ = j.w.Write(append(b, '\n')) // Emit cannot report a write failure
}

type redacting struct {
	next Emitter
	r    *config.Redactor
}

// WithRedactor scrubs every string in each event before it reaches next.
func WithRedactor(next Emitter, r *config.Redactor) Emitter { return redacting{next, r} }

func (e redacting) Emit(ev Event) {
	if ev.Fields != nil {
		ev.Fields = e.r.Any(ev.Fields).(map[string]any)
	}
	e.next.Emit(ev)
}

// Console renders events as lipgloss-styled lines. Prompts and fatal errors go
// to the error writer when one is set.
type Console struct {
	mu    sync.Mutex
	w, ew io.Writer
	clock func() time.Time
	r     *lipgloss.Renderer
}

// NewConsole returns the console renderer; style=false disables all styling.
func NewConsole(w io.Writer, style bool, clock func() time.Time) *Console {
	r := lipgloss.NewRenderer(w)
	if style {
		r.SetColorProfile(termenv.ANSI)
	} else {
		r.SetColorProfile(termenv.Ascii)
	}
	return &Console{w: w, ew: w, clock: clock, r: r}
}

// WithErr sends error events to ew (normally stderr).
func (c *Console) WithErr(ew io.Writer) *Console { c.ew = ew; return c }

func (c *Console) st(color string, bold bool) lipgloss.Style {
	s := c.r.NewStyle().Bold(bold)
	if color != "" {
		s = s.Foreground(lipgloss.Color(color))
	}
	return s
}

func str(f map[string]any, k string) string {
	switch v := f[k].(type) {
	case nil:
		return ""
	case string:
		return sanitize.Text(v)
	default:
		return sanitize.Text(fmt.Sprint(v))
	}
}

func severityColor(sev string) string {
	switch sev {
	case "high":
		return "1"
	case "medium":
		return "3"
	}
	return "4"
}

// Emit renders one event.
func (c *Console) Emit(ev Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f := ev.Fields
	var b strings.Builder
	out := c.w
	switch ev.Type {
	case "run_start":
		b.WriteString(c.st("6", true).Render("recon") + " " + str(f, "engagement"))
		if s := str(f, "scope"); s != "" {
			b.WriteString("  " + s)
		}
		if p, _ := f["passive"].(bool); p {
			b.WriteString("  " + c.st("3", false).Render("[passive-only]"))
		}
		if a, _ := f["authorised"].(bool); a {
			b.WriteString("  " + c.st("2", false).Render("[authorised]"))
		}
	case "stage":
		state := str(f, "state")
		color := map[string]string{"done": "2", "done-previously": "8", "running": "6", "failed": "1", "not-configured": "3"}[state]
		line := c.st("", true).Render(fmt.Sprintf("%-14s", str(f, "name"))) + " " + c.st(color, false).Render(state)
		if r := str(f, "reason"); r != "" {
			line += " (" + r + ")"
		}
		if state == "done" {
			line += fmt.Sprintf(" (%s checks, %s failed)", str(f, "checks"), str(f, "failed"))
		}
		b.WriteString(line)
	case "found":
		line := c.st("2", false).Render("+") + " " + str(f, "category") + ": " + str(f, "value")
		if sev := str(f, "severity"); sev != "" {
			line += " " + c.st(severityColor(sev), true).Render("["+sev+"]")
		}
		b.WriteString(line)
	case "count":
		b.WriteString("  " + c.st("8", false).Render(fmt.Sprintf("%s: %s", str(f, "category"), str(f, "n"))))
	case "warning":
		b.WriteString(c.st("3", false).Render("warning:") + " " + str(f, "message"))
	case "error":
		out = c.ew
		b.WriteString(c.st("1", true).Render("error:") + " " + str(f, "message"))
	case "summary":
		c.summary(&b, f)
	default: // run_end and unknown events print nothing on the console
		return
	}
	fmt.Fprintln(out, b.String())
}

func (c *Console) summary(b *strings.Builder, f map[string]any) {
	b.WriteString(c.st("6", true).Render("Summary"))
	if totals, ok := f["totals"].(map[string]int); ok {
		for _, k := range sortedKeys(totals) {
			fmt.Fprintf(b, "\n  %-16s %d", sanitize.Text(k), totals[k])
		}
	}
	if failed, ok := f["failed"].(map[string]int); ok && len(failed) > 0 {
		b.WriteString("\n" + c.st("3", true).Render("Failed checks (retried on the next run)"))
		for _, k := range sortedKeys(failed) {
			fmt.Fprintf(b, "\n  %-16s %d", sanitize.Text(k), failed[k])
		}
	}
	if fs, ok := f["findings"].([]map[string]any); ok && len(fs) > 0 {
		b.WriteString("\n" + c.st("1", true).Render("Findings (high and medium)"))
		for _, x := range fs {
			sev := str(x, "severity")
			fmt.Fprintf(b, "\n  %s %s %s", c.st(severityColor(sev), true).Render("["+sev+"]"), str(x, "category"), str(x, "target"))
			if d := str(x, "detail"); d != "" {
				b.WriteString(" - " + d)
			}
		}
	}
}

func sortedKeys(m map[string]int) []string { return slices.Sorted(maps.Keys(m)) }
