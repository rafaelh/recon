package store_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rafaelh/recon/internal/config"
	"github.com/rafaelh/recon/internal/store"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func open(t *testing.T, c *clock, r *config.Redactor) (*store.Store, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "state.db")
	s, err := store.Open(p, store.Options{Clock: c.now, Redactor: r})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, p
}

func newClock() *clock { return &clock{t: time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)} }

func mustFlush(t *testing.T, s *store.Store) {
	t.Helper()
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
}

func rec(t *testing.T, s *store.Store, kind, key string) store.Record {
	t.Helper()
	rs, err := s.Records(kind, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.Key == key {
			return r
		}
	}
	t.Fatalf("record %s/%s not found in %v", kind, key, rs)
	return store.Record{}
}

// B9: re-observation updates attrs and last_seen, keeps first_seen.
func TestReobservation(t *testing.T) {
	c := newClock()
	s, _ := open(t, c, nil)
	s.Complete("dns", "a", []store.Obs{{Kind: "host", Key: "h1", Attrs: map[string]any{"ip": "1.1.1.1"}}})
	mustFlush(t, s)
	r := rec(t, s, "host", "h1")
	if r.FirstSeen != "2026-11-01" || r.LastSeen != "2026-11-01" || !r.Current {
		t.Fatalf("first observation: %+v", r)
	}

	c.advance(48 * time.Hour)
	s.Complete("dns", "b", []store.Obs{{Kind: "host", Key: "h1", Attrs: map[string]any{"ip": "2.2.2.2"}}})
	mustFlush(t, s)
	r = rec(t, s, "host", "h1")
	if r.FirstSeen != "2026-11-01" || r.LastSeen != "2026-11-03" {
		t.Errorf("dates: %+v", r)
	}
}

// B9: two stages observing one record keep both stages' attrs; later stages in order win.
func TestTwoStagesAttrs(t *testing.T) {
	c := newClock()
	s, _ := open(t, c, nil)
	s.Complete("ct", "c1", []store.Obs{{Kind: "host", Key: "h", Attrs: map[string]any{"src": "ct", "only_ct": 1}}})
	s.Complete("archive", "a1", []store.Obs{{Kind: "host", Key: "h", Attrs: map[string]any{"src": "archive", "only_ar": 2}}})
	mustFlush(t, s)

	rs, _ := s.Records("host", []string{"ct", "archive"})
	r := rs[0]
	if r.Attrs["src"] != "archive" || r.Attrs["only_ct"] == nil || r.Attrs["only_ar"] == nil {
		t.Errorf("merged attrs = %v", r.Attrs)
	}
	rs, _ = s.Records("host", []string{"archive", "ct"})
	if rs[0].Attrs["src"] != "ct" {
		t.Errorf("order must decide: %v", rs[0].Attrs)
	}
	if strings.Join(rs[0].Stages, ",") != "archive,ct" {
		t.Errorf("stages = %v", rs[0].Stages)
	}

	// Redo of ct (check re-performed, no longer observed) leaves archive's attrs and currency.
	if err := s.Redo("ct"); err != nil {
		t.Fatal(err)
	}
	s.Complete("ct", "c1", nil)
	mustFlush(t, s)
	r = rec(t, s, "host", "h")
	if !r.Current || r.Attrs["src"] != "archive" || r.Attrs["only_ct"] != nil {
		t.Errorf("after ct redo: %+v", r)
	}
	// And when the last observer drops it, it goes not-current but stays.
	s.Complete("archive", "a1", nil)
	mustFlush(t, s)
	if r = rec(t, s, "host", "h"); r.Current {
		t.Errorf("should be not current: %+v", r)
	}
}

// B6/B8: completed checks vs failures.
func TestChecksAndFailures(t *testing.T) {
	c := newClock()
	s, _ := open(t, c, nil)
	s.Complete("s", "k1", nil)
	s.Fail("s", "k2", "timeout talking to host")
	mustFlush(t, s)
	done, err := s.Completed("s")
	if err != nil || len(done) != 1 || !hasKey(done, "k1") {
		t.Fatalf("completed = %v, %v", done, err)
	}
	fs, _ := s.Failures("s")
	if len(fs) != 1 || fs[0].Key != "k2" || fs[0].Error != "timeout talking to host" {
		t.Fatalf("failures = %v", fs)
	}
	s.Complete("s", "k2", nil) // success deletes the failure row
	mustFlush(t, s)
	if fs, _ = s.Failures("s"); len(fs) != 0 {
		t.Errorf("failure row should be deleted: %v", fs)
	}
}

func hasKey(m map[string]struct{}, k string) bool { _, ok := m[k]; return ok }

// B10: redo semantics.
func TestRedoSweepsOrphans(t *testing.T) {
	c := newClock()
	s, _ := open(t, c, nil)
	s.Complete("st", "ip1", []store.Obs{{Kind: "x", Key: "a"}})
	s.Complete("st", "ip2", []store.Obs{{Kind: "x", Key: "b"}})
	mustFlush(t, s)

	if err := s.Redo("st"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.PendingRedo(); len(got) != 1 || got[0] != "st" {
		t.Fatalf("pending redo = %v", got)
	}
	if done, _ := s.Completed("st"); len(done) != 0 {
		t.Fatalf("redo must clear checks: %v", done)
	}
	// ip1 is re-performed; ip2 is no longer produced by the stage.
	s.Complete("st", "ip1", []store.Obs{{Kind: "x", Key: "a"}})
	mustFlush(t, s)
	if err := s.FinishRedo("st", map[string]struct{}{"ip1": {}}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.PendingRedo(); len(got) != 0 {
		t.Errorf("marker not cleared: %v", got)
	}
	if !rec(t, s, "x", "a").Current || rec(t, s, "x", "b").Current {
		t.Error("orphaned observation should have been swept, making b not-current")
	}
}

func TestRedoFailedCheckKeepsObservations(t *testing.T) {
	c := newClock()
	s, _ := open(t, c, nil)
	s.Complete("st", "k", []store.Obs{{Kind: "x", Key: "a"}})
	mustFlush(t, s)
	s.Redo("st")
	s.Fail("st", "k", "boom")
	mustFlush(t, s)
	s.FinishRedo("st", map[string]struct{}{"k": {}})
	if !rec(t, s, "x", "a").Current {
		t.Error("a failed check keeps its old observations")
	}
}

// B7: batching commits and survives reopen; OnNew fires once per new record.
func TestBatchingAndOnNew(t *testing.T) {
	c := newClock()
	s, p := open(t, c, nil)
	var mu sync.Mutex
	var news []string
	s.OnNew(func(kind, key string, attrs map[string]any) {
		mu.Lock()
		defer mu.Unlock()
		news = append(news, kind+"/"+key)
	})
	for i := 0; i < 500; i++ {
		s.Complete("st", fmt.Sprintf("k%03d", i), []store.Obs{{Kind: "x", Key: fmt.Sprintf("r%03d", i%250)}})
	}
	mustFlush(t, s)
	if len(news) != 250 {
		t.Errorf("OnNew fired %d times, want 250", len(news))
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := store.Open(p, store.Options{Clock: c.now})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	done, _ := s2.Completed("st")
	if len(done) != 500 {
		t.Errorf("completed after reopen = %d", len(done))
	}
	rs, _ := s2.Records("x", nil)
	if len(rs) != 250 {
		t.Errorf("records = %d", len(rs))
	}
}

// B24: redaction at the writer sink.
func TestRedactionInStore(t *testing.T) {
	c := newClock()
	r := config.NewRedactor("TOPSECRET")
	s, p := open(t, c, r)
	s.Complete("st", "https://x/?k=TOPSECRET", []store.Obs{{Kind: "x", Key: "TOPSECRET-key", Attrs: map[string]any{"a": "v TOPSECRET", "n": []any{"TOPSECRET"}}}})
	s.Fail("st", "other", "GET https://x/?k=TOPSECRET failed")
	mustFlush(t, s)
	s.Close()
	rs, _ := mustOpenRecords(t, p)
	for _, r := range rs {
		if strings.Contains(fmt.Sprint(r), "TOPSECRET") {
			t.Errorf("leaked: %v", r)
		}
	}
	fs, _ := mustOpenFailures(t, p)
	if strings.Contains(fs[0].Error, "TOPSECRET") {
		t.Errorf("leaked failure: %v", fs)
	}
}

// A check key containing a key value is matched in its stored (redacted) form.
func TestRedactedCheckKeyMatches(t *testing.T) {
	s, _ := open(t, newClock(), config.NewRedactor("123"))
	s.Complete("st", "AS4123", nil)
	mustFlush(t, s)
	done, err := s.Completed("st")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := done[s.CheckKey("AS4123")]; !ok || len(done) != 1 {
		t.Errorf("completed = %v, CheckKey = %q", done, s.CheckKey("AS4123"))
	}
}

// URI metacharacters in the directory are part of the filename.
func TestOpenPathWithURIMetacharacters(t *testing.T) {
	p := filepath.Join(t.TempDir(), "client#1 ?50%", "state.db")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(p, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetMeta("k", "v"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Errorf("database not at %s: %v", p, err)
	}
}

// Sends racing Close are dropped, never a send on a closed channel.
func TestSendDuringClose(t *testing.T) {
	s, _ := open(t, newClock(), nil)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 200 {
				s.Complete("st", fmt.Sprintf("%d-%d", i, j), nil)
				s.Flush()
			}
		}()
	}
	s.Close()
	wg.Wait()
}

func mustOpenRecords(t *testing.T, p string) ([]store.Record, error) {
	s, err := store.Open(p, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	return s.Records("x", nil)
}

func mustOpenFailures(t *testing.T, p string) ([]store.Failure, error) {
	s, err := store.Open(p, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	return s.Failures("st")
}

func TestInputsAndMeta(t *testing.T) {
	c := newClock()
	s, _ := open(t, c, nil)
	added, err := s.AddInput("root", "example.com")
	if err != nil || !added {
		t.Fatal(added, err)
	}
	if added, _ = s.AddInput("root", "example.com"); added {
		t.Error("duplicate should not be added")
	}
	s.AddInput("cidr", "10.0.0.0/8")
	in, _ := s.Inputs()
	if len(in) != 2 || in[0].Kind != "cidr" || in[1].Value != "example.com" || in[1].AddedAt != "2026-11-01" {
		t.Errorf("inputs = %+v", in)
	}
	if _, ok := s.Meta("ack_at"); ok {
		t.Error("meta should be unset")
	}
	s.SetMeta("ack_at", "2026-11-01")
	if v, ok := s.Meta("ack_at"); !ok || v != "2026-11-01" {
		t.Errorf("meta = %q %v", v, ok)
	}
}

func TestObservationsOf(t *testing.T) {
	c := newClock()
	s, _ := open(t, c, nil)
	s.Complete("asn", "AS1", []store.Obs{{Kind: "netblock", Key: "10.0.0.0/24"}})
	s.Complete("other", "x", []store.Obs{{Kind: "netblock", Key: "10.9.0.0/24"}})
	mustFlush(t, s)
	obs, err := s.Observations("netblock", "asn")
	if err != nil || len(obs) != 1 || obs[0].Key != "10.0.0.0/24" || obs[0].CheckKey != "AS1" {
		t.Errorf("%v %v", obs, err)
	}
}

func TestOpenRejectsForeignDB(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.db")
	if err := writeGarbage(p); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open(p, store.Options{}); err == nil {
		t.Fatal("garbage file must not open")
	}
}
