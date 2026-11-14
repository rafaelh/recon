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

// Re-observation updates attrs and last_seen, keeps first_seen.
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

// Two stages observing one record keep both stages' attrs; later stages in order win.
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

// Completed checks vs failures.
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

// Redo semantics.
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

// Retire forgets the checks a stage no longer yields, with their observations
// and failures, and leaves the other stages and the still-valid checks alone.
func TestRetireUnlistedChecks(t *testing.T) {
	c := newClock()
	s, _ := open(t, c, nil)
	s.Complete("st", "svc|fp=old", []store.Obs{{Kind: "x", Key: "a"}, {Kind: "x", Key: "shared"}})
	s.Complete("st", "svc|fp=new", []store.Obs{{Kind: "x", Key: "b"}})
	s.Complete("other", "svc|fp=old", []store.Obs{{Kind: "x", Key: "shared"}})
	s.Fail("st", "gone|fp=old", "boom")
	mustFlush(t, s)
	before := s.KindVersion("x")
	if err := s.Retire("st", map[string]struct{}{"svc|fp=new": {}}); err != nil {
		t.Fatal(err)
	}
	if rec(t, s, "x", "a").Current || !rec(t, s, "x", "b").Current {
		t.Error("the retired check's observation must stop being current; the valid one stays")
	}
	if !rec(t, s, "x", "shared").Current {
		t.Error("another stage's observation of the same record keeps it current")
	}
	if done, _ := s.Completed("st"); len(done) != 1 {
		t.Errorf("completed = %v, want only the valid check", done)
	}
	if done, _ := s.Completed("other"); len(done) != 1 {
		t.Errorf("another stage's checks were retired: %v", done)
	}
	if f, _ := s.Failures("st"); len(f) != 0 {
		t.Errorf("failures of an unlisted check = %v", f)
	}
	if s.KindVersion("x") == before {
		t.Error("retiring must bump the version of the kinds it changed")
	}
}

func TestRedoFailedCheckKeepsObservations(t *testing.T) {
	c := newClock()
	s, _ := open(t, c, nil)
	s.Complete("st", "k", []store.Obs{{Kind: "x", Key: "a"}})
	mustFlush(t, s)
	if err := s.Redo("st"); err != nil {
		t.Fatal(err)
	}
	s.Fail("st", "k", "boom")
	mustFlush(t, s)
	if err := s.FinishRedo("st", map[string]struct{}{"k": {}}); err != nil {
		t.Fatal(err)
	}
	if !rec(t, s, "x", "a").Current {
		t.Error("a failed check keeps its old observations")
	}
}

// Batching commits and survives reopen; OnNew fires once per new record.
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

// Redaction at the writer sink.
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
	if _, err := s.AddInput("cidr", "10.0.0.0/8"); err != nil {
		t.Fatal(err)
	}
	in, _ := s.Inputs()
	if len(in) != 2 || in[0].Kind != "cidr" || in[1].Value != "example.com" || in[1].AddedAt != "2026-11-01" {
		t.Errorf("inputs = %+v", in)
	}
	if _, ok := s.Meta("ack_at"); ok {
		t.Error("meta should be unset")
	}
	if err := s.SetMeta("ack_at", "2026-11-01"); err != nil {
		t.Fatal(err)
	}
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

// KindVersion moves when a kind's records change, including when a redo drops
// them, and not for other kinds' writes.
func TestKindVersion(t *testing.T) {
	s, _ := open(t, newClock(), nil)
	if s.KindVersion("x") != 0 {
		t.Fatal("fresh store")
	}
	s.Complete("st", "c1", []store.Obs{{Kind: "x", Key: "a"}})
	mustFlush(t, s)
	v1 := s.KindVersion("x")
	if v1 == 0 {
		t.Fatal("a new record must change the version")
	}
	s.Complete("st", "c2", []store.Obs{{Kind: "y", Key: "b"}})
	mustFlush(t, s)
	if s.KindVersion("x") != v1 {
		t.Error("another kind's write must not change the version")
	}
	s.Complete("st", "c1", nil) // c1 no longer produces a
	mustFlush(t, s)
	v2 := s.KindVersion("x")
	if v2 == v1 {
		t.Error("a dropped observation must change the version")
	}
	s.Complete("st", "c3", []store.Obs{{Kind: "x", Key: "c"}})
	mustFlush(t, s)
	if err := s.Redo("st"); err != nil {
		t.Fatal(err)
	}
	v3 := s.KindVersion("x")
	if err := s.FinishRedo("st", map[string]struct{}{}); err != nil {
		t.Fatal(err)
	}
	if s.KindVersion("x") == v3 {
		t.Error("a redo sweep must change the version")
	}
}

// A redo moves the version of the kinds the stage observes, because those
// records lose their observers at once; a kind it does not observe stays put.
func TestRedoBumpsTheKindsTheStageObserves(t *testing.T) {
	s, _ := open(t, newClock(), nil)
	s.Complete("st", "c1", []store.Obs{{Kind: "x", Key: "a"}})
	s.Complete("other", "c2", []store.Obs{{Kind: "y", Key: "b"}})
	mustFlush(t, s)
	x, y := s.KindVersion("x"), s.KindVersion("y")
	if err := s.Redo("st"); err != nil {
		t.Fatal(err)
	}
	if s.KindVersion("x") == x {
		t.Error("the redone stage's kind must change version")
	}
	if s.KindVersion("y") != y {
		t.Error("another stage's kind must not")
	}
}

// Observers lists, per record, the completed checks that observe it now: not
// the observations of a check a redo has forgotten, nor of one retired.
func TestObservers(t *testing.T) {
	s, _ := open(t, newClock(), nil)
	obs := func(kind string, keys ...string) []store.Obs {
		var out []store.Obs
		for _, k := range keys {
			out = append(out, store.Obs{Kind: kind, Key: k})
		}
		return out
	}
	s.Complete("whoisxml", "Acme", obs("root", "x.org", "y.org"))
	s.Complete("crtsh", "k1", obs("root", "x.org"))
	s.Complete("crtsh", "k2", obs("hostname", "x.org"))
	mustFlush(t, s)

	want := func(got map[string][]store.Observer, key string, pairs ...string) {
		t.Helper()
		var have []string
		for _, o := range got[key] {
			have = append(have, o.Stage+"/"+o.CheckKey)
		}
		if strings.Join(have, ",") != strings.Join(pairs, ",") {
			t.Errorf("observers of %s = %v, want %v", key, have, pairs)
		}
	}
	got, err := s.Observers("root")
	if err != nil {
		t.Fatal(err)
	}
	want(got, "x.org", "crtsh/k1", "whoisxml/Acme") // by stage, then check
	want(got, "y.org", "whoisxml/Acme")
	if len(got) != 2 {
		t.Errorf("only the kind's own records: %v", got)
	}

	// A check that no longer produces a record stops observing it.
	s.Complete("crtsh", "k1", nil)
	mustFlush(t, s)
	got, _ = s.Observers("root")
	want(got, "x.org", "whoisxml/Acme")

	// A redo forgets the stage's completed checks: until one completes again it
	// observes nothing, even though its stale observations are still stored.
	if err := s.Redo("whoisxml"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Observers("root")
	if len(got) != 0 {
		t.Errorf("after a redo, before the checks run again: %v", got)
	}
	s.Complete("whoisxml", "Acme", obs("root", "x.org")) // y.org is no longer found
	mustFlush(t, s)
	if err := s.FinishRedo("whoisxml", map[string]struct{}{"Acme": {}}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Observers("root")
	want(got, "x.org", "whoisxml/Acme")
	want(got, "y.org")

	// A retired check no longer observes.
	s.Complete("st", "svc|fp=old", obs("root", "z.org"))
	s.Complete("st", "svc|fp=new", obs("root", "z.org"))
	mustFlush(t, s)
	got, _ = s.Observers("root")
	want(got, "z.org", "st/svc|fp=new", "st/svc|fp=old")
	if err := s.Retire("st", map[string]struct{}{"svc|fp=new": {}}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Observers("root")
	want(got, "z.org", "st/svc|fp=new")
}
