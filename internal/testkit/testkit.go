// Package testkit has fakes for exercising the runner in tests.
package testkit

import (
	"context"
	"fmt"
	"iter"
	"sync"

	"github.com/rafaelh/recon/internal/config"
	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/run"
)

// Stage is a configurable fake run.Stage that records what it executes.
type Stage struct {
	StageName string
	Kind      run.Contact
	Src       []string

	ConfiguredFn func(run.Env) (bool, string)
	ChecksFn     func(v run.View) []run.Check
	ChecksErr    error // yielded after the checks, as if enumeration failed
	RunFn        func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error)

	mu        sync.Mutex
	executed  []string
	active    int
	maxActive int
}

func (s *Stage) Name() string         { return s.StageName }
func (s *Stage) Contact() run.Contact { return s.Kind }
func (s *Stage) Sources() []string    { return s.Src }

func (s *Stage) Configured(e run.Env) (bool, string) {
	if s.ConfiguredFn != nil {
		return s.ConfiguredFn(e)
	}
	return true, ""
}

func (s *Stage) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		if s.ChecksFn != nil {
			for _, c := range s.ChecksFn(v) {
				if !yield(c, nil) {
					return
				}
			}
		}
		if s.ChecksErr != nil {
			yield(run.Check{}, s.ChecksErr)
		}
	}
}

func (s *Stage) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	s.mu.Lock()
	s.executed = append(s.executed, c.Key)
	s.active++
	if s.active > s.maxActive {
		s.maxActive = s.active
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.active--
		s.mu.Unlock()
	}()
	if s.RunFn == nil {
		return nil, nil
	}
	return s.RunFn(ctx, c, e)
}

// Executed returns the keys of the checks run so far, in order.
func (s *Stage) Executed() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.executed...)
}

// MaxActive is the highest number of checks that ran concurrently.
func (s *Stage) MaxActive() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxActive
}

// Reset forgets what has been executed.
func (s *Stage) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.executed, s.maxActive = nil, 0
}

// Keys returns n checks keyed prefix000, prefix001, ...
func Keys(prefix string, n int) []run.Check {
	out := make([]run.Check, n)
	for i := range out {
		out[i] = run.Check{Key: fmt.Sprintf("%s%03d", prefix, i)}
	}
	return out
}

// Budgeted is a Stage with a per-run budget of Limit.
type Budgeted struct {
	*Stage
	Limit int
}

// Budget is the stage's per-run budget.
func (b Budgeted) Budget(config.Settings) int { return b.Limit }
