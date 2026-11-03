// Package engagement opens an engagement directory: it recognises recon's own
// directories, takes the single-run lock and holds scope inputs, the
// authorisation acknowledgement and the netblock approval.
package engagement

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rafaelh/recon/internal/config"
	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/store"
)

// NotEngagementError means the directory exists, is non-empty and is not a recon engagement.
type NotEngagementError struct{ Dir string }

func (e *NotEngagementError) Error() string {
	return fmt.Sprintf("%s exists but is not a recon engagement (no .recon directory); refusing to use it", e.Dir)
}

// LockedError means another run holds the engagement.
type LockedError struct{ Dir string }

func (e *LockedError) Error() string {
	return fmt.Sprintf("another recon run is using the engagement in %s (lock held)", e.Dir)
}

// Options configure Open.
type Options struct {
	Clock    func() time.Time
	Redactor *config.Redactor
}

// Engagement is an open, locked engagement directory.
type Engagement struct {
	dir   string
	lock  *os.File
	st    *store.Store
	clock func() time.Time
}

// Open creates or opens the engagement in dir and takes its lock.
func Open(dir string, o Options) (*Engagement, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	marker := filepath.Join(dir, ".recon")
	if _, err := os.Stat(marker); errors.Is(err, os.ErrNotExist) {
		entries, rerr := os.ReadDir(dir)
		if rerr != nil {
			return nil, rerr
		}
		if len(entries) > 0 {
			return nil, &NotEngagementError{Dir: dir}
		}
	}
	if err := os.MkdirAll(marker, 0o755); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(marker, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, &LockedError{Dir: dir}
		}
		return nil, err
	}
	st, err := store.Open(filepath.Join(marker, "state.db"), store.Options{Clock: o.Clock, Redactor: o.Redactor})
	if err != nil {
		lock.Close()
		return nil, err
	}
	clock := o.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Engagement{dir: dir, lock: lock, st: st, clock: clock}, nil
}

// Dir is the engagement directory.
func (e *Engagement) Dir() string { return e.dir }

// Store is the engagement's state store.
func (e *Engagement) Store() *store.Store { return e.st }

// Close closes the store and releases the lock.
func (e *Engagement) Close() error {
	err := e.st.Close()
	if cerr := e.lock.Close(); err == nil { // closing the descriptor releases the flock
		err = cerr
	}
	return err
}

// MergeInputs adds inputs and exclusions to the stored scope (a union; nothing is removed).
func (e *Engagement) MergeInputs(p input.Parsed) error {
	for kind, vals := range map[string][]string{"root": p.Roots, "org": p.Orgs, "asn": p.ASNs, "cidr": p.CIDRs, "exclude": p.Exclusions} {
		for _, v := range vals {
			if _, err := e.st.AddInput(kind, v); err != nil {
				return err
			}
		}
	}
	return nil
}

// Inputs returns the stored scope and exclusions.
func (e *Engagement) Inputs() (input.Parsed, error) {
	rows, err := e.st.Inputs()
	if err != nil {
		return input.Parsed{}, err
	}
	var p input.Parsed
	for _, r := range rows {
		switch r.Kind {
		case "root":
			p.Roots = append(p.Roots, r.Value)
		case "org":
			p.Orgs = append(p.Orgs, r.Value)
		case "asn":
			p.ASNs = append(p.ASNs, r.Value)
		case "cidr":
			p.CIDRs = append(p.CIDRs, r.Value)
		case "exclude":
			p.Exclusions = append(p.Exclusions, r.Value)
		}
	}
	return p, nil
}

// Acked reports whether the operator's authorisation has been recorded.
func (e *Engagement) Acked() bool { _, ok := e.st.Meta("ack_at"); return ok }

// SetAck records the authorisation acknowledgement.
func (e *Engagement) SetAck() error {
	return e.st.SetMeta("ack_at", e.clock().UTC().Format(time.RFC3339))
}

// NetblockApproved is the IPv4 address count the operator approved (0 if none).
func (e *Engagement) NetblockApproved() int {
	v, ok := e.st.Meta("netblock_approved")
	if !ok {
		return 0
	}
	n, _ := strconv.Atoi(v)
	return n
}

// SetNetblockApproved remembers an approved IPv4 address count.
func (e *Engagement) SetNetblockApproved(n int) error {
	return e.st.SetMeta("netblock_approved", strconv.Itoa(n))
}
