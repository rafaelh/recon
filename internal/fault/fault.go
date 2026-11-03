// Package fault provides deterministic crash points for subprocess tests.
//
// When RECON_FAULT names a point, the first goroutine to reach it writes the
// point (and optional detail) to RECON_FAULT_FILE and then blocks forever so a
// test can kill the process at a known moment. With RECON_FAULT unset, Point
// does nothing.
package fault

import (
	"os"
	"sync/atomic"
)

var (
	target  = os.Getenv("RECON_FAULT")
	file    = os.Getenv("RECON_FAULT_FILE")
	tripped atomic.Bool
)

// Point pauses at the named point if it is the configured fault.
func Point(name string) { PointDetail(name, "") }

// PointDetail is Point with a detail string recorded in the fault file.
func PointDetail(name, detail string) {
	if target == "" || target != name || !tripped.CompareAndSwap(false, true) {
		return
	}
	if file != "" {
		tmp := file + ".tmp"
		if err := os.WriteFile(tmp, []byte(name+" "+detail+"\n"), 0o600); err == nil {
			os.Rename(tmp, file)
		}
	}
	select {}
}
