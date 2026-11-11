package output

import (
	"strconv"

	"github.com/rafaelh/recon/internal/kinds"
)

var thirdPartyColumns = []string{"root", "mechanism", "domain", "provider", "depth"}

// thirdPartyRows lists the shown third parties of every mechanism: the
// organisations a root's name servers and verification records point at.
func thirdPartyRows(s Snapshot) []Row {
	var rows []Row
	vis := s.vis()
	for _, r := range s.of(kinds.ThirdParty) {
		a := kinds.ThirdPartyOf(r)
		// A record no longer current keeps no attributes, so the showing rule is
		// asked with the root and domain its key gives back: a name server whose
		// domain a later root brings into scope is hidden either way.
		asked := r
		if len(r.Attrs) == 0 {
			asked.Attrs = map[string]any{"root": a.Root, "domain": a.Domain}
		}
		if !vis.Shown(kinds.ThirdParty, asked) {
			continue
		}
		rows = append(rows, recordRow(r, a.Root, a.Mechanism, a.Domain, a.Provider, strconv.Itoa(a.Depth)))
	}
	return rows
}
