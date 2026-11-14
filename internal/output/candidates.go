package output

import (
	"cmp"
	"slices"
	"strconv"

	"github.com/rafaelh/recon/internal/candidates"
	"github.com/rafaelh/recon/internal/kinds"
)

var candidateColumns = []string{"type", "value", "sources", "evidence_count", "confidence"}

// Positions of the cells the sort reads, found by name so that a column moved
// or added in candidateColumns cannot leave the sort reading the wrong one.
var (
	candidateValue = slices.Index(candidateColumns, "value")
	candidateCount = slices.Index(candidateColumns, "evidence_count")
	candidateLevel = slices.Index(candidateColumns, "confidence")
)

// candidateRows lists the roots, hostnames and netblocks the summary counts as
// candidates: both ask the snapshot's Visibility. Each row carries the rank the
// runner derived for it, and the currency and dates of the candidate itself. A
// candidate with no rank yet (a Snapshot built without the derivation) is listed
// with no sources and the lowest confidence.
func candidateRows(s Snapshot) []Row {
	ranks := map[string]kinds.CandidateRankAttrs{}
	for _, r := range s.of(kinds.CandidateRank) {
		if r.Current {
			ranks[r.Key] = kinds.CandidateRank.Attrs(r)
		}
	}
	var rows []Row
	vis := s.vis()
	for _, kind := range kinds.CandidateKinds {
		for _, r := range s.of(kind) {
			if vis.Category(kind, r) != kinds.Candidates {
				continue
			}
			rank, ok := ranks[kinds.CandidateRankKey(kind.Name(), r.Key)]
			if !ok {
				rank.Confidence = string(candidates.Low)
			}
			rows = append(rows, recordRow(r, kind.Name(), r.Key, rank.Sources, strconv.Itoa(rank.EvidenceCount), rank.Confidence))
		}
	}
	return rows
}

// candidateOrder sorts candidates.csv: high confidence first, then more
// evidence, then by value. A row that is not current is last, and shows the
// confidence it last had.
func candidateOrder(a, b Row) int {
	entry := func(r Row) candidates.Entry {
		n, _ := strconv.Atoi(r.Cells[candidateCount])
		return candidates.Entry{Value: r.Cells[candidateValue], Current: r.Current, Confidence: candidates.Confidence(r.Cells[candidateLevel]), Count: n}
	}
	return cmp.Or(candidates.Compare(entry(a), entry(b)), slices.Compare(a.Cells, b.Cells))
}
