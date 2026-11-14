# Spec 15: ranked candidates

## Goal

The user can tell at a glance which candidates in `candidates.csv` are worth promoting to scope,
because each shows how many independent signals support it and a confidence level.

## Behaviours

1. `candidates.csv`'s `found_by` column is replaced by `sources` (the distinct stages or
   mechanisms that observed the candidate, `;`-joined, allowed values listed in the README),
   `evidence_count` (the number of distinct source-and-supporting-item pairs, where the supporting
   item is the address, root, name server or record that linked the candidate) and `confidence`
   (`low`, `medium`, `high`).
2. Sources are grouped into families: certificate transparency (crt.sh, Cert Spotter, Censys),
   web archive (Wayback, Common Crawl), passive DNS (OTX, VirusTotal, SecurityTrails, Shodan,
   Chaos, urlscan, Anubis, HackerTarget hostsearch), reverse IP, registrant (RDAP, reverse
   WHOIS), shared infrastructure (shared NS or MX) and web identifier. Confidence is `high` when a
   registrant-family match of the input organisation (by the word rule of Spec 8) is joined by any
   other family, or three or more families agree; `medium` with two families, or one of: a shared
   self-hosted name server or mail host, reverse IP on two or more addresses, or a registrant
   match alone; `low` otherwise. Without an `--org` input the registrant match rule does not
   apply. The README states these rules.
3. `candidates.csv` is sorted high first, then evidence count descending, then value. Rows that
   are not current sort last and show the confidence they last had.
4. The console summary lists up to 20 `high` candidates with the input that promotes each (a root
   or hostname as a positional domain, a netblock as `--cidr`, an autonomous system as `--asn`, an
   organisation as `--org`), then `and N more in candidates.csv`. `medium` and `low` candidates
   are listed only in `candidates.csv`. `--json` emits one `candidate` event per high candidate.
5. Confidence is recomputed on every run from current evidence. After `--redo` of the stage that
   found a candidate's support, a candidate no longer supported drops a level.

# Design

**Status:** ready to build (wave 1). **Depends on:** nothing. The family table names sources that
Specs 2, 8, 10, 13 and 16 add; re-check it as each lands. **Owns for later specs:** candidate
evidence, `internal/candidates`, `internal/orgname`, the derived-records hook, `File.Order`.

## Decisions

- **Evidence is read from the observations the store already keeps**, not from a new kind. A
  candidate's evidence is the distinct `(source, item)` pairs of the completed checks that
  currently observe its record. `store.Observers(kind)` returns the `(stage, check key)` pairs per
  record key. By default the source is the stage name and the item is the check key, which is
  already the supporting item for today's candidate producers (an organisation for `ct-org`,
  `whoisxml` and `org-asn`, a netblock for `shodan`, a service for `httpprobe`, an address for
  `rdns`). A stage whose key carries settings, or which reports a mechanism rather than its own
  name, implements `run.Evidencer.Evidence(checkKey) (source, item string)`.
- **Ranking is pure**, in a new package `internal/candidates`: the family table, the confidence
  rules of behaviour 2, the sort order, and `Promote(type, value)` giving the input that promotes
  a candidate. Sources outside the listed families each form their own family (`httpprobe`,
  `rdns`); the README lists them. `org-asn` is in the registrant family (assumption: RIPEstat's
  organisation search matches registry organisation names).
- **A registrant match of the input organisation** is evidence from a registrant-family source
  whose item is an `--org` input. Those stages already filter by the word rule, which moves to
  `internal/orgname` so RDAP (Spec 8) uses the same function.
- **Ranks are stored as derived records**, like findings. The runner gets a small list of
  derivers (`name`, the kinds it reads, `derive func(DeriveInput) []store.Obs`), run at the two
  places `deriveFindings` is called today (after a stage did work, and before a render), each
  skipped while the versions of the kinds it reads, the inputs and the date are unchanged, and
  each stored under its own pseudo-stage. Findings stay as they are: their derivation also
  returns the storage attribution the render needs, and they depend on every evidence kind. Their
  signature additionally excludes `candidate_rank`. The `candidate_rank` deriver emits one record
  per candidate (`type`, `value`, `sources`, `evidence_count`, `confidence`, `current`) and
  re-emits the last rank of a candidate that is no longer current, which is how such a row keeps
  "the confidence it last had".
- **A candidate root also counts the evidence of candidate hostnames under it.** Reverse IP,
  Shodan and the pivots report roots while `rdns` and the probe report hostnames; without this the
  families would rarely combine. The hostname rows keep their own rank.
- **A candidate-producing stage whose check key carries a setting must implement `Evidencer`**,
  or a changed setting would leave two keys observing one record and count twice.
- **`candidates.csv`** is written from `candidate_rank` joined to the entity record for its dates,
  with columns `type`, `value`, `sources`, `evidence_count`, `confidence`. `output.File` gains
  `Order func(a, b Row) int` so this file can sort by confidence instead of by cells; not-current
  rows sort last.
- **Summary**: the `summary` event gains `candidates` (the high ones, with `promote`); the console
  lists 20 and `and N more in candidates.csv`. `--json` emits one
  `candidate` event per high candidate before the summary.

## Changes

- `internal/store/store.go`: `Observers`. `internal/run/stage.go`: `Evidencer`.
- `internal/candidates/` and `internal/orgname/` (moved from `orgpivot.tokens`).
- `internal/run/runner.go`: the deriver list, `candidate_rank`, summary fields.
- `internal/kinds/candidaterank.go`. `internal/output/candidates.go` (moved out of `output.go`),
  `File.Order` in `renderFile`. `internal/report/report.go`: summary block and `candidate` event.
- `README.md`: columns, allowed sources, families and rules.

## Tests

- `internal/candidates`: the rule table (registrant plus another family, three families, two
  families, registrant alone, reverse IP on two addresses, shared NS, one source, no `--org`),
  sort order, `Promote`.
- `internal/store`: `Observers` after completes, a redo and a retire.
- `internal/cli/candidates_test.go` (fake stages): columns and order; a not-current row sorts last
  with its last confidence; `--redo` of a supporting stage lowers a level; a hostname's evidence raises its root; findings
  are still re-derived when only an evidence kind changed; the console list, the
  `N more` line and `candidate` events.

## Out of scope

The `organisation` and `asn` candidate types (Spec 8 adds them to this model); any change to what
is contacted.
