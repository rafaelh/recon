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
   organisation as `--org`), then `and N more in candidates.csv`. `--verbose` also lists `medium`
   candidates. `--json` emits one `candidate` event per high candidate.
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
  lists 20 and `and N more in candidates.csv`; `--verbose` adds medium. `--json` emits one
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
  `N more` line, `--verbose` medium list and `candidate` events.

## Out of scope

The `organisation` and `asn` candidate types (Spec 8 adds them to this model); any change to what
is contacted.

# Implementation

## Develop

Built as designed. `store.Observers(kind)` joins `observations` to `checks`, so only completed
checks count (a redo forgets a stage's checks at once, before the stale observations are swept).
`run.Evidencer` is looked up by stage name when a derivation runs. `internal/run/derive.go` holds
the deriver list (`DeriveInput`, `deriveRecords`) and `rankCandidates`; `candidate_rank` is
derived there and stored under the pseudo-stage `candidate-rank`. `deriveRecords` runs next to
`deriveFindings` at both call sites and is skipped while the versions of the scope kinds, the
inputs and the date are unchanged; the findings signature now also excludes `candidate_rank`.
`internal/candidates` holds the family table, `Score`, `Compare` and `Promote`;
`internal/orgname` holds the word rule moved out of `orgpivot`, which `org-asn` now calls.
`output.File.Order` sorts `candidates.csv` (`internal/output/candidates.go`). `Crawl` implements
`Evidencer` (its key carries depth and pages); no other stage that can find a candidate has a
setting in its key. `README.md` has a new Ranked candidates section, and `CLAUDE.md` names
`Evidencer` and the derivers.

Tests: the rule table, sort order, `Promote`, and a README check that every source in the table is
listed are in `internal/candidates`; `Observers` after completes, a redo and a retire in
`internal/store`; `File.Order` in `internal/output`; the summary block in `internal/report`;
the crawl's `Evidence` in `internal/stages/web`; and behaviours 1 to 5 end to end in
`internal/cli/candidates_test.go` (columns and order, a not-current row last with its last
confidence and no `candidate` event, `--redo` lowering a level, recomputation with no redo, no
`--org`, a hostname raising its root, `Evidencer` against the default, findings still re-derived
when only an evidence kind changed, the console list with its overflow line and `--verbose`
medium list, and the `candidate` events). Two assertions in `web_redirect_test.go` moved from
`found_by` to `sources`.

Decisions the design left open:

- `ct-org` is in the certificate transparency family (it searches certificates by organisation),
  so `whoisxml` or `org-asn` plus `ct-org` for the same `--org` is a registrant match joined by
  another family.
- `shodan-dns` is in the passive DNS family with `shodan`.
- The family table already names `rdap`, `reverseip`, `nsreverse` and `identifier-pivot`, the
  names in the final stage registry. The README lists them as reserved until those stages exist.
- A registrant match is a registrant-family source whose item is exactly an `--org` input.
  `candidates` does not apply the word rule itself (see Known limitations).
- `Store.Redo` now bumps the version of every kind the stage observes, since a redo changes
  `Observers` without touching a record.
- Shared-infrastructure evidence always counts as "a shared self-hosted name server or mail host":
  Spec 16's stage is expected to report only self-hosted ones.
- "And N more" counts the candidates of that confidence beyond the 20 listed, once for high and once
  for medium under `--verbose`. The summary's `candidates` field holds every high candidate
  (the console does the cutting), and `medium_candidates` is present only with `--verbose`.
- The `candidate` event and summary entries name the type `kind`, because `type` is the event's own
  field in `--json`.

Mutation checks: `## Tests` marks none, so these were done on the three pieces of logic that carry the
most: the three-family rule (`>= 3` made `>= 4`) failed `TestScore` and
`TestCandidates_ColumnsAndOrder`; removing the hostname-to-root roll-up failed
`TestCandidates_HostnameEvidenceRaisesItsRoot`; dropping the carry-forward of a not-current
candidate's last rank failed `TestCandidates_NotCurrentSortsLastWithLastConfidence`. Each edit was
undone by hand.

Verify pass: a current candidate whose own checks have all been forgotten by a redo (so only
evidence rolled up from its hostnames is left) keeps its last rank until they run again, instead of
being re-ranked from the hostnames alone; `TestCandidates_RootAwaitingRedoKeepsItsRankDespiteItsHostnames`
pins it. Each deriver now declares the kind it writes, so `derivationSignature` skips every derived
kind, and `kinds.CandidateKinds` is the one list of candidate kinds, used by the runner and the
output. Left as they were, for the reasons under the simplify pass: deriving after every stage, the
full `Observers` scan, and the two derivation copies.

Simplify pass: applied `maps.Keys` in place of two hand-written iterators, `currentRecords` in
`rankedCandidates`, one `derive()` for both call sites, the sort positions found by column name, and
`Store.Redo` bumping the versions of the kinds the stage observes (which removed a Known limitation).
Skipped: deriving ranks once per pass instead of after each stage (the design names both call
sites), caching `Observers` and skipping unchanged ranks, `dnsname.Parents` for the roll-up (it stops
at the registrable domain and a root need not be one), a shared helper for the findings and rank
derivations, moving the ranking into `internal/candidates`, and stripping `|name=value` from the
default item.

## Known limitations

- Behaviour 1: a candidate that was never ranked and is no longer current (lost before the first
  derivation) has no rank to keep, so its `candidates.csv` row has no sources, an evidence count
  of 0 and `low`.
- Behaviour 2: only `Crawl` implements `Evidencer`. A stage that gains a setting in its check key
  and can find candidates must implement it too; nothing enforces that.
- Behaviour 2: a registrant match is a registrant-family source that was asked about an `--org`
  input. Only `org-asn` applies the word rule to what it gets back; `whoisxml` takes the
  organisations its search returns, so a `high` can rest on a match the word rule would reject.
- Behaviour 2: the family table lists four sources for stages that are not built yet; the spec
  that builds each must check its stage's name and the `Evidencer` it needs.

# Verification

## Result

Checked against the goal, behaviours 1 to 5 and `## Out of scope` by reading every changed file,
the stages that can observe a root, hostname or netblock, and the build-order plan, and by running
`make test` (passes). The goal is met. Each `candidates.csv` row shows its supporting sources, an
evidence count and a confidence, sorted so the best-supported candidates come first, and the
summary names the high ones with the input that promotes each. Nothing contacted changes: ranking
reads only the store.

- **B1 met.** The header is `type, value, sources, evidence_count, confidence` then the usual
  `current, first_seen, last_seen`, matching the plan's column order. `sources` is the sorted
  distinct sources, `;`-joined. `evidence_count` counts distinct (source, item) pairs, where the
  item is the check key or the stage's `Evidencer` result. I checked every stage that can observe a
  root, hostname or netblock outside scope. They are `ct-org`, `whoisxml` and `org-asn` (keyed by
  organisation), `shodan` (netblock), `httpprobe` (service), `rdns` (address) and `crawl` (which
  has a `Evidencer` that drops its limits). Each of their names is in the README's list. The
  subdomain sources and `shodan-dns` carry settings in their keys, but they only record names under
  an in-scope root, so today they never support a candidate.
- **B2 partly met.** The family table, the high, medium and low rules, and the no-`--org` case are
  in `candidates.Score`, are unit-tested row by row, and are stated in the README. Known limitation
  3 stands: a registrant match is a registrant-family source asked about an `--org` input. Only
  `org-asn` applies the word rule to the names it gets back. `whoisxml`'s reverse WHOIS search
  returns domains, not registrant names, so the word rule cannot be applied to them. A `high` can
  therefore rest on whatever WhoisXML's search matched. The `rdap`, `reverseip`, `nsreverse` and
  `identifier-pivot` families exist only in the table until their stages are built (known
  limitation 4). The rules for them are tested on synthetic evidence only.
- **B3 met after one fix.** The rows are sorted current first, then high, medium, low, then evidence
  count descending, then value, through `File.Order`. A not-current row keeps its last rank because
  the deriver re-emits it. *Fixed:* a run with `--redo X` derives the ranks after any earlier stage
  that does work, before X has run again. A candidate supported only by X then has no completed
  observer, and was ranked `low` with no sources while still current. If X then no longer found
  it, that empty rank became the "confidence it last had". A current candidate with no evidence
  now keeps its last rank until the redone checks run (`rankCandidates` in
  `internal/run/derive.go`). `TestCandidates_NotCurrentAfterRedoKeepsTheRankItHadWhileSupported`
  covers this, and it fails without the fix. Known limitation 1 (a candidate already not current
  before its first derivation, which in practice means one left over from before this change, has
  no rank to keep) stands, so B3 is not met for those rows.
- **B4 met.** The console lists up to 20 current high candidates as `value, count, (sources),
  promote: <input>`, with values passed through `sanitize`. Roots and hostnames are promoted as a
  positional domain and netblocks with `--cidr` (`--asn` and `--org` are in `Promote` for Spec 8).
  An `and N more in candidates.csv` line follows. `--verbose` adds the medium list in the same
  form. `--json` emits one `candidate` event per high candidate before the `summary`. "N" is read
  as the high candidates beyond the 20 listed, so the line is printed only when there are more
  than 20. The spec can also be read as every candidate not listed (Follow-ups).
- **B5 met.** A new Runner derives on its first call, so ranks are worked out again on every run. A
  redo bumps the version of the kinds the redone stage observes and drops its checks from
  `Observers`. When the stage runs again and no longer finds the candidate, the candidate drops a
  level (tested).

Out of scope respected: there are no `organisation` or `asn` candidate types, and no stage
contacts anything new.

# Follow-ups

- The `.claude/hooks/go-check.sh` hook runs from the main checkout, so in a worktree its `go vet`
  fails on the path, and the installed golangci-lint was built with go1.26 while `go.mod` targets
  1.27.3. `golangci-lint` was not run on this change; `gofmt` and `go vet ./...` were.
- When Specs 8, 10, 13 and 16 land, re-check their stage names against the family table in
  `internal/candidates` and remove "reserved" from the README sentence.
