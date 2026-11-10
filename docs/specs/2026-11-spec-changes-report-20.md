# Spec 20: what changed since the last run

## Goal

After a re-run the user sees exactly what is new and what disappeared, without diffing CSV files
by hand.

## Behaviours

1. A change is a difference between what the output files would show when the run starts and what
   they show when it ends, for the kinds written to output files: `new` (shown at the end, absent
   at the start), `returned` (shown at the end, on record but not shown at the start) and `gone`
   (shown at the start, not shown at the end). Candidates count as their own kind. Internal and
   evidence kinds are not listed.
2. `changes.csv` has one row per change: `change`, kind, key, scope and, for findings, severity,
   with the standard `current`, `first_seen` and `last_seen` columns. It is replaced each run and
   removed when a run has no changes. On a first run (no records when the run starts) no
   `changes.csv` is written and no change events are emitted.
3. The console summary ends with a "since last run" block: counts of new (including returned)
   hostnames, addresses, web services, open ports, candidates and findings, and of gone findings,
   followed by the new high and medium findings as a separate list. It is omitted on a first run.
4. `--json` emits one `change` event per row after the summary event, in addition to the `found`
   events already emitted during the run.
5. The baseline is the state when this invocation starts, so a resumed run after an interrupt
   compares against the interrupted run's end state. An interrupted run writes `changes.csv` for
   the work it completed before exiting 130.
6. Findings can be new or gone with no contact: a certificate crosses its expiry date, a setting
   or the binary changes. A `--passive` run never reports target-derived records as gone, because
   the stages that observe them did not run.

# Design

**Status: review before building (wave 3).** The mechanism is generic over kinds, so this design
is complete, but its summary block and passive rule name kinds and stages other specs add. Build
it last, and at review re-check the items marked *Review*. **Depends on:** Spec 21
(`run.BuildScope`), Spec 15 (`candidate_rank`), and in practice every spec that adds a kind.

## Decisions

- **A change is a difference between two "shown" states of a record**, taken when the run starts
  and each time the files are written. A record's state is `absent`, `on record` (stored but not
  current or not shown) or `shown` (current and shown by the decision the
  files use). `new` is absent to shown, `returned` is on record to shown, `gone` is shown to
  anything else.
- **Which kinds are listed is a property of the kind**: `Kind.Change` is the label used in
  `changes.csv` (`hostname`, `address`, `web service`, `url`, `open port`, `third party`,
  `code mention`, `finding`, …); kinds without one (evidence and internal kinds) are skipped.
  Candidates are their own label: an entity record the scope classifies as a candidate, plus the
  other candidate types. *Review:* give a label to each kind the other specs added that has an
  output file.
- **The baseline is what the last render showed, saved, not recomputed.** Recomputing it when a
  run starts would use today's date, settings, binary and scope, and so absorb exactly the changes
  behaviour 6 asks for (a certificate that expired overnight would already be in the baseline).
  Every render, including the one an interrupt triggers, replaces a `shown` table in the state
  database (`kind`, `key`, `stages`) in one transaction. A run reads it once, before its first
  derivation, and diffs every later render against that copy. A resumed run therefore compares
  against where the interrupted run stopped. If the store has no records the run is a first run
  and nothing below happens; an engagement last written by a binary without the table gets its
  baseline computed once from the stored records instead.
- **An entity's state follows the files**, not `Visibility.Shown`, which is true for every
  entity: a hostname is shown when its category is `hosts` and it is not wildcard-only, and a
  candidate when its category is `candidates`.
- **`changes.csv` is an ordinary output file** whose rows come from `Snapshot.Changes`, which the
  runner fills on every render (including the one an interrupt triggers), so it is replaced each
  run, removed when empty, and written atomically like the rest. Columns: `change`, `kind`,
  `key`, `scope`, `severity`.
- **Passive rule**: in a `--passive` run a record is not reported `gone` when every stage
  observing it at the baseline was a target-contact stage. Findings are exempt from the rule:
  they are re-derived with or without contact, so a finding that stops being derived is gone.
- **Reporting**: the `summary` event gains `changes` (counts per label and change, and the new
  high and medium findings); the console prints the "since last run" block from it; `--json`
  emits one `change` event per row after the summary. *Review:* the six labels the block counts.

## Changes

- `internal/kinds/kinds.go`, `table.go` and the per-kind files: `Change` labels.
- `internal/store/store.go`: the `shown` table (created if missing), `SaveShown`, `Shown`.
- `internal/run/changes.go`: baseline and diff. `runner.go`: take the baseline, fill
  `Snapshot.Changes`, summary fields, `change` events.
- `internal/output/changes.go`; one line in `Default()`. `internal/report/report.go`: the block.
- `README.md`: the file, the block, the event.

## Tests

- `internal/run`: the diff over the three states, the first-run rule, the passive rule and its
  findings exemption.
- `internal/cli/changes_test.go` (fake stages and the fixed clock): a first run writes no file and
  emits no events; a second run lists new, returned and gone rows with scope and severity; a run
  with no changes removes the file; a certificate crossing its expiry date with no contact, a changed setting and a new exclusion
  each show their changes; a `--passive` run does not report a web service gone after a scope change; the
  console block and its omission on a first run; `change` events follow the summary.
- `internal/cli/crash_test.go`: an interrupted run writes `changes.csv` for completed work and
  exits 130; the resumed run's baseline is the interrupted run's end state.

## Out of scope

History across more than one run; diffing attribute values of a record that stayed shown.
