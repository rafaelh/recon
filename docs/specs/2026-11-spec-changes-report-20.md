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
