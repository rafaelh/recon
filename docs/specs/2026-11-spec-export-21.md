# Spec 21: whole-engagement export

## Goal

Everything recon has recorded about an engagement can be exported as machine-readable lines for
other tooling, without the CSV columns having to stay stable.

## Behaviours

1. `recon export -e <name>` writes to stdout one JSON object per line for every record in the
   engagement, current or not: `kind`, `key`, `attrs`, `current`, `first_seen`, `last_seen`, the
   stages currently observing it (empty for records that are not current), and either `scope`
   (`in-scope`, `candidate`, `excluded`) for hostnames, roots, netblocks and excluded items, or
   `shown` (`true`/`false`) for every other kind, classified with the engagement's inputs and the
   current configuration. The engagement's inputs and exclusions are exported as their own lines
   (`kind` `input` and `exclusion`). The authorisation acknowledgement, netblock approval and
   settings are not exported.
2. `--output <file>` writes to a file instead, replacing an existing file atomically; a write
   failure exits 1. `--current` limits the export to current records and `--kind <kind>`
   (repeatable) to the given kinds; both filters combine. Kind names are listed by
   `recon export --help`, and an unknown kind exits 2.
3. Secrets are never present: the export contains no API keys.
4. `export` does not take the run lock: it reads a consistent snapshot and works while a run is in
   progress, and never writes to the engagement. It exits 1 for an engagement that does not exist
   (creating nothing) or a directory that is not a recon engagement, found under `--output-dir`
   or `output_dir` as for a run. It makes no network requests.
5. Target-supplied text (titles, banners) is sanitised as for console output.
6. The README documents the command and says that the stable names are the stored attribute
   names kept by the state database and the export's own field and kind names; finding attributes
   are derived and may change.

# Design

**Status:** ready to build (wave 1). **Depends on:** nothing; it reads kinds generically, so later
kinds are exported without change. **Owns for Spec 20:** `run.BuildScope`.

## Decisions

- **`export` is a cobra subcommand** in `internal/cli/export.go`. The root keeps
  `cobra.ArbitraryArgs`; `export` is not a valid domain, so nothing is ambiguous. It takes `-e`
  (required), `--output`, `--current`, `--kind`, and the root's `--output-dir` and `--config`.
- **Read-only open.** `engagement.OpenReadOnly(dir)` creates nothing and takes no lock: a missing
  directory, or one without `.recon/state.db`, is an error (exit 1). `store.OpenReadOnly` opens
  with `mode=ro` and `query_only`, checks the application id and never runs the schema.
- **One snapshot.** Every read happens inside one read transaction (`store.View(func(Reader))`),
  which under WAL is a consistent snapshot while a run writes. `Store.Records`, `Inputs` and
  `Observations` move onto a small `Reader` type over a querier so the store and the snapshot
  share them.
- **Classification reuses the run's rules.** The scope and inventory construction in
  `Runner.buildScope`, `inventoryData` and `asnNetblocks` moves to `run.BuildScope(src)`, where
  `src` gives the inputs, the records of a kind merged in the registry's stage order, and the
  observations of a kind by stage (ASN-expanded netblocks are found that way). The runner and
  `export` both call it, so the export cannot classify differently from a run. What stays in the
  runner: the netblock-limit approval (a write) and building the egress policy. No egress is
  created by `export`: the command makes no network requests by construction.
- **Lines** are written in kind order, then key order: `kind`, `key`, `attrs`, `current`,
  `first_seen`, `last_seen`, `stages`, and `scope` for entity kinds or `shown` otherwise. Inputs
  and exclusions come first as `kind: "input"` (`type`, `value`, `added`) and
  `kind: "exclusion"`. `--kind` accepts the names of `kinds.All()` plus `input` and `exclusion`.
- **Text safety**: every string in `attrs` and `key` passes through `sanitize.Text`, then the
  redactor built from the configured keys (the store already redacts on write).
- **`--output`** writes a temporary file beside the target and renames it.

## Changes

- `internal/cli/export.go`; `cli.go` registers the subcommand and its help (kind list).
- `internal/engagement/engagement.go`: `OpenReadOnly`. `internal/store/store.go`:
  `OpenReadOnly`, `View`, `Reader`.
- `internal/run/scopebuild.go`: `BuildScope` (moved code); `runner.go` calls it.
- `README.md`: the command, and which names are stable.

## Tests

`internal/cli/export_test.go`:

- Every record of a populated engagement is exported once with the right `scope` or `shown`,
  including not-current ones with empty `stages`; ASN-expanded netblocks are `in-scope` and merged
  `attrs` equal a run's; inputs and exclusions are lines; no
  acknowledgement, netblock approval or settings appear.
- `--current`, repeated `--kind` and both together; an unknown kind exits 2.
- `--output` replaces a file atomically; an unwritable path exits 1.
- A configured key value appears nowhere; a title with terminal escapes is sanitised.
- Export while a run holds the lock succeeds and matches a consistent state; the engagement
  directory's files are byte-identical before and after; a missing engagement and a
  non-engagement directory exit 1 and create nothing; the canaries see no traffic.

## To verify while building

Opening a WAL database read-only may create `-shm` when no run is active. If it does, open with
`immutable=1` when no `-wal` file exists, so the "never writes" test holds.

## Out of scope

Importing; formats other than JSON lines; exporting settings.
