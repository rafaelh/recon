# Spec 6: larger built-in word and sensitive-path lists

## Goal

The default permutation wordlist and sensitive-path list are large enough to be useful without the
user supplying their own, and neither a large list nor a large target can make a run's request
count explode.

## Behaviours

1. The built-in permutation wordlist has between 2,000 and 5,000 entries: lowercase, unique, valid
   DNS labels, ordered most common first (the per-seed cap takes words from the front), assembled
   from MIT-licensed SecLists lists with attribution in the file header and the README.
   `--wordlist` continues to replace it. Permutations keep their current `--passive` status; the
   README states the lookup volume per root.
2. The built-in sensitive-path list has at least 150 entries, each with a body signature or byte
   prefix and an explicit severity. A test checks that each entry matches a sample of the real file
   and does not match a generic 200 page or a soft 404. `--sensitive-paths` continues to replace
   it.
3. The first run after upgrading repeats every permutation check once, because the list changed.
   Sensitive-path checks are performed for the new entries only; every existing built-in entry is
   kept unchanged so its hits stay current.
4. `permutations.max_names` (default 200,000) caps the names generated per run. Roots are taken
   before seeds, each in name order, and a root's or seed's names are never split across runs:
   once the next one would pass the cap, it and the rest are deferred, though the first is always
   taken even if it alone exceeds the cap. Deferral is not a failure; the stage shows `done`, and
   the console summary and the `--json` summary event give the deferred count. `max_per_seed` is
   unchanged. Names under a zone already known to be a wildcard are not generated.
5. `sensitive_path_max_requests` (default 50,000; 0 is invalid and exits 2; the setting is not
   nested under the existing `sensitive_paths` file setting) caps sensitive-path requests per run.
   Requests are taken entry by entry in severity order, then by service, so every service gets its
   highest-severity paths first; the remainder is deferred to later runs. A hit from an earlier run
   stays current in a run that defers other requests. Deferral is not a failure; the stage shows
   `done`, and the console summary and the `--json` summary event give the deferred count. The
   README states the request count formula (services × entries) and the time it takes at the
   default rate.

# Design

**Status:** ready to build (wave 1). **Depends on:** nothing. **Owns for later specs:**
`run.Budgeted`, `Check.Cost` and the deferred count in the summary (Specs 4, 7, 13).

## Decisions

- **A per-run budget is a runner feature**, not something each stage counts for itself, because a
  stage cannot see which of its checks are already done. A stage opts in with
  `Budgeted.Budget(config.Settings) int`; a check may carry `Cost` (0 means 1). While producing a
  stage's pending checks the runner adds each cost to what the stage has spent in this run; the
  first check that would pass the budget, and every pending check after it, is deferred, except
  that the first pending check of the run is always taken. Deferred checks are not sent, not
  failed and not counted as attempted, so the pass loop still ends and the stage shows `done`.
- **Deferred checks stay valid**: a check is deferred only after its key has joined the set the
  redo sweep and `Retiring` use, so a
  hit from an earlier run stays current while its neighbours wait (behaviour 5).
- **The summary reports it**: the `summary` event gains `deferred` (`{stage: count}` from the
  stage's last pass) and the console prints `Deferred to the next run` with a line per stage.
- **Permutations.** `Checks` yields roots then seeds, each sorted, with `Cost` set to the number of
  names the check will query (computed with the same generator `Run` uses). A root or a seed's
  parent that has a current `wildcard` record is not yielded. Budget: `permutations.max_names`
  (default 200,000, minimum 1, flag `--permutations-max-names`).
- **Sensitive paths.** `Checks` yields entry by entry in severity order (high, medium, low; the
  list order within a severity), then by service; each check costs 1. The egress index stays the
  entry's position in the configured list. Budget: `sensitive_path_max_requests` (default 50,000,
  minimum 1, flag `--sensitive-path-max-requests`).
- **Existing entries are frozen by a test** that compares each of today's 23 `path|hash` pairs
  with a golden list, so no existing check key changes and only new entries are requested.
- **The lists are data, assembled once by hand**: the wordlist from SecLists
  `Discovery/DNS/subdomains-top1million-5000.txt`, filtered to valid lower-case labels, in its
  order, with the MIT attribution in the file's comment header; the path list extended to at
  least 150 entries, each with an explicit severity.

## Changes

- `internal/run/stage.go`: `Budgeted`, `Check.Cost`. `internal/run/runner.go`: budget accounting
  in the produce loop, `deferred` in `emitSummary`. `internal/report/report.go`: the block.
- `internal/stages/dns/permutations.go`: ordering, cost, wildcard skip, `Budget`.
- `internal/stages/risk/sensitive.go`: ordering, `Budget`.
- `internal/config/config.go`: the two settings. `internal/config/builtin/`: both lists, and
  `testdata/sensitive/` with one sample per entry plus a generic 200 page and a soft 404.
- `README.md`: attribution, lookup volume per root, the request formula and time at default rate.

## Tests

- `internal/run` (fake stages): budget stops at the first overflow, the first check is always
  taken, deferred checks are neither failed nor retired, the count is in the summary, and the
  remainder runs next time; in a later pass of the same run the "first check" exception does not
  take another overflowing check; `--redo` of a budgeted retiring stage keeps earlier hits current.
- `internal/config`: wordlist size, uniqueness, validity; every path entry has a severity and a
  sample that matches, and does not match the generic 200 or soft 404; the golden list of existing
  entries; `sensitive_path_max_requests: 0` exits 2.
- `internal/cli/lists_test.go`: an upgraded engagement repeats permutation checks once and
  requests only new sensitive paths; roots before seeds; a root alone over the cap is still taken;
  no names under a wildcard zone; severity order across services; an earlier hit stays current in
  a deferring run; the console and `--json` deferred counts.

## Out of scope

Changing `max_per_seed`; a general per-stage time limit; fetching SecLists at build time.
