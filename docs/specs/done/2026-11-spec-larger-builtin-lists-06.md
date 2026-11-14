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

# Implementation

## Develop

**Runner.** `run.Budgeted` (`Budget(config.Settings) int`) and `Check.Cost` are in
`internal/run/stage.go`. `stageStats.spent` is the cost of the checks sent in this run, kept across
passes; `runStage` reads it into a local before the produce loop and writes it back with the pass's
other counters. In the loop, after the done, failed-this-run and aborted checks have been skipped, a
pending check is deferred when `spent > 0 && spent+cost > budget`, or when an earlier check of this
pass was deferred; otherwise its cost is added to `spent`. A zero `spent` is how "the first
pending check of the run is always taken" is expressed, and it is why a later pass never gets that
exception again. A deferred check's key has already joined `all`, so the redo sweep and `Retire` keep
treating it as valid. `stageStats.deferred` is the deferred cost of the stage's last pass; the
`summary` event carries it as `deferred`, and the console prints `Deferred to the next run`.

**Permutations.** `Checks` yields the sorted roots, then the seeds (already sorted). It builds each
check's names once, passes them as the check's input and sets `Cost` to their number, so `Run`
queries exactly what was priced. The wildcard rule lives in `inventory`: `Inventory.WildcardZone`
(exposed as `View.WildcardZone`) says whether a root is a wildcard zone, and `Inventory.Seeds` no
longer returns a seed whose parent is one. **Sensitive paths.** `Checks` stable-sorts the entry
indices by `SensitivePath.SeverityRank()` (high, medium, low, anything else last, so no entry is ever
dropped), then yields entry by entry and by service; the egress index is still the entry's position
in the configured list. **Settings.** `permutations.max_names` (200,000) and
`sensitive_path_max_requests` (50,000), each minimum 1, with the flags
`--permutations-max-names` and `--sensitive-path-max-requests`.

**Lists.** `wordlist.txt` is `subdomains-top1million-5000.txt` filtered to valid lower-case unique
labels, in order (4,860 of its 5,000 lines), with the SecLists attribution and the MIT licence text
in its header. `sensitive_paths.yaml` has 268 entries: the 23 earlier ones first, each with an
explicit `severity` (the eleven that relied on the default now say `medium`; severity is not
in the hash), then the new ones grouped high, medium, low. `internal/config/testdata/sensitive/` has
a sample per entry named after its path (`/` becomes `__`, a trailing `~` becomes `-tilde` and
`.DS_Store` becomes `dot-DS_Store`, because git ignores files of those names and a sample that is
never committed passes only where it was written), plus `_generic-200.html` and `_soft-404.html`. A
test fails if two sample names differ only in case: `/web.config` and `/Web.config` once shared one
file on a case-insensitive filesystem and would have failed on Linux, so the second was dropped (IIS
paths are case-insensitive). Both lists were generated once by a throwaway script and are not regenerated by
the build. README and `CLAUDE.md` describe the lists, the volume, the caps and the new interface.

**Tests.**
- `internal/cli/budget_test.go` (fake stages through the harness; see deviations): first overflow,
  cost accumulation, cost 0, first check always taken, remainder next run, later pass does not take
  another overflowing check, unbudgeted stage unlimited, a failed check spends budget and deferred
  ones are not failures, console block, redo of a budgeted retiring stage keeps hits current.
- `internal/config/lists_test.go`: wordlist size, case, validity, uniqueness, order, attribution;
  README content; every path has an explicit severity, a matching sample, and no match on the
  generic 200, the soft 404 or the wrong status; every sample has an entry; the golden 23
  `path|hash` pairs; both new settings (default, file, env, flag, minimum, not nested).
- `internal/cli/lists_test.go`: roots before seeds, whole-or-nothing deferral and the next run doing
  the rest, a root alone over the cap, no names under a wildcard zone, console and `--json` counts,
  `0` exits 2, a changed list repeats permutation checks once, severity order across services, an
  earlier hit staying current in a deferring redo, and an upgrade requesting only new paths.
- Failing first: every behaviour test failed on an assertion (after a stub for the settings and
  flags, without which they failed only on an unknown flag). Already passing before the code, as
  they pin existing behaviour: the golden entries, `--wordlist`/`--sensitive-paths` replacing the
  lists, a changed list repeating checks once and an upgrade requesting only new entries (both are
  the existing key mechanism), the two validation tests and the settings tests (the stub carried the
  plumbing), and the wildcard representative test.

**Mutation checks.** `## Tests` marks no behaviour for one, so these were chosen by hand, each undone
by hand afterwards: removing `spent > 0 &&` from the deferral test (the first-check exception)
failed `TestBudget_FirstCheckAlwaysTaken`, `TestBudget_LaterPassDoesNotTakeAnotherOverflowingCheck`
and `TestListsPermutations_RootAloneOverCapIsTaken`; not writing `spent` back after a pass failed 12
budget and sensitive-path tests; deleting a deferred key from `all` (so the redo sweep would drop
its hit) failed `TestBudget_RedoKeepsDeferredHitsCurrent` and
`TestListsSensitive_EarlierHitStaysCurrentWhenDeferring`; removing the seed-parent wildcard check
from `Inventory.Seeds` failed `TestSeeds`, and a sort that does not reorder failed
`TestListsSensitive_SeverityOrderAcrossServices` (the first attempt at that one only stopped the
package compiling, so it was redone with a comparator that returns 0).

**Deviations from the plan.**
- The runner tests are in `internal/cli/budget_test.go`, not `internal/run`: `internal/run` has no
  test scaffolding and the harness already drives `cli.Execute` with fake stages. `internal/testkit`
  gained `Budgeted` and `RetiringBudgeted` wrappers.
- The deferred count is in the budget's own unit (names for permutations, requests for sensitive
  paths), not a count of checks.
- The sensitive-path list has 268 entries; the spec's 150 is a floor. I chose to cover the common
  credential, state, source, database, debug and archive exposures by category rather than stop at 150.
- Existing tests changed because the behaviour did: `TestWildcards_WildcardWithDefaultPermutations`
  (names under a wildcard are no longer generated; a second test keeps the one-representative
  rule), `TestBuiltinSensitivePaths` (no longer "about 20"), and `TestKeys` (searched the settings
  dump for the word "secret", which is now in both lists; it searches for the key values).
  `TestSources_KeylessSources` was also changed while the world still used the built-in list, where
  `d` is a word and permutations observe `d.example.com` too; with the fixture list below that no
  longer happens, and it keeps the more precise query of Common Crawl's own observation. The `world`
  fixtures set
  `RECON_WORDLIST` to the previous 104-word list (`internal/cli/testdata/words-default.txt`) so the
  suite does not run thousands of lookups per root in every test; the suite took 100 s instead of
  39 s without it. A test of the built-in list clears it.
- `.claude/hooks/go-check.sh` could not run in the worktree: it vets
  `./.claude/worktrees/…` paths the module does not contain, and the installed golangci-lint was
  built with Go 1.26 against a Go 1.27.3 module. `gofmt`, `go vet` and `make test` were run by hand.

**External facts.** `subdomains-top1million-5000.txt` has 5,000 lines, of which 4,860 survive the
filter; the first four are `www`, `mail`, `ns2`, `ns1`. SecLists' licence is MIT, copyright 2018
Daniel Miessler.

## Known limitations

- **Behaviour 2.** Each signature is checked against a sample written for it, not against the file
  from a real server, so a signature could still miss a real file whose format the sample does not
  show (for example a log in a locale-specific date format). The samples contain no real secrets.
- **Behaviour 4.** Only a wildcard record for a root itself, or for a seed's immediate parent, stops
  generation (both in `inventory`). A seed two levels under a wildcard zone whose own parent was never probed is still
  permuted. The wildcard stage runs before permutations in the same pass, so a zone found this run
  is honoured this run; a zone found later is not retroactive for checks already completed.
- **Behaviour 4 and 5.** A check that fails still spends its share of the budget in that run, so a
  run with many transient failures does less than the cap's worth of useful work.
- **Behaviour 5.** The README's time estimates (54 s per service, about 9 minutes for 100 services)
  assume the default rate and a 200 ms response, and were calculated, not measured.

# Verification

## Result

Checked against the code and tests on this branch (all uncommitted against `main`); `make test`
and `go test -race -count=1 ./...` pass. Nothing was changed before the code review.

- **Behaviour 1: met.** `internal/config/builtin/wordlist.txt` has 4,860 unique, lower-case, valid
  labels in SecLists order (`www`, `mail`, `ns2`, `ns1`, ...), with the SecLists attribution and MIT
  text in its header; the README names the source and licence, says permutations stay on under
  `--passive`, and gives 4,860 lookups (about 97 s at 50 queries a second) per root. `--wordlist`
  still replaces the list (`TestCustomListsReplaceBuiltin`).
- **Behaviour 2: partly met.** 268 entries, each with a signature or magic and an explicit severity;
  `TestBuiltinSensitivePathsSamples` checks each against its sample, a wrong status, a generic 200
  and a soft 404. The samples are hand-written in each file's format, not captured from real files
  (Known limitations), so "a sample of the real file" is met only as far as the samples are
  faithful. `--sensitive-paths` still replaces the list.
- **Behaviour 3: met.** The wordlist hash is in every permutation key, so a new list repeats each
  check once (`TestListsPermutations_ChangedListRepeatsChecksOnce`). The 23 existing entries keep
  their path, signature, magic and status (I compared them with `main`; only quoting and an explicit
  `severity: medium`, which is not hashed, changed), the golden test pins their `path|hash`, and the
  sensitive-path key carries no list position, so reordering by severity changes no key.
- **Behaviour 4: largely met.** `permutations.max_names` (default 200,000, minimum 1, flag, env and
  file) is a runner budget: roots sorted, then seeds sorted, each check costed with exactly the names
  `Run` queries, deferral whole-check, first pending check of the run always taken, a later pass
  never re-granted that exception, deferred work neither failed nor attempted so the stage shows
  `done`, and the console block and `--json` `summary.deferred` carry the count (in names).
  `max_per_seed` is unchanged. Wildcards: a root that is a wildcard zone and a seed whose immediate
  parent is one are skipped, and (after the code review) a seed check drops every generated name
  whose immediate parent is a wildcard zone, so a seed that is itself a wildcard zone no longer
  queries `dev.<seed>`. Part not met: a name two or more levels below a wildcard zone, whose own
  parent was never probed (for example under a CT-log name that does not resolve), is still
  generated (Known limitations). Where that parent does exist, DNS does not apply the ancestor's
  wildcard, so skipping every descendant would lose real names; which reading to take is a
  decision for the user.
- **Behaviour 5: met.** `sensitive_path_max_requests` (default 50,000, top level, `0` exits 2 and
  names the setting) caps requests; checks are stable-sorted high, medium, low then yielded per
  service, each costing 1; deferred keys stay in the set the redo sweep and `Retire` use, so an
  earlier hit stays current (`TestListsSensitive_EarlierHitStaysCurrentWhenDeferring`); the stage
  shows `done` and both summaries give the deferred count. The README gives services × entries (268
  per service) and about 54 s per service at 5 requests a second; those times are calculated, not
  measured.
- **Goal: met**, except the wildcard gap above. Both lists are now useful by default, and a run
  sends at most about 200,000 permutation lookups and 50,000 sensitive-path requests (plus at most
  one oversized first check), whatever the list or target size.

Not checkable here: `.claude/hooks/go-check.sh` and `golangci-lint` (the installed binary was built
with Go 1.26 and refuses the Go 1.27.3 module), so no lint run covers this branch.

## Code review

`/code-review high --fix` reported six findings and fixed three. All were checked against the spec
and kept; `make test` passes afterwards.

- **Fixed, behaviour 4 (wildcard rule):** `Permutations.Checks` drops each generated seed name whose
  immediate parent is a known wildcard zone before pricing the check, so a seed that is itself a
  wildcard zone no longer queries names under it, and the cost still equals what `Run` queries. New
  test `TestListsPermutations_SeedThatIsAWildcardZone`; no existing test was edited.
- **Fixed, no behaviour (convention):** the two new flags are registered after `--chaos-max-pages`,
  as CLAUDE.md asks new settings to be appended.
- **Fixed, behaviour 1 (README wording):** "Each input root costs 4860 lookups per root" now reads
  "The list costs 4860 lookups per root".
- **Left unfixed, behaviour 4:** `Checks` builds every root's and seed's names on every pass, done
  ones included. It is already a follow-up and needs a change to the runner and `Budgeted`.
- **Left unfixed, behaviours 4 and 5:** the console deferred block shows bare numbers in each stage's
  own unit (names, requests) with no unit label. The README explains the units; labelling them is a
  presentation choice for the user.
- **Not addressed separately:** the reviewer's note that the wildcard rule is split between the stage
  and `inventory` is resolved as far as the spec needs by the first fix.

# Follow-ups

1. Decide whether "names under a zone already known to be a wildcard" should also exclude names two
   or more levels below a wildcard zone whose own parent was never probed. If so, change the seed
   filter in `Permutations.Checks` (`internal/stages/dns/permutations.go`) to check every in-scope
   ancestor, accepting that real names under an existing sub-zone would be skipped.
2. Check the sensitive-path signatures against real files, not only the hand-written samples in
   `internal/config/testdata/sensitive/`: replace a sample with a real (redacted) file and run
   `go test ./internal/config/ -run TestBuiltinSensitivePathsSamples -count=1`.
3. Measure a real authorised run against a few hundred services, for example
   `./recon --authorised --output-dir /tmp/recon-measure <root>` after `make build`, to confirm the
   README's time estimate (54 s per service, about 9 minutes for 100) and whether 50,000 is a
   sensible `sensitive_path_max_requests` default.
4. Consider trimming the low-severity development-file entries (`/package.json`, `/Dockerfile` and
   similar) in `internal/config/builtin/sensitive_paths.yaml` if they prove noisy: each costs one
   request per service on every engagement.
5. Decide whether the console `Deferred to the next run` block should label its units (names for
   permutations, requests for sensitive paths); the place is `Console.summary` in
   `internal/report/report.go`.
6. If engagements with tens of thousands of seeds appear, let the runner ask a `Budgeted` stage for
   the cost of pending checks only (`runStage` in `internal/run/runner.go`), since `permutations`
   prices every root and seed on every pass (about 0.2 s per pass for 10,000 seeds).
7. Update the pinned golangci-lint to one built with Go 1.27.3 or later and make
   `.claude/hooks/go-check.sh` resolve package paths inside a worktree, then run
   `golangci-lint run ./...` on this branch, which no lint run has covered yet.
