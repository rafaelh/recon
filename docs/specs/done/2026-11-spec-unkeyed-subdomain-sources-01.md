# Spec 1: more unkeyed passive subdomain sources

## Goal

A run with no API keys configured finds hostnames that only free passive sources report: names
that appear in `subdomains.txt` only because one of the new sources returned them. No new kind of
contact with the target is introduced.

## Behaviours

1. Five new third-party stages exist and run under `--passive`: `otx` (AlienVault OTX passive
   DNS), `hackertarget` (hostsearch), `urlscan` (urlscan.io search), `anubis` (jldc.me) and
   `certspotter` (Cert Spotter issuances). Each is listed by `recon --help` and can be named in
   `--redo`.
2. A repeatable `--skip <stage>` flag and a matching `skip` setting (`RECON_SKIP` takes a
   comma-separated list) turn stages off. The flag replaces the setting for that run, as other
   list settings do, and `--skip none` runs every stage. A skipped stage is shown as
   `not-configured (skipped)`, shown before any other reason, and performs no checks. An unknown
   stage name, naming a stage in both `--redo` and `--skip`, or naming `resolve`, `wildcard`,
   `ipowner` or `providerranges` (which other stages' safety depends on) exits 2 and lists the
   stage names. Skipping never marks any record, evidence or finding not current, and when every
   stage that contacts the target is skipped no authorisation prompt is shown.
3. Each new stage performs one check per input root that is in scope. A returned name under the
   queried root is recorded as a hostname and, like any hostname, appears in `subdomains.txt`,
   `wildcard-excluded.txt` or `excluded.csv` according to scope. Names not under the queried root
   are ignored, as the existing sources do. Only hostnames are recorded: addresses, URLs,
   certificate data and other values these sources return are not recorded.
4. Names are normalised before recording: lowercased, trailing dot removed, a leading `*.`
   removed, internationalised names kept in punycode as today, and names that are not valid DNS
   hostnames dropped. The `*.` stripping applies to every source, crt.sh included, so
   `*.dev.example.com` yields `dev.example.com`. A root that returns no names (including
   HackerTarget's "No records found" reply) completes with zero observations and is not retried.
5. When a source answers that its quota is spent (HTTP 429, or HackerTarget's "API count
   exceeded" body with status 200), the stage stops. Checks not done count as failures, so the
   stage shows `failed` if none succeeded and `done` otherwise. Under `--verbose`, one warning names
   the source, says its quota is spent, and says the checks will be retried next run. No other
   stage is affected.
6. Cert Spotter runs unkeyed. When `keys.certspotter` is set the key is sent; a 401 or 403 then
   stops the stage as in behaviour 5, and the key never appears in any output, event, file or
   warning. A key added later applies to checks not yet done; `--redo certspotter` repeats the
   rest. Result pages are followed up to `certspotter.max_pages` (default 10), which is part of
   the check, so raising it repeats the checks; reaching it completes the check with a `--verbose`
   warning that the result was truncated.
7. A source's HTTP 404 is an empty result. An unreadable body (not the expected format, or an
   error object with status 200), any other non-200 status, a network error or a body over the
   existing third-party size limit is a transient failure: the check is retried on the next run.
8. Re-running an existing engagement does not repeat the existing sources' checks. The new stages
   run, and later stages (`resolve`, `permutations`, the web and port stages) run only for the
   names the new stages add.
9. The README's passive-boundary section names each new source, and the keyed-sources list adds
   `certspotter` as optional.

# Design

**Status:** ready to build (wave 1). **Depends on:** nothing. **Owns for later specs:** `--skip`,
`run.ErrQuota`, `run.Warnf`, `httpsrc.CleanName`, `ThirdPartyRequest.KeyPrefix` and `Accept`
(see `docs/plans/2026-11-build-order.md`).

## Decisions

- **The five sources are fetchers on the existing `subdomains.Stage`**, not new packages. The
  stage already yields one check per input root and keeps only names under it (behaviour 3).
  Roots that are not in scope are skipped in `Checks` (the email stage's rule), which also fixes
  the existing sources for an excluded root.
- **Quota is a typed abort.** `run.ErrQuota` wraps `run.ErrAbortStage`. A new `httpsrc.GetQuota`
  is `Get` that also returns it for an unkeyed 429; the new sources and later quota-limited stages
  call it. `Get` itself is unchanged, so a 429 from one range publisher or from RIPEstat stays a
  failed check and does not abort `providerranges`, `asn` or the organisation pivots. A keyed 401,
  403 or 429 keeps today's abort. HackerTarget's `API count exceeded` body returns `ErrQuota` from
  the fetcher. When a stage aborts, the runner emits one
  warning (`<stage>: quota spent or key rejected; N checks will be retried next run`) and stops
  warning per aborted check; the checks still count as failed, so the `failed`/`done` state rule
  of behaviour 5 is today's arithmetic.
- **Warnings from inside a check** use `run.Warnf(ctx, format, …)`. The runner puts its warner in
  the context it passes to `Run`; with no warner the call does nothing, so stages stay testable.
  This is preferred to a new `Run` parameter because every stage and fake would change.
- **Paging caps are part of the check key**: `certspotter` keys are `<root>|pages=<n>`. Reaching
  the cap completes the check and calls `run.Warnf`.
- **Cert Spotter's optional key.** `Checks` reads `v.Settings().Keys` and puts `keyed bool` in the
  check input; `Run` sets `KeySource` only then, so egress never fails for a missing key. The key
  is sent as `Authorization: Bearer <key>` through a new `ThirdPartyRequest.KeyPrefix`. The key is
  not in the check key, so adding one later affects only checks not yet done.
- **`*.` stripping** moves into one exported helper, `httpsrc.CleanName`, that every source stage
  uses: lower-case, drop a trailing dot and a leading `*.`, then `input.ParseDomain`.
- **`--skip` is enforced in the runner's gate**, before the passive and authorisation reasons, as
  `not-configured (skipped)`. A skipped stage returns before `Checks`, so nothing is retired or
  swept and no record changes. Validation is in `cli`: unknown name, a name also given to
  `--redo`, or one of `resolve`, `wildcard`, `ipowner`, `providerranges` exits 2 with the stage
  list. `acknowledge` ignores skipped stages when deciding whether to prompt.
- **`skip` is a list setting**: `skip: [a, b]` in the file, `RECON_SKIP=a,b`, `--skip a --skip b`;
  the flag replaces the setting; `none` clears it.

## Changes

- `internal/run/stage.go`: `ErrQuota`, `Warnf`, the context key.
- `internal/run/runner.go`: `Config.Skip`; `gate` returns `skipped` first; one abort warning per
  stage; pass the warner context to `Run`.
- `internal/stages/httpsrc/httpsrc.go`: `GetQuota`, `CleanName`.
- `internal/egress/thirdparty.go`: `KeyPrefix` (prepended to the header value) and `Accept`.
- `internal/stages/subdomains/subdomains.go`: `Stage` gains `optionalKey` and
  `maxPages func(config.Settings) int`; `cleanName` becomes `httpsrc.CleanName`. New file
  `sources_unkeyed.go` with `otx`, `hackertarget`, `urlscan`, `anubis`, `certspotter` and their
  body parsers. Sources: `otx.alienvault.com`, `api.hackertarget.com`, `urlscan.io`, `jldc.me`,
  `api.certspotter.com`.
- `internal/config/config.go`: `Skip []string`, `Certspotter.MaxPages` (default 10, minimum 1,
  flag `--certspotter-max-pages`).
- `internal/cli/cli.go`: `--skip` (repeatable), validation, `acknowledge`, help footer.
- `README.md`: `--skip`, the five sources in the passive-boundary list, `certspotter` as an
  optional keyed source.

Source formats: OTX `passive_dns[].hostname`; HackerTarget `host,ip` lines, with
`error check your search parameter` and `No records found` as empty; urlscan `results[].page.domain`
and `results[].task.domain`; Anubis a JSON array of names; Cert Spotter `[].dns_names`, paged with
`after=<last id>`. A body that is not the expected shape is a transient error (behaviour 7).

## Tests

New `internal/cli/sources_unkeyed_test.go` and `skip_test.go`, with loopback fakes through
`SourceBaseURLs`:

- A name only one new source returns reaches `subdomains.txt`; an out-of-root name, an address and
  a URL in the same answer are not recorded.
- `*.dev.example.com` from crt.sh and from a new source yields `dev.example.com`.
- HackerTarget's two "empty" bodies complete with nothing and are not retried; `API count
  exceeded` and a 429 abort that stage only, show one warning under `--verbose`, and the checks run
  on the next run.
- Cert Spotter: unkeyed sends no header; keyed sends it and never prints it; 401 aborts; the page
  cap completes with a truncation warning; raising it repeats the checks.
- A 429 from a range publisher still fails only that list's check (`Get` is unchanged).
- 404 is empty; a wrong-shaped body, a 500 and an oversized body are retried next run.
- An existing engagement re-run does not repeat `crtsh` checks and resolves only the added names.
- `--skip`: state `not-configured (skipped)`, no checks, no record goes not current, the four
  protected stages and a `--redo` clash exit 2, `--skip none` overrides the setting, and no prompt
  appears when every target stage is skipped.

## Out of scope

RapidDNS (HTML scraping); recording addresses or URLs from these sources; per-source rate
settings.

# Implementation

## Develop

Built as designed, with the five sources as fetchers on `subdomains.Stage` (new file
`internal/stages/subdomains/sources_unkeyed.go`). Every behaviour is tested through `cli.Execute`
against loopback fakes, in `internal/cli/sources_unkeyed_test.go` and `skip_test.go`.

- **Runner** (`internal/run`): `ErrQuota` wraps `ErrAbortStage`; `Warnf` reads a warner the runner
  puts in the context it passes to `Run`. An aborted stage now emits one warning after its pass
  (`<stage>: quota spent or key rejected; N checks will be retried next run`) and no longer warns
  once per aborted check. This applies to the existing keyed aborts too. `gate` returns `skipped`
  before the passive and authorisation reasons.
- **`httpsrc`**: `GetQuota` (`Get` plus unkeyed 429 → `ErrQuota`, keyed 429 keeps `ErrAbortStage`) and
  `CleanName`. `ThirdPartyRequest` gained `KeyPrefix` and `Accept`.
- **Subdomain stage**: `fetcher` now takes the whole `rootInput` (root, `pages`, `keyed`) instead of
  the root. `Checks` skips roots that are not in scope, so an excluded root is no longer asked about
  by any source, old ones included. Cert Spotter's check key is `<root>|pages=<n>`; whether a key is
  set is in the check's input, not its key.
- **Config and CLI**: `skip` (list; `none` clears; `none` with stage names is rejected) and
  `certspotter.max_pages` (minimum 1). `--skip` validation (unknown name, clash with `--redo`, the
  four protected stages) is in `cli.validateSkip`; `acknowledge` ignores skipped stages.
- **Tests** (behaviour → test): 1 `TestUnkeyed_NamesAreRecorded`, `TestUnkeyed_HelpAndRedo`; 2
  `TestSkip_*`; 3 `TestUnkeyed_NamesAreRecorded`, `TestUnkeyed_ScopeDecidesTheFile`,
  `TestUnkeyed_ExcludedRootIsNotQueried`; 4 `TestUnkeyed_NamesAreNormalised`,
  `TestUnkeyed_HackerTargetEmptyBodies`; 5 `TestUnkeyed_QuotaSpentAbortsOnlyThatStage`,
  `TestRunner_QuotaAbortWarnsOnce`; 6 `TestCertSpotter_*`; 7 `TestUnkeyed_NotFoundIsEmpty`,
  `TestUnkeyed_TransientFailuresAreRetried`; 8 `TestUnkeyed_RerunResolvesOnlyAddedNames`; 9
  `TestReadme_NamesTheNewSources`; `Get` unchanged: `TestGet_RangePublisher429StaysAFailedCheck`.
- **Deviations from the plan**: `--skip` is read from `Settings.Skip` in the runner, so there is no
  separate `Config.Skip`. The help footer keeps `Stages accepted by --redo:` (an existing test pins
  it) and adds one line for `--skip`. `world_test.go` lists the five new hosts so the existing tests
  never reach the network.
- **Side effect**: `CleanName` strips `*.` before validating, so a certificate name `*.example.com`
  now records the root `example.com` itself from crt.sh, as an exact `example.com` name always did.
- **Mutation checks**: `## Tests` marks no behaviour for one, so none were run.
- **External facts**: checked once against the live services on 2026-11-11 (a single request each,
  for `example.com`), after the build. HackerTarget (`host,addr` lines), Cert Spotter (a JSON array of
  issuances with `id` and `dns_names`) and urlscan (`results[].page.domain` and `task.domain`) match the
  parsers. Three differed from `# Design`:
  - urlscan returned 100 of 7957 results with `has_more: false`, so the field does not signal
    truncation. The stage now also compares `total` with the number of results.
  - OTX answered 429 ("Anonymous access to this endpoint is limited. Please authenticate.") on two
    requests, so the passive DNS endpoint is no longer usable without a key. With the shipped code the
    stage aborts on its first check with the quota warning.
  - `jldc.me` answers 301 to `jonlu.ca`, and both hosts returned a Cloudflare challenge (403) to
    `curl`. Anubis is likely unusable from a plain client as it stands. The stage's check fails each run.

## Known limitations

- B3, urlscan: only the first page of results (the API's default of 100) is read and the rest are
  not paged. The stage warns under `--verbose` when `has_more` is set or `total` exceeds the results
  returned (the live service sets only `total`).
- B6: reaching `certspotter.max_pages` warns even when the last page was also the final one, since
  the stage cannot tell without another request.
- B5: only the five new sources use `GetQuota`. The existing unkeyed sources (`crtsh`, `wayback`,
  `commoncrawl`) still treat a 429 as a failed check.

## Simplify

Four reviewers (reuse, quality, efficiency, altitude). Fixed: `CleanName` leans on `ParseDomain`'s
normalising and only strips `*.`; the optional-key test uses `run.Env.Key`; the runner's abort
bookkeeping is one `abortFail` closure; `stageNames` is computed once in `runCommand`; `skipNone` is
unexported; the new egress `KeyPrefix` and `Accept` have a test; the new tests share one `messages`
helper, a named table type for the invalid `--skip` cases, and no longer repeat `resolveAll`. The reuse
review's finding that the invalid-`--skip` test's network check could never fail is fixed (it now
checks the fake DNS and source request counts).
Skipped: trimming the per-source failure subtests (each pins that source's own wiring, and it saves
about 3.5 s); the altitude findings below, which change seams that `# Design` decided and that spec 2
re-checks after this merges.

# Verification

## Result

Checked against the goal, B1–B9 and `## Out of scope`, by reading every changed file and running
`make test` (passes). The goal is met: the five sources are `ThirdParty` fetchers on
`subdomains.Stage`, they run under `--passive` with no keys, and a name only one of them returns
reaches `subdomains.txt`. No new contact with the target is added.

- **B1 met.** All five stages are registered, listed in `--help` and accepted by `--redo`.
- **B2 met after one fix.** Skipping is checked first in `Runner.gate`, before `Checks`, so a
  skipped stage runs no checks and retires nothing. Precedence is flag over `RECON_SKIP` (comma
  list) over the file, and `none` clears the list. `acknowledge` ignores skipped target stages.
  *Fixed:* naming a stage in both `--redo` and `--skip` exited 2 but did not list the stage names,
  which B2 requires. The message now lists the stages that can be skipped, and
  `TestSkip_InvalidExits2` checks for the list in that case too. Not in the spec, and kept:
  `--skip none` together with a stage name is rejected as a contradiction.
- **B3 partly met.** There is one check per in-scope input root, names outside the root are
  dropped, and `CleanName` (`input.ParseDomain`) drops addresses and URLs. Scope picks the output
  file. Known limitation: urlscan reads only its first results page (100), so roots with more scans
  can miss names. `## Out of scope` does not cover this.
- **B4 met after one fix.** `httpsrc.CleanName` lowercases, removes the trailing dot and a leading
  `*.`, converts to punycode and drops invalid names. Every subdomain source goes through it, crt.sh
  included. The ct-org root pivot and TLS SAN names already removed `*.`. *Fixed:* a HackerTarget
  200 reply with an empty body was treated as unreadable and retried on every run. That is the
  "returns no names" case of B4, so it now completes with zero observations (the B7 entry under
  `## Known limitations` no longer applies). `TestUnkeyed_HackerTargetEmptyBodies` covers it.
- **B5 met for the five new sources.** An unkeyed 429, or HackerTarget's `API count exceeded`, returns
  `run.ErrQuota`. The stage stops, the checks it did not do count as failures (`failed` or `done`
  by the existing arithmetic), and the runner gives one `--verbose` warning per stage per run.
  Other stages are unaffected, and `Get` is unchanged for range publishers. Known limitation:
  `crtsh`, `wayback` and `commoncrawl` still treat a 429 as one failed check. B5 says "a source",
  but `# Design` limited `GetQuota` to the new sources, so this needs a decision (Follow-ups).
- **B6 partly met.** Cert Spotter runs unkeyed. With `keys.certspotter` set it sends
  `Authorization: Bearer <key>`, a 401 or 403 aborts the stage, and the key is in no output
  (`w.anywhere`). The key is part of the check input, not its key, and `pages=N` is in the key.
  Known limitation: when the cap is reached, the truncation warning is given even if the last page
  read was the final one.
- **B7 met.** 404 is empty. A wrong shape, an error object with status 200, any other status, a
  network error and an oversized body are transient and retried. All of these are tested for each
  source.
- **B8 met.** The existing check keys are unchanged, and `TestUnkeyed_RerunResolvesOnlyAddedNames`
  shows that crtsh is not repeated and that only the added name is resolved.
- **B9 met.** The passive-boundary section names all five sources, and the keyed-sources entry
  lists `certspotter` as optional.

The source URLs and body formats follow the documented APIs but were not checked against the live
services.

## Code review

A high-effort review fixed five issues and left five. *Fixed:* the README overstated which sources
record only hostnames and stop on a spent quota (it is the five new ones); urlscan gave no warning
when its first page was not the whole result; the unknown-stage message said `--skip` even for the
setting or `RECON_SKIP`; `web.sanHost` was a copy of `CleanName` and now calls it; `validateSkip` built
its stage list on every run. *Left:* the abort warning's fixed text drops the error that caused it
(`# Design` fixes the wording); a Cert Spotter 429 on a late page discards the pages already read, so
a large root can fail on every unkeyed run (needs a design change, such as keeping paging progress);
`--redo` of a subdomain stage no longer lists an excluded root, so its earlier observations are
swept (follows from querying in-scope roots only); the unskippable list is in `cli`; `Accept` has no
caller yet.

# Follow-ups

- OTX no longer answers anonymous requests, and Anubis (`jldc.me`, moved to `jonlu.ca`) returns a
  Cloudflare challenge. Decide whether to keep, key or drop each of the two stages; until then OTX
  warns and aborts on its first check and Anubis fails one check per root on every run.
- `golangci-lint` v1.64.8 on this machine is a v1 build (the config is v2) made with Go 1.26. Install a
  v2 build made with the `go.mod` toolchain (`go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest`).
  With v2.15.0, `golangci-lint run ./...` reports only two ST1018 findings in
  `internal/sanitize/sanitize_test.go`, which this work did not touch.
- Altitude review, left as designed: an `Unskippable` interface in `run` in place of `cli`'s list of
  four names; one limit field in `subdomains.Stage` in place of `archive` and `pageCap`; a
  `View.InScopeRoots` shared with the email stage; `ThirdPartyRequest.KeyOptional` in place of the
  stage deciding whether the optional key is sent. Revisit the second when spec 2 adds its paged stages.
- `httpsrc.CleanName` and `web.sanHost` (and a variant in `orgpivot.rootObs`) are three helpers that turn a
  reported name into a hostname. Merge them into one in `input` once the dependent specs have landed,
  since specs 2, 4, 10, 13 and 17 name `httpsrc.CleanName`. The "in-scope input roots" loop is also
  repeated in the email, wildcard and subdomain stages; a `View.InScopeRoots` would serve all three.
- Decide whether `crtsh`, `wayback` and `commoncrawl` should also stop their stage on a 429 (B5 says
  "a source"; `# Design` limited `GetQuota` to the five new sources).
- A Cert Spotter check that hits its unkeyed quota partway through a large root restarts from page 1
  on the next run and may never finish; consider keeping the pages already read.
- `--redo <subdomain stage>` after excluding a root sweeps that root's earlier observations; decide
  whether that is wanted.
