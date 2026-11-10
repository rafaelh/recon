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
