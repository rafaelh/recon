# Spec 17: GitHub code search for mentions of in-scope roots

## Goal

Public repositories that mention an in-scope root domain are recorded as locations, and hostnames
in the matched code become hostname observations, so forgotten internal hostnames surface.

## Behaviours

1. A `github` stage, keyed on `keys.github` and available under `--passive`, performs one code
   search per in-scope input root for the quoted root domain, reading results up to
   `github.max_results` (default 500; GitHub serves at most 1,000). A root's search completes
   once; new mentions appear only with `--redo github` or when the cap changes. Roots added to
   scope later are searched in later passes.
2. Each match is a row in `code-mentions.csv`: repository, file path and the match's URL, all
   sanitised, plus the hostnames found in the returned fragment that are under an in-scope root.
   Those hostnames are recorded as hostnames. No fragment text is written. Personal-account
   repositories are recorded like any other; the README says so.
3. Nothing is inferred about secrets, credentials or tokens, and no finding is produced. The
   README says the stage queries GitHub about the domain, not the target, and records only
   locations.
4. When GitHub's rate limit resets within 60 seconds, the stage waits and continues; an interrupt
   during the wait exits 130 promptly with completed roots kept. Otherwise, and on a 401 or any
   other 403 or 429, the stage stops for this run as for other keyed sources. Keys never appear in
   output.
5. Rows whose match is gone after `--redo github` are marked not current. The README adds
   `github` to the keyed-sources list, the passive-boundary list of third parties and the output
   table; without a key the stage is `not-configured (no key)`.

# Design

**Status:** ready to build (wave 2). Spec 1 has merged, and the design was re-checked against
the built specs on 2026-11-14 with no correction. **Depends on:** Spec 1 (`KeyPrefix`, `Accept`,
`Warnf`, `CleanName`).

## Decisions

- **One stage, `github`**, in `internal/stages/github`, keyed, source `api.github.com`. One check
  per in-scope input root, keyed `<root>|max=<n>`, so changing `github.max_results` (default 500,
  minimum 1, maximum 1,000) searches again.
- **Request**: `GET /search/code?q="<root>"&per_page=100&page=<n>` with
  `Authorization: Bearer <key>` and `Accept: application/vnd.github.text-match+json`, which is
  what makes GitHub return fragments. Pages are read until the cap, the total, or an empty page.
- **Rate limits are handled in the stage**, so it calls `ThirdParty.Do` and reads the headers
  itself instead of `httpsrc.Get`: on a 403 or 429 with `retry-after`, or with
  `x-ratelimit-remaining: 0` and `x-ratelimit-reset`, it computes the wait; 60 seconds or less
  means wait on a timer that also selects on the context (an interrupt returns at once and the
  check is simply not completed) and retry the same page; anything else, and any 401, returns
  `run.ErrAbortStage`. A root already completed is kept either way.
- **Records**: kind `code_mention`, keyed by the match's `html_url`, with `root`, `repository`,
  `path`, `url`, `hostnames` (`;`-joined), shown while `root` is in scope and counted as
  `code mentions`. Hostnames are extracted from `text_matches[].fragment` with a hostname
  pattern, cleaned, and kept when under an in-scope root (the check input carries the scope);
  each is also a `hostname` observation. The fragment itself is never stored.
- **`code-mentions.csv`**: `repository`, `path`, `url`, `hostnames`, `root`. Because a redo
  replaces the check's observations, a match that is gone goes not current.

## Changes

- `internal/stages/github/`. `internal/cli/cli.go`: registered after the subdomain sources.
- `internal/kinds/codemention.go`. `internal/output/codementions.go`; one line in `Default()`.
- `internal/config/config.go`: `github.max_results`. `README.md`: keyed sources, boundary list,
  output table, the statement of what is and is not recorded.

## Tests

`internal/cli/github_test.go`, with a loopback fake:

- No key: `not-configured (no key)`. With one: rows for each match, hostnames under an in-scope
  root recorded and resolved, other hostnames ignored, no fragment text in any file or the
  database.
- The cap stops paging; changing it searches again; a completed root is not searched again; a
  root added later is searched.
- A reset within 60 seconds waits and continues; an interrupt during the wait exits 130 with the
  completed roots kept; a longer reset, a 401 and a plain 403 stop the stage.
- `--redo github` marks vanished matches not current; the key appears nowhere; `--passive` runs
  the stage; nothing becomes a finding.

## Carried from built specs

Follow-ups and limits of the specs already built that bear on this one.

- **Failures every source shares (Spec 1).** The stage calls `ThirdParty.Do` itself, so it does
  not get `httpsrc.Get`'s mapping. It must repeat the two parts that still apply: a truncated
  body is a transient error, and any status other than 200 that the rate-limit rule does not
  handle is one too.
- **Paged sources (Spec 2, follow-up 3).** Cert Spotter, Censys and `shodan-dns` each hand-roll
  their page cap and truncation warning, with two rules between them. The behaviours here ask
  for no truncation warning. If one is added, use the rule Censys and `shodan-dns` share (warn
  only when the source reports more than was read) and do not add a third.
- **In-scope input roots (Spec 1, follow-up 4).** Several stages already walk `v.Inputs().Roots`
  and keep the in-scope ones. Add `View.InScopeRoots()` (the in-scope input roots, sorted) in
  `internal/run/stage.go` and use it here. The existing loops move to it in one later change,
  because Specs 9, 16 and 19 are editing three of those files.
- **`Evidencer` (Spec 15).** The key carries `max=`, but the stage records only names under an
  in-scope root, so it finds no candidate and needs none.
- **The check key does not carry the scope (Specs 2 and 3)**, as for `shodan-dns` and `dnsroot`.
  A hostname in a fragment that is under another root the user adds later was ignored, so it is
  recorded only after `--redo github`. The README says so.
- **A record that is no longer current has no attributes (Spec 3, follow-up 1).** The key is the
  match's URL, so a `code-mentions.csv` row whose match is gone shows `url` and blank
  `repository`, `path`, `hostnames` and `root`. The URL names the repository and the path, so
  that is accepted; do not add a key-parsing fallback. The README says a not-current row keeps
  only its URL.
- **Hostname cleaning (Spec 1).** `httpsrc.CleanName` strips `*.` before it validates. The
  hostname helpers are merged in one change after Specs 4, 10, 13 and 17.
- **`Kind` is not comparable (Spec 3).** Compare `Name()`.

## Out of scope

Secrets detection; cloning or reading file contents; GitLab and paste sites.
