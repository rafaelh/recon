# Spec 12: web posture evidence and low findings

## Goal

From responses recon already has, obvious web configuration weaknesses are reported as low
findings, without any additional request or probing technique, and without burying the user in
near-universal conditions.

## Behaviours

1. For each live in-scope web service the probe requested, recon records: whether the first HTTPS
   response carries `Strict-Transport-Security`; each cookie set by any response in the redirect
   chain that lacks `Secure` on an HTTPS service, or lacks `HttpOnly` on any service (cookie names
   only, never values, sanitised); whether the final same-origin page of `/` is a directory listing
   (a title or first heading beginning `Index of /`); and `Server` and `X-Powered-By` values that
   contain a version, meaning a `/` followed by a digit (`Apache/2.4.41` yes; `nginx` and
   `ASP.NET` no).
2. `web-services.csv` gains `hsts` (`yes`/`no`, blank for HTTP), `insecure_cookies` (cookie names
   with the missing flag, `;`-joined), `directory_listing` (`yes`/`no`) and `version_disclosure`
   (the header values).
3. Low findings in `risk-web-posture.csv`, one row per service and condition: `missing-hsts` (HTTPS
   services only), `insecure-cookie` (missing `Secure` on HTTPS; cookies `;`-joined in one row),
   `directory-listing` and `version-disclosure`. Missing `HttpOnly` is evidence only, not a
   finding. No posture finding is made for a service addressed by IP literal or served by a SaaS
   platform. Headers such as CSP and `X-Frame-Options` are intentionally not assessed.
4. A condition absent after `--redo httpprobe` marks its finding not current. Existing
   engagements gain the columns and findings only after `--redo httpprobe`; the README says so.
5. `recon --help`'s severity list includes the new finding types and the README's output table
   adds `risk-web-posture.csv`.

# Design

**Status:** ready to build (wave 1). **Depends on:** nothing. **Shares with Specs 13 and 18:** the
probe's `service()` function and `web-services.csv`; each adds one call and its own columns.

## Decisions

- **Posture is an evidence kind of its own**, `web_posture`, keyed by the service URL like
  `web_service` and shown while its `host` is in scope. The probe writes it in the same check as
  the service, so `--redo httpprobe` refreshes it and existing engagements gain it only then, with
  no change to the probe's check key. A separate kind keeps this spec out of `WebServiceAttrs`,
  which Specs 13 and 18 also touch.
- **Attributes**: `host`, `hsts` (pointer: unset for HTTP), `cookies_no_secure`,
  `cookies_no_httponly` (cookie names, `;`-joined), `directory_listing`, `version_disclosure`
  (header values, `;`-joined).
- **Which responses are read**: HSTS from the service's first response; cookies from every
  response in the probe's redirect chain, as behaviour 1 says (`Secure` is judged only for
  responses received over HTTPS); the directory listing from the last
  same-origin page of the chain; version headers from the first response.
- **Extraction is pure**, in `internal/stages/web/posture.go`: `posture(chain []egress.Response)`.
  `service()` collects the chain it already walks and makes one call.
- **`web-services.csv`** joins the posture record by key: `hsts`, `insecure_cookies` (each name
  followed by `(secure)`, `(httponly)` or both), `directory_listing`, `version_disclosure`.
- **Findings** are a new category `web-posture` in `internal/findings/posture.go`:
  `missing-hsts`, `insecure-cookie`, `directory-listing`, `version-disclosure`, all low, one per
  service and condition, written to `risk-web-posture.csv` (`severity`, `url`, `type`, `detail`).
  No finding for an IP-literal service or one `inv.SaaSServed` reports.

## Changes

- `internal/kinds/webposture.go`: the kind. `internal/stages/web/posture.go` and one call in
  `probe.go`. `internal/output/output.go`: four columns (see the column order in the build-order
  plan). `internal/findings/posture.go`, `table.go`, `records.go` (`riskFiles`), `findings.go`.
- `README.md`: the file, the columns, the `--redo httpprobe` note.

## Tests

- `internal/stages/web`: `posture` over crafted chains: HSTS on first response only; cookie flags
  case-insensitive; names sanitised, values never kept; `Index of /` in title or first heading;
  `Apache/2.4.41` yes, `nginx` and `ASP.NET` no.
- `internal/findings`: each condition, HTTP services have no HSTS finding, `HttpOnly` alone makes
  no finding, IP-literal and SaaS-served services make none.
- `internal/cli/web_posture_test.go`: columns and `risk-web-posture.csv` from a loopback service;
  an existing engagement gains them only after `--redo httpprobe`; a fixed condition goes not
  current after a redo; no request beyond the probe's (canaries); `--help` lists the types.

## Out of scope

CSP, `X-Frame-Options` and other headers; posture of crawled pages.

# Implementation

## Develop

`web_posture` is a new evidence kind (`internal/kinds/webposture.go`, `HostAttr: "host"`). The probe's
`service()` now keeps the chain it walks and makes one call, `posture(host, chain)`
(`internal/stages/web/posture.go`), and stores the result beside the `web_service` record under the
same key, in the same check. The probe's check key is unchanged, so `--redo httpprobe` is what
refreshes posture. Because the store merges only current observations, a redo that finds a
condition gone drops it from the record, and the finding is no longer derived.

- **Extraction.** The chain is a slice of `hop` values, each a response reduced to its scheme,
  origin, headers, body and media type; a hop parses its page at most once, so the title and the
  directory-listing check share one parse. HSTS is read from the first response and is unset for
  HTTP. Cookies come from every response in the chain, and are parsed by hand: `net/http` is not
  allowed outside egress.
  Only names are kept (sanitised), `Secure` is judged only for responses received over HTTPS, and
  names are sorted and `;`-joined. A directory listing is read from the last response whose origin
  matches the first, as `text/html` whose title or first `h1`-`h6` begins `Index of /`. Version
  headers come from the first response (`Server`, then `X-Powered-By`, all values, sanitised).
- **Findings.** `internal/findings/posture.go` derives `web-posture` findings from current,
  visible posture records, skipping IP-literal hosts and `inv.SaaSServed` hosts. It writes
  `risk-web-posture.csv` (`severity`, `url`, `type`, `detail`) via `riskFiles`.
- **Output.** `web-services.csv` appends `hsts`, `insecure_cookies`, `directory_listing`,
  `version_disclosure`, joined to the posture record by key. A service with no current posture
  record has the four cells blank.
- **README.** A "Web posture" section, the `risk-web-posture.csv` row, and the `--redo httpprobe`
  note. `--help` needed no change: it prints the severity table, which gained four rows.

How each behaviour is tested:

1. Extraction: `internal/stages/web/posture_test.go` over crafted chains (HSTS first response only,
   cookie flags in any case, names sanitised with values never kept, `Index of /` in title or first
   heading, `Apache/2.4.41` yes and `nginx`/`ASP.NET` no, chain and same-origin rules). The
   `web_posture` kind is pinned in `internal/kinds/evidence_test.go`.
2. Columns: `internal/cli/web_posture_test.go` (`ColumnsAndFindingsFromLoopbackServices`,
   `RedirectChainDecidesWhatIsRead`).
3. Findings: `internal/findings/posture_test.go` (each condition, one row per service and
   condition, no HSTS or Secure finding for HTTP, `HttpOnly` alone makes none, IP-literal and
   SaaS-served make none, scope and currency) and the CLI tests, including the canary-style check
   that each fake server saw only `GET /` (`onlyGET` and `uris`).
4. Currency and redo: `ExistingEngagementGainsPostureOnlyAfterRedo` deletes the posture and
   finding records to look like an older engagement, shows a plain run adds nothing and sends no
   request, then shows `--redo httpprobe` adds the columns and findings.
   `FixedConditionGoesNotCurrentAfterRedo` shows the rows stay on record, not current.
5. Help and README: the four finding types are rows of the severity table, which `--help` prints.
   `TestSeverityTable` (extended) pins them and `TestRiskPlumbing_Help` requires every table row in
   `--help`, so no test of its own was added. The README is checked by reading.

Existing tests that pin exact lists were updated: the findings file list, the default output
registry and the `web-services.csv` header.

Deviations from the plan:

- `posture` takes `[]*hop`, a small type of the web package, not `[]egress.Response` as the design
  said. `egress.Response` has no exported constructor, so crafted chains could not be built outside
  egress, and adding one would let any package invent a response origin to feed `egress.Link` and
  `egress.Redirect`. A hop also lets the probe and `posture` share one HTML parse. Real responses
  have canonical header keys, so hops are read by canonical key and the tests use them.
- The spec's tests list a canary check only for `internal/cli`; no new canary was needed because
  the per-site request logs already prove no request beyond the probe's.
- `page.title()` now shares a `firstText` helper in `html.go` with the first-heading lookup.

No external fact in `## External facts` differed (the spec has none).

Mutation checks: `## Tests` marks no behaviour for a mutation check, so none were run.

## Known limitations

- Behaviour 1 (HSTS): any non-blank `Strict-Transport-Security` counts as present, including
  `max-age=0`, which switches HSTS off. The value is not parsed.
- Behaviour 1 (cookies): a cookie set by several responses is reported if any of them lacks the
  flag, even if a later one sets it. `Secure` is judged per response, by the scheme it arrived
  over, so a cookie set on an HTTP hop of an HTTPS service's chain is never reported, and an HTTP
  service whose chain upgrades to HTTPS lists a cookie in `insecure_cookies` as `(secure)` with no
  finding (findings need an HTTPS service).
- Behaviour 3 (SaaS exemption): it is judged on the service's own host. A cookie set by a
  SaaS-served host the chain redirects to still counts against the service.
- Behaviour 1 (directory listing): the status code is not checked, so an error page whose title
  begins `Index of /` counts.
- Behaviour 4 (existing engagements): the "older engagement" in the test is simulated by deleting
  records from the state database, not by running an older binary.
- A finding no longer derived keeps only the columns its key identifies (`url` and `type`), as for
  every other category, so a not-current row has a blank `severity` and `detail`.
- `golangci-lint` could not be run here: the installed binary was built with Go 1.26 and `go.mod`
  needs 1.27.3. `gofmt`, `go vet` for the four targets and the full test suite were run.

# Verification

## Result

All five behaviours and the goal are met. `make test` (cross-target `go vet` and
`go test -race ./...`) passes.

- **Goal.** Posture is read only from the responses `httpprobe` already receives
  (`internal/stages/web/posture.go`, one call in `service()`), and the CLI tests confirm that each
  fake server saw only `GET /`. Near-universal conditions stay out of the findings: a missing
  `HttpOnly` is evidence only, and CSP and `X-Frame-Options` are not read.
- **B1: met.** The probe stores a `web_posture` record for every live service, in the same check as
  its `web_service`. HSTS is read from the first response and left unset for HTTP. Cookies come from
  every response in the chain. Only their sanitised names are kept. `Secure` is judged for
  responses received over HTTPS and `HttpOnly` for every response, and flags match in any case.
  The directory listing is read from the last same-origin page, by title or first `h1`-`h6`
  beginning `Index of /`. A version is a `/` followed by a digit in `Server` or `X-Powered-By`.
  Read literally, B1 judges `Secure` "on an HTTPS service". The design judges it per response
  instead, so an HTTP service that redirects to HTTPS lists a non-`Secure` cookie from its HTTPS
  hop as `(secure)` in `web-services.csv`. B3 still gives that service no finding. The design chose
  this, so it is not counted as a defect. The `## Known limitations` items for B1 (`max-age=0`
  counted as present, a cookie set more than once, status not checked) fall within B1's wording.
- **B2: met.** `web-services.csv` appends `hsts`, `insecure_cookies` (`name(secure)(httponly)`),
  `directory_listing` and `version_disclosure`, in the build-order plan's column order.
- **B3: met.** `risk-web-posture.csv` (`severity`, `url`, `type`, `detail`) has one low row per
  service and condition. `insecure-cookie` is raised only for HTTPS services, with its cookies in
  one row. `HttpOnly` alone makes no finding, and IP-literal and SaaS-served services make none.
- **B4: met.** The probe's check key is unchanged, so a plain re-run adds nothing and
  `--redo httpprobe` adds the evidence. A condition that is gone after a redo leaves its finding on
  record but not current. The README says this. The test simulates an older engagement by deleting
  records, as `## Known limitations` says. That is a limit of the test, not of the behaviour.
- **B5: met.** `recon --help` prints the severity table, which includes the four new types (checked
  by running `go run ./cmd/recon --help`). The README output table has the `risk-web-posture.csv`
  row.

Changed during verification: the README's `web-services.csv` row said the posture columns were
described "(see below)", but the Web posture section comes before the table. It now says "(see
Web posture above)".

`golangci-lint run ./...` still can't run. The installed binary is v1.64.8, built with Go 1.26.1,
while `.golangci.yml` is v2 config and `go.mod` targets Go 1.27.3.

# Follow-ups

- Rebuild `golangci-lint` with Go 1.27.3 and run `golangci-lint run ./...` on this branch.
- `.claude/hooks/go-check.sh` resolves paths against the main checkout (`CLAUDE_PROJECT_DIR`), so
  in a worktree it fails with "main module does not contain package ..." on every edit. It needs to
  use the worktree's root.
