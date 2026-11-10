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
