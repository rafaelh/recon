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
