# Spec 13: web identifiers as pivot evidence

## Goal

Tracking IDs, favicon hashes and copyright lines found on in-scope pages are recorded so the user
can pivot to related sites, and with a Shodan key the pivot is done for them.

## Behaviours

1. From pages the probe and crawl fetched, recon records per web service, as the union over its
   fetched pages: Google Analytics and Tag Manager IDs found in `gtag/js?id=`, `gtag('config',
   …)` or GTM snippet contexts; Facebook pixel IDs found in `fbq('init','<digits>')` or
   `facebook.com/tr?id=`; the first line of the root page's visible text containing `©` or `(c)`
   followed by a year, at most 120 characters, sanitised; and the favicon hash from behaviour 2.
2. The probe fetches one favicon per web service: the same-host `<link rel=icon>` URL if present,
   else `/favicon.ico`; a redirect is followed only to the same host; a 404, HTML or non-image
   response gives no hash; an icon link on another host falls back to `/favicon.ico`. The hash is
   the one Shodan's `http.favicon.hash` uses (signed 32-bit MurmurHash3 of the base64 body with
   line breaks every 76 characters), pinned by a test with a known value. The README adds one
   favicon GET per service to the list of requested paths.
3. `web-services.csv` gains `analytics_ids`, `pixel_ids`, `favicon_hash` and `copyright`.
4. An `identifier-pivot` stage, keyed on `keys.shodan` and available under `--passive`, searches
   Shodan once per distinct analytics ID, pixel ID or favicon hash seen on an in-scope service
   that is not served by a SaaS platform, first result page only, up to
   `identifier_pivot.max_queries` per run (default 50, remainder on later runs). A hostname on a
   returned host is recorded as a hostname when under an in-scope root, otherwise its registrable
   domain is a candidate root whose `sources` entry reads `identifier-pivot:<id>`. Returned
   addresses are classified by the normal scope rules, appear in `ips.csv`, and are never
   contacted when out of scope. A search returning more than 200 hosts records none and produces
   a `--verbose` warning.
5. Favicon hashes on a built-in list of defaults (the empty file and common framework icons,
   listed in the README) are not pivoted. Copyright lines are never pivoted.
6. A key without search access shows the stage failed with one clear warning; exhausted credits
   stop the stage for this run as for other keyed sources. Without a key the identifiers are still
   recorded and the stage is `not-configured (no key)`.
7. Under `--passive` no new identifiers are collected, but the pivot still searches identifiers
   recorded on earlier runs. Existing engagements gain identifiers only after `--redo httpprobe`
   and `--redo crawl`; the README says so.

# Design

**Status:** ready to build (wave 2). **Depends on:** Spec 1 (`Warnf`, `ErrQuota`, `CleanName`),
Spec 6 (`run.Budgeted`), Spec 15 (candidate evidence), and Spec 12 for the shape of the probe's
`service()` seam (re-check the call site once it has merged).

## Decisions

- **Each identifier is a record**, kind `web_identifier`, keyed `<service>|<type>|<value>` with
  `service`, `host`, `type` (`analytics`, `pixel`, `favicon`, `copyright`) and `value`, shown
  while the host is in scope. One record per identifier makes "the union over fetched pages" the
  store's ordinary behaviour: the probe and the crawl each observe what they saw, and an
  identifier stays current while either still sees it. A single merged attribute would let one
  stage overwrite the other.
- **Extraction is pure**, in `internal/stages/web/identifiers.go`: regular expressions anchored to
  the contexts in behaviour 1, and the copyright line from the root page's visible text. The probe
  calls it on the pages of its redirect chain that came from the service's origin; the crawl on
  each page it scans. Neither check key changes.
- **Favicon**: the probe makes one extra GET per service through `egress.Link`, which
  enforces same host: against the final page for its `link[rel~=icon]` URL when that page is on
  the service's host, and otherwise (an off-host icon link, or a chain that ended on another host)
  against the service's first response for `/favicon.ico`. A redirect is
  followed once and only to the same host. The hash is computed only for a 2xx response whose
  content type is an image type or absent and whose body does not start with `<`.
  `web.FaviconHash` implements MurmurHash3 x86-32 over the base64 body with a newline every 76
  characters (and a trailing newline), returned as a signed 32-bit integer; it is written by hand,
  about thirty lines, to avoid a dependency.
- **`web-services.csv`** gains `analytics_ids`, `pixel_ids`, `favicon_hash`, `copyright`, built by
  grouping current `web_identifier` records by service.
- **`identifier-pivot`** (`internal/stages/shodan/pivot.go`, keyed on `shodan`, third-party
  contact) yields one check per distinct analytics ID, pixel ID or favicon hash on a shown service
  that is not `SaaSServed`, skipping favicon hashes on the built-in default list. Keys:
  `favicon|<hash>` and `html|<id>`. It is `Budgeted` by `identifier_pivot.max_queries` (default
  50, minimum 1). `Run` requests the first result page of `http.favicon.hash:<h>` or
  `http.html:"<id>"`; a total above 200 records nothing and warns. Otherwise each match's address
  is an `ip` observation, each hostname under an in-scope root a `hostname`, and any other
  hostname's registrable domain a `root`.
- **Evidence**: `Evidencer` returns (`identifier-pivot:<id>`, the identifier).
- **Under `--passive`** the probe and crawl are gated as today, so nothing new is collected, while
  the pivot (third-party) runs over records kept from earlier runs.

## Changes

- `internal/kinds/webidentifier.go`. `internal/stages/web/identifiers.go`, `favicon.go`; one call
  each in `probe.go` and `crawl.go`. `internal/stages/shodan/pivot.go`; registered after `jsparse`.
- `internal/output/output.go`: four columns. `internal/config/config.go`: the setting.
- `README.md`: the favicon GET in the requested-paths list, the default favicon list, columns.

## Tests

- `internal/stages/web`: extraction contexts (and near-misses that must not match); the copyright
  rule and 120-character cut; `FaviconHash` against a known Shodan value.
- `internal/cli/identifiers_test.go`: union of probe and crawl pages; favicon from the same-host
  link, the `/favicon.ico` fallback, an off-host link, a probe chain that ends on another host, a redirect off host, a 404 and an HTML
  answer; exactly one favicon GET per service.
- Pivot: one search per distinct identifier; SaaS-served services and default favicons are not
  pivoted; copyright never; the per-run cap defers; over 200 hosts records nothing and warns;
  in-scope hostnames and candidate roots with `identifier-pivot:<id>` in `sources`; returned
  addresses appear in `ips.csv` and **(canary)** are never contacted when out of scope; a key
  without search access fails the stage with one warning; `--passive` pivots stored identifiers
  and collects none.

## Out of scope

Other tracker families; pivoting on copyright text; favicon search on sources other than Shodan.
