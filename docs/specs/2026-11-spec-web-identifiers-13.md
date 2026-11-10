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
