# Spec 11: JavaScript endpoint extraction

## Goal

The API hostnames and paths referenced inside an in-scope site's own JavaScript are recorded as
URLs and hostnames, so the services behind a single-page application are discovered. Nothing found
inside a script is ever requested.

## Behaviours

1. The crawl records which URLs it saw in a `<script src>` element. A `jsparse` stage (target
   contact, skipped under `--passive` and until authorisation) performs one check per such URL
   whose host is in scope, not excluded, not wildcard-only and not served by a SaaS platform.
   Scripts on any other host, CDNs included, are not fetched. The check is one GET of the script
   URL; a redirect is followed only to the same in-scope host; a non-2xx response completes with
   nothing; a timeout is a transient failure.
2. At most `jsparse.max_scripts` (default 50) scripts are fetched per script origin, in URL order;
   the rest are not fetched and a `--verbose` warning says how many were skipped.
3. From the script body recon records, in `urls.csv` with `found_by` including `jsparse` and no
   status: absolute URLs and protocol-relative references whose host is under an in-scope root;
   and quoted paths beginning with `/`, at least two characters long, without whitespace,
   backslashes or template placeholders (`${`, `{{`), joined to the script's own origin.
   Hostnames under an in-scope root are recorded as hostnames. Hostnames outside scope are
   ignored, as the crawl does. Examples: `/api/v1/users` and `//api.example.com/v2` are recorded;
   `/.js`, `/\d+/g`, `/ ` and `//comment` are not.
4. At most 500 URLs are recorded per script, in order of appearance; reaching the cap produces a
   `--verbose` warning.
5. A response with a `text/html` content type or a body starting with `<` completes with nothing.
   Scripts are read up to 4 MiB (larger than the usual target-response limit, because bundles are
   large); a longer body completes with the URLs found in the part read and a `--verbose` warning
   that it was truncated. The README states the limit.
6. No stage requests a URL recorded from a script. The README's passive-boundary list of requested
   paths adds "same-site script files referenced by crawled pages" and says the URLs found in them
   are recorded, never requested.
7. When a re-crawl no longer references a script, the URLs found only in that script are marked
   not current.
8. Existing engagements gain script records only when the crawl runs again (`--redo crawl`); the
   README says so.

# Design

**Status:** ready to build (wave 2). Spec 1 has merged, and the design was re-checked against
the built specs on 2026-11-14 with no correction. **Depends on:** Spec 1 (`run.Warnf`). **Shares
with Spec 13:** `crawl.go` (each adds one emit in `observations()`); nothing in the probe.

## Decisions

- **Scripts are a kind**, `script` (key: the normalised script URL; `url`, `host`, `service`),
  shown while its host is in scope. The crawl emits one for every `script[src]` it sees, in
  addition to the `url` record it writes today. The crawl's check key does not change, so existing
  engagements gain scripts only when the crawl runs again.
- **`jsparse`** (`internal/stages/web/jsparse.go`, target contact) yields one check per `script`
  whose host is a probe hostname (in scope, resolved, not wildcard-only), not excluded and not
  `SaaSServed`. Per script origin it takes the first `jsparse.max_scripts` (default 50, minimum 1)
  and warns from `Checks` about the rest. Scripts already parsed are taken first, then others in
  URL order: each completed check also emits a `script_parsed` marker (key: the URL), so a script
  that was fetched is never pushed past the cap, and so never retired, by a new script that sorts
  before it. Key: `<url>|p=<parser hash>`. The stage is
  `Retiring`, so when a re-crawl stops referencing a script its check is retired and the URLs only
  it observed go not current (behaviour 7), and a parser change re-reads scripts.
- **Egress cannot be asked for an arbitrary path.** A new constructor `egress.Script(url)` builds
  a request that the policy allows only if the URL is in `Policy.Scripts`, a set the runner builds
  from current `script` records, exactly as sensitive paths are allowed by list index. Host scope,
  exclusion and port rules apply as for any target request. Script responses are read up to
  4 MiB; `Response.Truncated` is set when the cap cut the body.
- **Redirects**: `egress.Redirect` is used only when the target is on the same host; anything else
  completes with nothing. Non-2xx completes with nothing; a timeout is a transient error.
- **Extraction is pure**: `web.ExtractEndpoints(body, origin)` returns candidate URLs in order of
  appearance from string literals: absolute `http(s)://` URLs, `//host/path` references, and
  quoted paths starting with `/` that are at least two characters with no whitespace, backslash,
  `${` or `{{`, and whose first segment is not empty and not just an extension. The stage keeps
  those whose host is in scope, records at most 500 as `url` observations without a status, and
  records their hosts as `hostname` observations. `text/html` or a body starting with `<` yields
  nothing.
- **Nothing recorded here is requested**: the crawl queues only links from pages it fetched, and
  `egress.Script` accepts only crawl-recorded script URLs.

## Changes

- `internal/kinds/script.go` (`script`, `script_parsed`). `internal/stages/web/crawl.go`: emit `script`.
- `internal/stages/web/jsparse.go`, `endpoints.go`. `internal/cli/cli.go`: after `crawl`.
- `internal/egress/http.go`, `egress.go`: `Script`, `Policy.Scripts`, the 4 MiB cap, `Truncated`.
- `internal/run/runner.go`: `script` in `scopeKinds`; `Policy.Scripts` in `buildScope`.
- `internal/config/config.go`: `jsparse.max_scripts`. `README.md`: boundary list, limit, stage.

## Tests

- `internal/stages/web`: the extraction table, including every example in behaviour 3, the 500
  cap and template placeholders.
- `internal/egress`: `Script` is refused for a URL not in the policy set, a candidate host, an
  excluded host and under `--passive`; the 4 MiB cap and `Truncated`.
- `internal/cli/jsparse_test.go`: same-host scripts are fetched once, CDN and SaaS-hosted ones
  never; the per-origin cap and its warning; a parsed script stays within the cap, and its URLs stay
  current, when new scripts sort before it; URLs appear in `urls.csv` with `found_by` including
  `jsparse` and no status; in-scope hosts become hostnames; an HTML answer and a non-2xx record
  nothing; a truncated bundle records what was read and warns; a script dropped by a re-crawl
  retires its URLs; **canary:** no URL found in a script is ever requested.

## Carried from built specs

Follow-ups and limits of the specs already built that bear on this one.

- **`Evidencer` (Spec 15).** A stage whose check key carries a setting and which can find
  candidates must implement it. This key carries the parser hash, but the stage records only
  names under an in-scope root, so it finds no candidate and needs none. If that ever changes,
  it must implement `Evidencer` and drop the hash from the item.
- **The check key does not carry the scope (Specs 2 and 3)**, as for `shodan-dns` and `dnsroot`.
  A URL or hostname under a root the user adds later was ignored when its script was read, so it
  is recorded only after `--redo jsparse`. The README says so beside the `--redo crawl` note.
- **Merge order (build-order plan).** Spec 21 moves the scope and inventory construction to
  `run.BuildScope`. If it has merged, `script` joins the kinds that function reads and
  `Policy.Scripts` is built beside it, not in `runner.go`.
- **`Kind` is not comparable (Spec 3).** Compare `Name()`.
- **Console text (Spec 22).** If Spec 22 has merged, the `--verbose` warnings of behaviours 2, 4
  and 5 are WARN lines, shown without a flag.

## Out of scope

Source maps, inline scripts, executing JavaScript, secrets detection.
