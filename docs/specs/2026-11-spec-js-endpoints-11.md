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
