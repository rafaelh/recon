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
