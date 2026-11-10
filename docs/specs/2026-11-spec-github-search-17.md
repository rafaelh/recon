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
