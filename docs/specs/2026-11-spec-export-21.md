# Spec 21: whole-engagement export

## Goal

Everything recon has recorded about an engagement can be exported as machine-readable lines for
other tooling, without the CSV columns having to stay stable.

## Behaviours

1. `recon export -e <name>` writes to stdout one JSON object per line for every record in the
   engagement, current or not: `kind`, `key`, `attrs`, `current`, `first_seen`, `last_seen`, the
   stages currently observing it (empty for records that are not current), and either `scope`
   (`in-scope`, `candidate`, `excluded`) for hostnames, roots, netblocks and excluded items, or
   `shown` (`true`/`false`) for every other kind, classified with the engagement's inputs and the
   current configuration. The engagement's inputs and exclusions are exported as their own lines
   (`kind` `input` and `exclusion`). The authorisation acknowledgement, netblock approval and
   settings are not exported.
2. `--output <file>` writes to a file instead, replacing an existing file atomically; a write
   failure exits 1. `--current` limits the export to current records and `--kind <kind>`
   (repeatable) to the given kinds; both filters combine. Kind names are listed by
   `recon export --help`, and an unknown kind exits 2.
3. Secrets are never present: the export contains no API keys.
4. `export` does not take the run lock: it reads a consistent snapshot and works while a run is in
   progress, and never writes to the engagement. It exits 1 for an engagement that does not exist
   (creating nothing) or a directory that is not a recon engagement, found under `--output-dir`
   or `output_dir` as for a run. It makes no network requests.
5. Target-supplied text (titles, banners) is sanitised as for console output.
6. The README documents the command and says that the stable names are the stored attribute
   names kept by the state database and the export's own field and kind names; finding attributes
   are derived and may change.
