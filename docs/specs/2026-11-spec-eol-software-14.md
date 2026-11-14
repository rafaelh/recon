# Spec 14: end-of-life software

## Goal

A web server, framework or network service whose detected version is past the end of security
support for its release cycle is reported as a finding, from versions recon already captures.

## Behaviours

1. recon embeds a table of products and the end of security support of each release cycle, as
   endoflife.date records them, for each product endoflife.date tracks that recon can version
   from Wappalyzer or from SSH, FTP and SMTP banners. The README lists the products, the data
   source and the date the data was taken. A run warns once when the embedded data is older than
   twelve months.
2. A version whose cycle's end date is on or before the run date (UTC) is a medium finding of type
   `eol` in `risk-eol-software.csv`: target (the service URL, or `ip:port` with a hostnames column
   as in `risk-ports.csv`), product, version, end date and where it was seen (`web` or `banner`).
   Each end-of-life product on a service or port is its own finding. A version carrying a
   distribution suffix (`Debian`, `Ubuntu`, `CentOS`, `+deb`, `~bpo` and the like) is one step
   lower (low) with `distribution build` in the detail. A version known only from a Shodan port
   report is one step lower and marked unconfirmed, as in Spec 4.
3. A cycle whose end date is after the run date and within `eol_warn_days` (default 90, flag
   `--eol-warn-days`, minimum 1, 0 disables) is a low finding of type `eol-approaching`.
4. A version that cannot be matched to a cycle in the table produces no finding.
5. SSH, FTP and SMTP banners in `open-ports.csv` gain `product` and `version` columns when the
   banner is recognised (OpenSSH, Dropbear, ProFTPD, vsftpd, Pure-FTPd, Postfix, Exim, Sendmail,
   Microsoft IIS/FTP and Exchange SMTP at least, listed in the README); unrecognised banners leave
   both empty. Values are sanitised like other target text. Existing engagements gain the columns
   on their next run without new contact.
6. Findings are re-derived on every run from the latest probe and banner records and the run
   date, so one may appear with no new contact when the date passes an end date or the table
   changes, and under `--passive` they come from records kept from earlier runs. A finding goes not
   current when `--redo httpprobe` or `--redo ports` no longer shows that version. Only in-scope web
   services and port-eligible addresses are assessed, as for other findings. Both types appear in
   the `--help` severity table and the file in the README output table.

# Design

**Status: review before building (wave 3).** The parts that read Shodan's ports depend on Spec 4,
which is not built yet. Everything else is complete, and was re-checked against the built specs on
2026-11-14 with no correction; after Spec 4 merges, re-read the items marked *Review*. **Depends
on:** Spec 4 (`reported_port`, the `confirmed` column and the "one step lower" rule,
`open-ports.csv`'s merged rows).

## Decisions

- **End-of-life data is embedded data in a pure package**, `internal/eol`: one JSON file per
  product as endoflife.date publishes it, under `internal/eol/data/`, a `products.yaml` that maps
  a detected name (a Wappalyzer technology or a banner product) to a product file and says how a
  version maps to a release cycle (major, or major.minor), and a `DATE` file with the day the data
  was taken. `eol.Lookup(name, version) (cycle, end string, ok bool)` and `eol.DataDate()`.
- **The data is refreshed by a `make eol-data` target that uses `curl`**, not by Go code: no
  first-party package may import a network package or `os/exec`. The target rewrites the JSON
  files and `DATE`; the diff is reviewed and committed.
- **Banner recognition is pure**, in `internal/banner`: `Parse(banner string) (product, version
  string, distro bool)` for the listed SSH, FTP and SMTP servers, where `distro` is true when the
  version carries a distribution suffix. It reads the stored banner, so `open-ports.csv`'s
  `product` and `version` columns are derived on read and existing engagements gain them on their
  next run with no contact.
- **Findings are derived**, in `internal/findings/eol.go` (category `eol-software`, file
  `risk-eol-software.csv`): for each shown web service, each `Name:version` technology; for each
  shown open port, the parsed banner. Past the end date is `eol` (medium); within `eol_warn_days`
  is `eol-approaching` (low); a `distro` version is one step lower with `distribution build` in
  the detail; no cycle match means no finding. The key is `eol-software|<type>|<target>|<product>`
  so each product on a target is its own row. *Review:* a version known only from a
  `reported_port` banner is one step lower with `confirmed: no`, using Spec 4's helper.
- **Columns**: `severity`, `target`, `hostnames`, `type`, `product`, `version`, `end_date`,
  `seen` (`web` or `banner`), `confirmed`.
- **`eol_warn_days`**: default 90, minimum 0, where 0 disables the approaching type; flag
  `--eol-warn-days`.
- **Stale data warning**: at the start of a run, if the run date is more than twelve months after
  `eol.DataDate()`, the runner emits one warning that is not limited to `--verbose`.

## Changes

- `internal/eol/`, `internal/banner/`. `Makefile`: `eol-data`.
- `internal/findings/eol.go`, `table.go`, `records.go`, `findings.go`.
- `internal/output/ports.go`: `product`, `version` (*Review:* the file Spec 4 creates).
- `internal/config/config.go`: `eol_warn_days`. `internal/run/runner.go`: the warning.
- `README.md`: products, data source and date, banners recognised, the file, the severity table.

## Tests

- `internal/eol`: lookups across cycle shapes, an unknown product, an unmatched version; every
  product named in `products.yaml` has a data file.
- `internal/banner`: each listed server, distribution suffixes, unrecognised banners.
- `internal/findings`: past, approaching, future, the date boundary (on the end date is `eol`),
  the distribution step, several products on one service, `eol_warn_days: 0`, an out-of-scope
  service and an ineligible address.
- `internal/cli/eol_test.go`: findings appear with no contact when the clock passes an end date
  and under `--passive` from stored records; `--redo httpprobe` with a new version marks the old
  finding not current; `open-ports.csv` columns on an existing engagement; the stale-data warning;
  `--help` and the README table.

## Carried from built specs

Follow-ups and limits of the specs already built that bear on this one.

- **A finding that is no longer derived keeps only what its key holds (Specs 3 and 12).** The
  store keeps attributes only from current observations. The key
  `eol-software|<type>|<target>|<product>` gives such a row its type, target and product; its
  version, end date and severity are blank, as in every risk file.
- **Version banners are not a source (Spec 12).** `web-services.csv` has a `version_disclosure`
  column read from `Server` and `X-Powered-By`. Versions come only from Wappalyzer technologies
  and port banners here, as `## Out of scope` says; do not read that column.
- **Findings layout (Spec 12).** A category is its own file in `internal/findings`, with its
  rows appended to `table`, one entry in `riskFiles` and one line in `deriver.findings()`.
- **`Kind` is not comparable (Spec 3).** Compare `Name()`.
- **Console text (Spec 22).** If Spec 22 has merged, the stale-data warning is a WARN line. It is
  already meant to show without a flag.

## Out of scope

CVE matching; products endoflife.date does not track; versions from sources other than
Wappalyzer and banners.
