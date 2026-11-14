# Build order and shared seams for the November 2026 specs

Written 2026-11-11 with the `# Design` sections of `docs/specs/2026-11-spec-*.md`. It says which
specs can be built at the same time, which must wait, which spec owns each piece of shared
plumbing, and how to keep parallel branches from colliding. Each design repeats the part that
applies to it; this file is the whole picture.

Updated 2026-11-14: Specs 1, 2 and 3 have merged, and their files are in `docs/specs/done/`.
Spec 22 (log colours) was added the same day; it has no `# Design` yet.

## Waves

A spec can be built once every spec it depends on has merged. Specs in the same wave do not depend
on each other.

| Wave | Specs | Why they wait |
|---|---|---|
| 1 | ~~1~~, ~~3~~, 5, 6, 12, 15, 18, 21, 22 | Nothing. Each owns a shared seam or is self-contained. |
| 2 | ~~2~~, 4, 8, 9, 10, 11, 13, 17, 19 | Use seams from wave 1 (see the table below). |
| 3 | 7, 14, 16, 20 | Use kinds, files or stages from wave 2, or (Spec 20) the final set of kinds. |

Struck-through specs are built. What can be built now:

- **Ready now:** 5, 6, 12, 15, 18, 21 (the rest of wave 1), and 11 and 17 (they waited only on 1).
  Spec 22 depends on nothing but needs `/spec-design` first.
- **Waiting on 6:** 4, 19.
- **Waiting on 15:** 8, 9, 10. Spec 13 waits on 6, 12 and 15.
- **Wave 3** is unchanged: 7 waits on 5, 6 and 18; 14 on 4; 16 on 9 and 15; 20 on all others.

Per-spec dependencies. "Still waits on" leaves out the specs already built:

| Spec | Depends on | Still waits on | Design status |
|---|---|---|---|
| 1 unkeyed sources | none | | **built** |
| 2 keyed sources | 1 | | **built** |
| 3 root DNS records | none | | **built** |
| 4 Shodan per address | 1, 3, 6 | 6 | ready; re-check the budget interface after 6 |
| 5 provider ranges | none | none | ready |
| 6 larger lists | none | none | ready |
| 7 origin exposure | 2, 5, 6, 18 | 5, 6, 18 | **review before building** |
| 8 RDAP | 1, 15 | 15 | ready; re-check candidate types after 15 |
| 9 email third parties | 3, 15 | 15 | ready; re-check the derived-records hook after 15 |
| 10 reverse IP | 1, 15 | 15 | ready |
| 11 JavaScript endpoints | 1 | none | ready |
| 12 web posture | none | none | ready |
| 13 web identifiers | 1, 6, 12, 15 | 6, 12, 15 | ready; re-check the probe seam after 12 |
| 14 end-of-life software | 4 | 4 | **review before building** |
| 15 ranked candidates | none | none | ready; family table re-checked as 8, 10, 13, 16 land |
| 16 shared name servers | 3, 9, 15 | 9, 15 | **review before building** |
| 17 GitHub search | 1 | none | ready |
| 18 TLS detail | none | none | ready |
| 19 SRV records | 3, 6 | 6 | ready; `dnsroot` is built as designed (checks keyed `<root>\|<TYPE>`) |
| 20 changes report | all others | all unbuilt | **review before building** |
| 21 export | none | none | ready |
| 22 log colours | none | none | **not designed**; build early (see `report.go` below) |

## Shared seams and their owners

Each seam is designed in the first spec that needs it. A dependent spec uses it as built and does
not write its own. A seam marked **built** exists under the name given here; the others exist only
once their owner merges.

| Seam | Owner | Used by | State |
|---|---|---|---|
| `--skip` and the `skip` setting (read from `Settings.Skip`; there is no `Config.Skip`) | 1 | all later stages (they are skippable for free) | **built** |
| `run.ErrQuota` and `httpsrc.GetQuota`: a spent quota aborts the stage with one warning | 1 | 8, 10, 13, 16, 17 | **built** |
| `run.Warnf(ctx, …)`: a `--verbose` warning from inside `Run` (a WARN line shown by default once 22 merges) | 1 | 8, 10, 11, 13, 16, 17 | **built** |
| `httpsrc.CleanName` (lower-case, strip `*.`, validate) | 1 | 4, 10, 13, 17 | **built** |
| `ThirdPartyRequest.KeyPrefix` (`Bearer `) and `Accept` | 1 | 17 | **built** |
| `third_party` kind, `third-parties.csv`, `OutsideAttr` showing rule | 3 | 9, 19 | **built** |
| `provider` domain table (`domains:`, `DB.DomainOwner`) and TXT verification table (`txt:`, `DB.Verification`) | 3 | 9, 16 | **built** |
| `Kind.Found`: a kind's own `+` line and `found` event fields (not findings) | 3 | 4 | **built** |
| egress `TypeNS`, `TypeSOA`, `TypeCAA` and the `dnsroot` stage | 3 | 16, 19 | **built** |
| `dns_claim` kind and the `source` column of `resolutions.csv` | 2 | 7 | **built** |
| `run.Budgeted` and `Check.Cost`: per-run cap, deferred count in the summary | 6 | 4, 7, 13 | |
| Candidate evidence (`store.Observers`, `run.Evidencer`), `internal/candidates`, the derived-records hook in the runner, `File.Order` | 15 | 4, 8, 9, 10, 13, 16 | |
| `internal/orgname` (the organisation word rule) | 15 | 8 | |
| `reported_port` kind, `source`/`confirmed` on ports, severity-raise `+` line, `run.Noter`, `View.Done` | 4 | 14 | |
| Wider TLS offer for target requests, `Response.TLSVersion/TLSCipher/CertTrust` | 18 | 7 | |
| Provider class passed through for every class (`cdn`) | 5 | 7 | |
| `run.BuildScope` (scope and inventory from records, outside the Runner) | 21 | 20 | |
| Console streams and levels: log lines on stderr, the summary alone on stdout, `--quiet` and `--debug` in place of `--verbose`, the palette and severity badges | 22 | 4, 6, 7, 15, 20 (each adds a `+` line or a summary line) | |

Notes from the builds that later specs should know:

- `httpsrc.CleanName` strips `*.` before validating, so a wildcard certificate name records its
  root (`*.example.com` gives `example.com`).
- A `dns_claim`'s `source` is an attribute, so a second claim source reporting the same record
  would overwrite the first. Spec 7 should check this before adding another claim source.
- Three paged sources (Cert Spotter, Censys, Shodan DNS) each hand-roll their page cap and
  truncation warning, with two truncation rules between them. A new paged source (17) should copy
  the nearest one, not add a third rule.

## Keeping parallel branches apart

These rules make almost every conflict a keep-both conflict.

- **Kinds.** A new kind goes in its own file `internal/kinds/<kind>.go` (the `define` calls register
  from any file of the package). A field added to an existing attribute struct goes at the end of
  the struct. Do not embed structs in attribute structs: `decode` falls back to slow JSON decoding
  for them.
- **Stages.** A new stage is one line in `defaultStages()`. The final order is below; insert at
  the stage's place in it.
- **Output files.** A new file's row function goes in its own file `internal/output/<file>.go`,
  with one line in `Default()`. A column added to an existing file is appended after the existing
  columns, in the order given below.
- **Findings.** A new category gets its own file in `internal/findings`, with its rows appended to
  `table`, one entry in `riskFiles` and one line in `deriver.findings()`.
- **Settings.** A setting is five one-line additions in `internal/config/config.go` (`Settings`
  field, default, `settingTable`, flag, `rawSettings` plus its validation). Append each at the end
  of its block.
- **`runner.go` in wave 1.** Specs 6, 15 and 21 still edit it (1 and 3 have merged). Merge Spec 21
  next: it moves the scope and inventory construction out to `run.BuildScope`, and later specs
  that add a kind to the inventory (8, 11, 16) then edit that function, not the runner.
- **`probe.go` in wave 1.** Specs 12 and 18 both edit `service()`; each adds its own helper call,
  and 18 replaces two `web-services.csv` columns while 12 appends four. Merge 18 first.
- **`crawl.go` in wave 2.** Specs 11 and 13 each add one emit to `observations()`.
- **`report.go` and console text.** Spec 22 rewrites the console renderer: stage, `+` and warning
  lines become levelled log lines on stderr, the summary stays on stdout, and `--verbose` goes.
  Specs 4 and 7 add `+` lines, and 4, 6, 15 and 20 add summary lines. Merge 22 before them where
  possible. A spec that merges before 22 asserts its console text on stdout, and 22 then moves
  those assertions. A spec that merges after 22 writes its `+` lines through the log formatter,
  asserts them on stderr, and reads "shown with `--verbose`" in its design as "a WARN line".
- **Tests.** Each spec adds its behaviour tests in a new `internal/cli/<feature>_test.go`.
- **README.** One table row or bullet per addition; keep lists in the order of the stage registry.

### Final stage registry order

Built so far, in this order: every stage up to `chaos`, then `shodan`, `shodan-dns`,
`providerranges`, `resolve`, `wildcard`, `permutations`, `rdns`, `ipowner`, `dnsroot`, `email`,
`httpprobe`, `crawl`, `storage`, `takeover`, `sensitive-paths`, `ports`.

`asn`, `org-asn`, `ct-org`, `whoisxml`, `crtsh`, `wayback`, `commoncrawl`, `virustotal`,
`securitytrails`, `otx`, `hackertarget`, `urlscan`, `anubis`, `certspotter`, `censys`, `chaos`,
`github`, `shodan`, `shodan-dns`, `providerranges`, `resolve`, `wildcard`, `permutations`, `rdns`,
`ipowner`, `dnsroot`, `rdap`, `shodan-host`, `reverseip`, `dnshistory`, `email`, `nsreverse`,
`httpprobe`, `crawl`, `jsparse`, `identifier-pivot`, `storage`, `takeover`, `sensitive-paths`,
`origincheck`, `ports`.

### Final column order of files several specs extend

- `resolutions.csv`: `name`, `type`, `value`, `source` (2), `self_hosted` (16),
  `historical_first_seen`, `historical_last_seen` (7).
- `ips.csv`: existing columns, then `registrant`, `registrant_netblock`, `registry` (8),
  `srv_ports` (19).
- `open-ports.csv`: `ip`, `port`, `banner`, `hostnames`, `source`, `confirmed`,
  `shodan_last_seen` (4), `product`, `version` (14).
- `web-services.csv`: existing columns with `tls_error` and `tls_self_signed` replaced by
  `tls_version`, `tls_cipher`, `tls_trust` (18), then `hsts`, `insecure_cookies`,
  `directory_listing`, `version_disclosure` (12), `analytics_ids`, `pixel_ids`, `favicon_hash`,
  `copyright` (13).
- `email-posture.csv`: existing columns, then `mta_sts` (9), `mx_self_hosted` (16).
- `candidates.csv`: `type`, `value`, `sources`, `evidence_count`, `confidence` (15).
- `third-parties.csv`: `root`, `mechanism`, `domain`, `provider`, `depth` (3; 9 and 19 add rows,
  not columns).
