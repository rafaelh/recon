# Build order and shared seams for the November 2026 specs

Written 2026-11-11 with the `# Design` sections of `docs/specs/2026-11-spec-*.md`. It says which
specs can be built at the same time, which must wait, which spec owns each piece of shared
plumbing, and how to keep parallel branches from colliding. Each design repeats the part that
applies to it; this file is the whole picture.

## Waves

A spec can be built once every spec it depends on has merged. Specs in the same wave do not depend
on each other.

| Wave | Specs | Why they wait |
|---|---|---|
| 1 | 1, 3, 5, 6, 12, 15, 18, 21 | Nothing. Each owns a shared seam or is self-contained. |
| 2 | 2, 4, 8, 9, 10, 11, 13, 17, 19 | Use seams from wave 1 (see the table below). |
| 3 | 7, 14, 16, 20 | Use kinds, files or stages from wave 2, or (Spec 20) the final set of kinds. |

Per-spec dependencies:

| Spec | Depends on | Design status |
|---|---|---|
| 1 unkeyed sources | none | ready |
| 2 keyed sources | 1 | ready; re-check helper names after 1 |
| 3 root DNS records | none | ready |
| 4 Shodan per address | 1, 3, 6 | ready; re-check the budget interface after 6 |
| 5 provider ranges | none | ready |
| 6 larger lists | none | ready |
| 7 origin exposure | 2, 5, 6, 18 | **review before building** |
| 8 RDAP | 1, 15 | ready; re-check candidate types after 15 |
| 9 email third parties | 3, 15 | ready; re-check the derived-records hook after 15 |
| 10 reverse IP | 1, 15 | ready |
| 11 JavaScript endpoints | 1 | ready |
| 12 web posture | none | ready |
| 13 web identifiers | 1, 6, 12, 15 | ready; re-check the probe seam after 12 |
| 14 end-of-life software | 4 | **review before building** |
| 15 ranked candidates | none | ready; family table re-checked as 8, 10, 13, 16 land |
| 16 shared name servers | 3, 9, 15 | **review before building** |
| 17 GitHub search | 1 | ready |
| 18 TLS detail | none | ready |
| 19 SRV records | 3, 6 | ready; re-check `dnsroot` after 3 |
| 20 changes report | all others | **review before building** |
| 21 export | none | ready |

## Shared seams and their owners

Each seam is designed in the first spec that needs it. A dependent spec uses it as built and does
not write its own.

| Seam | Owner | Used by |
|---|---|---|
| `--skip` and the `skip` setting | 1 | all later stages (they are skippable for free) |
| `run.ErrQuota` and `httpsrc.GetQuota`: a spent quota aborts the stage with one warning | 1 | 2, 8, 10, 13, 16, 17 |
| `run.Warnf(ctx, …)`: a `--verbose` warning from inside `Run` | 1 | 2, 8, 10, 11, 13, 16, 17 |
| `httpsrc.CleanName` (lower-case, strip `*.`, validate) | 1 | 2, 4, 10, 13, 17 |
| `ThirdPartyRequest.KeyPrefix` (`Bearer `) and `Accept` | 1 | 2, 17 |
| `third_party` kind, `third-parties.csv`, `OutsideAttr` showing rule | 3 | 9, 19 |
| `provider` domain table (`domains:`) and TXT verification table | 3 | 9, 16 |
| `Kind.Found`: a kind's own `+` line and `found` event fields (not findings) | 3 | 4 |
| egress `TypeNS`, `TypeSOA`, `TypeCAA` and the `dnsroot` stage | 3 | 16, 19 |
| `run.Budgeted` and `Check.Cost`: per-run cap, deferred count in the summary | 6 | 4, 7, 13 |
| Candidate evidence (`store.Observers`, `run.Evidencer`), `internal/candidates`, the derived-records hook in the runner, `File.Order` | 15 | 4, 8, 9, 10, 13, 16 |
| `internal/orgname` (the organisation word rule) | 15 | 8 |
| `dns_claim` kind and the `source` column of `resolutions.csv` | 2 | 7 |
| `reported_port` kind, `source`/`confirmed` on ports, severity-raise `+` line, `run.Noter`, `View.Done` | 4 | 14 |
| Wider TLS offer for target requests, `Response.TLSVersion/TLSCipher/CertTrust` | 18 | 7 |
| Provider class passed through for every class (`cdn`) | 5 | 7 |
| `run.BuildScope` (scope and inventory from records, outside the Runner) | 21 | 20 |

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
- **`runner.go` in wave 1.** Specs 1, 3, 6, 15 and 21 all edit it. Merge Spec 21 first: it moves
  the scope and inventory construction out to `run.BuildScope`, and later specs that add a kind to
  the inventory (8, 11, 16) then edit that function, not the runner.
- **`probe.go` in wave 1.** Specs 12 and 18 both edit `service()`; each adds its own helper call,
  and 18 replaces two `web-services.csv` columns while 12 appends four. Merge 18 first.
- **`crawl.go` in wave 2.** Specs 11 and 13 each add one emit to `observations()`.
- **Tests.** Each spec adds its behaviour tests in a new `internal/cli/<feature>_test.go`.
- **README.** One table row or bullet per addition; keep lists in the order of the stage registry.

### Final stage registry order

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
