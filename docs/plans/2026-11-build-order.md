# Build order and shared seams for the November 2026 specs

Written 2026-11-11 with the `# Design` sections of `docs/specs/2026-11-spec-*.md`. It says which
specs can be built at the same time, which must wait, which spec owns each piece of shared
plumbing, and how to keep parallel branches from colliding. Each design repeats the part that
applies to it; this file is the whole picture.

Updated 2026-11-14: Specs 1, 2, 3, 5, 6, 12 and 15 have merged, and their files are in
`docs/specs/done/`. Spec 22 (log colours) was added the same day; it has no `# Design` yet. The
designs of the fifteen specs still to build were then re-checked against the code: the ones that
did not match a seam as built were corrected, and the follow-ups of the built specs were carried
into the specs they bear on (each has a `## Carried from built specs` section; the table near the
end of this file says where each follow-up went).

## Waves

A spec can be built once every spec it depends on has merged. Specs in the same wave do not depend
on each other.

| Wave | Specs | Why they wait |
|---|---|---|
| 1 | ~~1~~, ~~3~~, ~~5~~, ~~6~~, ~~12~~, ~~15~~, 18, 21, 22 | Nothing. Each owns a shared seam or is self-contained. |
| 2 | ~~2~~, 4, 8, 9, 10, 11, 13, 17, 19 | Use seams from wave 1 (see the table below). |
| 3 | 7, 14, 16, 20 | Use kinds, files or stages from wave 2, or (Spec 20) the final set of kinds. |

Struck-through specs are built. What can be built now:

- **Ready now:** 18 and 21 (the rest of wave 1), and all of wave 2: 4, 8, 9, 10, 11, 13, 17, 19.
  Spec 22 depends on nothing but needs `/spec-design` first.
- **Wave 3:** 7 waits on 18; 14 on 4; 16 on 9; 20 on all others.
- **Waiting on the user:** 7 (how Akamai addresses in Linode's list classify), 10 (the reading of
  behaviour 4), 16 (its open point) and 22 (its design). See "Decisions still open" below.

Per-spec dependencies. "Still waits on" leaves out the specs already built:

| Spec | Depends on | Still waits on | Design status |
|---|---|---|---|
| 1 unkeyed sources | none | | **built** |
| 2 keyed sources | 1 | | **built** |
| 3 root DNS records | none | | **built** |
| 4 Shodan per address | 1, 3, 6, 15 | none | ready; corrected: `shodan-host` joins the family table |
| 5 provider ranges | none | | **built** |
| 6 larger lists | none | | **built** |
| 7 origin exposure | 2, 5, 6, 18 | 18 | **review before building**; settled against 2, 5 and 6; one point to settle first |
| 8 RDAP | 1, 15 | none | ready; corrected: the `asn` and `organisation` candidate kinds |
| 9 email third parties | 3, 15 | none | ready; corrected: depth from 0, the deriver in `derive.go` |
| 10 reverse IP | 1, 15 | none | ready; corrected: evidence source `reverseip`; one reading to confirm |
| 11 JavaScript endpoints | 1 | none | ready; no correction |
| 12 web posture | none | | **built** |
| 13 web identifiers | 1, 6, 12, 15 | none | ready; corrected: the family lookup, the probe seam as 12 built it, a 402 stops the stage |
| 14 end-of-life software | 4 | 4 | **review before building**; no correction |
| 15 ranked candidates | none | | **built**; 4, 13 and 16 each change its family table |
| 16 shared name servers | 3, 9, 15 | 9 | **review before building**; corrected: `shared-ns` and `shared-mx` in the family table; open point |
| 17 GitHub search | 1 | none | ready; no correction |
| 18 TLS detail | none | none | ready; the column and probe seams written as 12 built them |
| 19 SRV records | 3, 6 | none | ready; `dnsroot` and the permutations keys written as built |
| 20 changes report | all others | all unbuilt | **review before building**; corrected: the baseline keeps scope and severity |
| 21 export | none | none | ready; the kind list it moves is also the rank deriver's `reads` |
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
| `run.Budgeted` (`Budget(config.Settings) int`) and `Check.Cost`: per-run cap, deferred cost per stage under `Deferred to the next run` | 6 | 4, 7, 13 | **built** |
| Candidate evidence (`store.Observers`, `run.Evidencer`), `internal/candidates` (`Family`, `Score`, `Promote`), the derived-records hook (`newDerivers()` in `internal/run/derive.go`), `kinds.CandidateKinds`, `File.Order` | 15 | 4, 8, 9, 10, 13, 16 | **built** |
| `internal/orgname` (`Tokens`, `Matches`: the organisation word rule) | 15 | 8 | **built** |
| Provider class passed through for every class (`provider.ClassCDN`) | 5 | 7 | **built** |
| `reported_port` kind, `source`/`confirmed` on ports, severity-raise `+` line, `run.Noter`, `View.Done` | 4 | 14 | |
| Wider TLS offer for target requests, `Response.TLSVersion/TLSCipher/CertTrust` | 18 | 7 | |
| `run.BuildScope` (scope and inventory from records, outside the Runner) | 21 | 20 | |
| Console streams and levels: log lines on stderr, the summary alone on stdout, `--quiet` and `--debug` in place of `--verbose`, the palette and severity badges | 22 | 4, 7, 20 (each adds a `+` line or a summary line) | |

Notes from the builds that later specs should know:

- `httpsrc.CleanName` strips `*.` before validating, so a wildcard certificate name records its
  root (`*.example.com` gives `example.com`).
- A `dns_claim`'s `source` is an attribute, so a second claim source reporting the same record
  would overwrite the first. Spec 7 adds no claim source (historical addresses are their own
  kind), so nothing to build has this problem.
- Three paged sources (Cert Spotter, Censys, Shodan DNS) each hand-roll their page cap and
  truncation warning, with two truncation rules between them. Specs 4 and 17 use the rule Censys
  and Shodan DNS share (warn only when the source reports more than was read) and add no third.
- **Candidate families are looked up by exact source.** `candidates.Family` maps the source an
  `Evidencer` returns (or the stage name, without one) through the `families` table, and any
  source not in it is a family of its own, so it adds a family towards high confidence. The
  table reserved `rdap`, `reverseip`, `nsreverse` and `identifier-pivot` for the stages to come.
  The designs now agree with it: 8 returns `rdap` and 10 returns `reverseip`, with no table
  change; 4 adds `shodan-host` as passive DNS; 13 returns `identifier-pivot:<id>`, as its
  behaviour 4 asks, and changes `Family` to look up the part before the first `:`; 16 returns
  `shared-ns` or `shared-mx`, as its behaviour 2 asks, and replaces the `nsreverse` entry with
  both. Each of those specs also updates the README sentence that lists the reserved names.
- **Candidates are ranked from records, not on read.** The `candidate-rank` deriver ranks the
  candidate-category records of each kind in `kinds.CandidateKinds` (now `Root`, `Hostname`,
  `Netblock`), and `candidates.csv` lists those same records with their stored rank and the
  kind's name as the type. It re-derives only when a kind in its `reads` (`scopeKinds` in
  `runner.go`) changes. Spec 8 therefore adds two entity kinds named `asn` and `organisation`
  (the types `candidates.Promote` already handles), appends both to `CandidateKinds`, gives each
  a case in `Visibility.category`, and adds them and `registration` to the deriver's `reads`.
- The derived-records hook is the `newDerivers()` list in `internal/run/derive.go`; a deriver is
  one entry there (`name`, `reads`, `writes`, `derive`). Spec 9's `thirdparty-cname` deriver goes
  there. The runner leaves every kind a deriver writes out of the findings' signature.
- A budgeted stage's first pending check of a run is always sent, even if its `Cost` exceeds the
  budget, and a budget below 1 counts as 1. A check that fails still spends its share. The
  `Deferred to the next run` summary line gives a bare number per stage; the README names the
  unit (names, requests). Specs 4, 7 and 13 add one README clause each for their unit
  (addresses, hostnames, searches). Whether the block should label its units is carried to
  Spec 22.
- **A record that is no longer current has no attributes.** The store keeps them only from
  current observations. A kind with an output file must therefore put in its key whatever a
  not-current row should still show, or accept blank cells; `ThirdPartyOf` and
  `splitResolutionKey` are the key-reading fallbacks that exist. Specs 9 and 19 extend the
  first, 17 accepts a row that keeps only its URL, 20 keeps scope and severity in its baseline
  table for this reason, and 21 exports empty `attrs`. Keeping a record's last attributes (a
  `records.attrs` column and one migration) would remove every fallback; it changes store
  semantics, so it is its own `fix:`, best landed before Spec 20.
- **`Kind` is not comparable** (it holds `Found`). Comparing two `kinds.Named` values with `==`,
  or using one as a map key, compiles and panics at runtime. Compare `Name()`.
- **Keyed aborts.** `httpsrc.Get` aborts a keyed stage on a 401, 403 or 429 and returns only the
  body of a 200. A Shodan 402 (no query credits) is an ordinary failed check. So 7 and 16 need no
  quota code, 13 maps a 402 itself, and 8 (referrals) and 17 (rate-limit headers) call
  `ThirdParty.Do` and repeat the mapping they need. `httpsrc.GetQuota` is for the 429 of an
  unkeyed source.
- **Third-party depth counts from 0.** `third-parties.csv` gives 0 to a domain the root's own
  records name. Spec 9's behaviour 1 said 1 and was amended.
- **Check keys do not carry the scope.** `shodan-dns` and `dnsroot` decide what is a hostname
  from the scope at the time of the check, and a root added later does not repeat it. Specs 4,
  10, 11, 13, 17 and 19 keep the same choice, each with a README `--redo` note, because a scope
  in the key would repeat every lookup (and spend quota or credits) on every scope change.

## Keeping parallel branches apart

These rules make almost every conflict a keep-both conflict.

- **Kinds.** A new kind goes in its own file `internal/kinds/<kind>.go` (the `define` calls register
  from any file of the package). A field added to an existing attribute struct goes at the end of
  the struct. Do not embed structs in attribute structs: `decode` falls back to slow JSON decoding
  for them. A new candidate kind is also one entry appended to `kinds.CandidateKinds`.
- **Stages.** A new stage is one line in `defaultStages()`. The final order is below; insert at
  the stage's place in it.
- **Output files.** A new file's row function goes in its own file `internal/output/<file>.go`,
  with one line in `Default()`. A column added to an existing file is appended after the existing
  columns, in the order given below.
- **Findings.** A new category gets its own file in `internal/findings`, with its rows appended to
  `table`, one entry in `riskFiles` and one line in `deriver.findings()`.
- **Derivers.** A new derived kind is one entry appended to `newDerivers()` in
  `internal/run/derive.go`, with its derivation function in a pure package (as `internal/candidates`
  is for `candidate-rank`).
- **Candidate families.** A new source is one entry in the `families` table in
  `internal/candidates/candidates.go`. Spec 4 adds a line, 16 replaces one, and 13 edits `Family`
  itself; 8 and 10 do not touch the file.
- **`thirdparty.go`.** Specs 9 and 19 each add mechanism constants and a case in
  `ThirdPartyOf`'s key fallback. Append both; the conflict is keep-both.
- **Shared helpers a spec adds.** Spec 10 moves HackerTarget's reply rules from `subdomains` to
  `httpsrc`; Spec 17 adds `View.InScopeRoots()`. The stages that could also use them are left
  alone until the cleanup listed under "Not carried".
- **Settings.** A setting is five one-line additions in `internal/config/config.go` (`Settings`
  field, default, `settingTable`, flag, `rawSettings` plus its validation). Append each at the end
  of its block.
- **`runner.go`.** Spec 21 is the last wave-1 spec that edits it. Merge it before the specs that
  add a kind to the inventory (8, 11, 16): it moves the scope and inventory construction out to
  `run.BuildScope`, and they then edit that function, not the runner.
- **`probe.go`.** Spec 12 merged first, so `service()` already calls its posture helper and
  `web-services.csv` already ends with its four columns. Spec 18 adds its helper call beside it and
  replaces `tls_error` and `tls_self_signed` in place, before 12's columns. Spec 13 then appends
  after 12's.
- **`crawl.go` in wave 2.** Specs 11 and 13 each add one emit to `observations()`.
- **`report.go` and console text.** Spec 22 rewrites the console renderer: stage, `+` and warning
  lines become levelled log lines on stderr, the summary stays on stdout, and `--verbose` goes.
  Specs 6 and 15 have already added summary lines (`Deferred to the next run` and the two candidate
  lists), asserted on stdout; 22 keeps them on stdout. Specs 4 and 7 add `+` lines, and 4 and 20
  add summary lines. Merge 22 before them where possible. A spec that merges before 22 asserts its
  console text on stdout, and 22 then moves those assertions. A spec that merges after 22 writes
  its `+` lines through the log formatter, asserts them on stderr, and reads "shown with
  `--verbose`" in its design as "a WARN line".
- **Tests.** Each spec adds its behaviour tests in a new `internal/cli/<feature>_test.go`.
- **README.** One table row or bullet per addition; keep lists in the order of the stage registry.

### Final stage registry order

Built so far, in this order: every stage up to `chaos`, then `shodan`, `shodan-dns`,
`providerranges`, `resolve`, `wildcard`, `permutations`, `rdns`, `ipowner`, `dnsroot`, `email`,
`httpprobe`, `crawl`, `storage`, `takeover`, `sensitive-paths`, `ports`. (Specs 5, 6, 12 and 15
added no stages.)

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
  `directory_listing`, `version_disclosure` (12, built), `analytics_ids`, `pixel_ids`,
  `favicon_hash`, `copyright` (13).
- `email-posture.csv`: existing columns, then `mta_sts` (9), `mx_self_hosted` (16).
- `candidates.csv`: `type`, `value`, `sources`, `evidence_count`, `confidence` (15, built; 8 adds
  the `asn` and `organisation` types as rows, not columns).
- `third-parties.csv`: `root`, `mechanism`, `domain`, `provider`, `depth` (3; 9 and 19 add rows,
  not columns).

## Decisions still open

Each is written up in the spec named, with a recommendation where there is one.

| Spec | Decision |
|---|---|
| 7 | Whether an address whose ASN is a `cdn` entry stays shared inside a dedicated published range (Linode's list covers Akamai space). It amends Spec 5's behaviour 2. Recommended: yes. |
| 10 | Whether "hostnames already obtained from Shodan are not fetched again" means the stage never calls Shodan (the design's reading, which keeps it independent of Spec 4). |
| 16 | Whether `dnsroot` and `email` may look up the addresses of name servers and mail hosts that are outside scope, or only in-scope hosts count as self-hosted. |
| 22 | Its whole design, and with it: units in the deferred block, the reading of "and N more", and what to do with the OTX and Anubis stages before warnings show by default. |

## Follow-ups from the built specs

Where each item of the `# Follow-ups` and `## Known limitations` of Specs 1, 2, 3, 5, 6, 12 and
15 went. "Carried" means the spec named has it under `## Carried from built specs` or in its
decisions.

| From | Follow-up | Where it went |
|---|---|---|
| 1 | OTX and Anubis no longer answer; keep, key or drop | 22 (decide before warnings show by default) |
| 1 | `View.InScopeRoots` for the repeated in-scope-roots loop | 17 adds and uses it; the older loops are not carried |
| 1 | Merge `httpsrc.CleanName`, `web.sanHost` and `orgpivot.rootObs` | Not carried: one change after 4, 10, 13 and 17 |
| 2 | A second claim source would overwrite `dns_claim.source` | 7: does not arise, historical addresses are their own kind |
| 2 | Three paged sources, two truncation rules | 4 and 17: use the shared rule, add no third |
| 2 | A Shodan 402 is a failed check, not a stopped stage | 4 and 13 |
| 2, 3 | `shodan-dns` and `dnsroot` keys do not carry the scope | 4, 10, 11, 13, 16, 17, 19 keep the same choice and say so |
| 3 | The store keeps no attributes for a not-current record | 7, 9, 13, 14, 16, 17, 18, 19, 20, 21; the fix itself is not carried |
| 3 | `Kind` is not comparable | Every spec that adds or lists a kind |
| 3 | `resolution` rows cost a scope rebuild | 16 and 19 |
| 3 | `domains:` matches by suffix; Route 53 has no entry | 9 and 16 |
| 5 | Linode's list covers Akamai `cdn` space | 7 (to settle first), 18 (noted) |
| 5 | A `linodeobjects.com` CNAME entry | 7 |
| 6 | Units in the `Deferred to the next run` block | 22; 4, 7 and 13 name their unit in the README |
| 6 | A failed check spends budget | 4, 7, 13 |
| 12 | A not-current finding keeps only its key's columns | 7, 14, 18, 20 |
| 12 | The probe's `hop` chain and `lastSameOrigin` | 13 and 18 |
| 15 | Re-check stage names against the family table; README "reserved" sentence | 4, 8, 10, 13, 16 |
| 15 | A stage with a setting in its key must implement `Evidencer` | 4, 8, 10, 11, 13, 16, 17 |
| 15 | The reading of "and N more"; the medium list under `--verbose` | 22 |

Not carried, because no remaining spec touches the code or the item needs a decision or a person:

- Spec 1: an `Unskippable` interface in `run`; one limit field in `subdomains.Stage`;
  `ThirdPartyRequest.KeyOptional`; whether `crtsh`, `wayback` and `commoncrawl` stop on a 429;
  a Cert Spotter check that restarts from page 1 after a quota stop; what `--redo` of a
  subdomain stage does after a root is excluded.
- Spec 2: whether `chaos.max_pages` should exist; whether a claim's `source` should come from
  `Record.Stages`; a shared paging helper in `httpsrc`; one request with a real Censys token and
  a real Chaos key; whether the `shodan-dns` key should carry the scope; whether a not-current
  claim should still add its source to a current row.
- Spec 3: keeping a record's last attributes in the store (its own `fix:`, see the notes above).
- Spec 5: aligning service and region per provider in `ips.csv`, and a region column (it would
  need a place in the `ips.csv` column order above).
- Spec 6: names two or more levels under a wildcard zone; checking the sensitive-path signatures
  against real files; measuring a real run; trimming the low-severity development-file entries;
  pricing only pending checks for very large engagements.
- Spec 15: `whoisxml` results are not checked by the word rule.
- Tooling (Specs 5, 6, 12, 15): `.claude/hooks/go-check.sh` still changes to the main checkout,
  so it fails in a worktree. The linter half is done: the installed `golangci-lint` is v2.15.0
  and runs against this module. `golangci-lint run ./...` on main on 2026-11-14 reports five
  findings, all in test files (`internal/cli/sources_keyed_test.go`, `providerranges_test.go` and
  `internal/sanitize/sanitize_test.go`).
