# Spec 3: root DNS records and the SaaS verification inventory

## Goal

For each in-scope root domain, recon records the name server, start-of-authority, TXT and CAA
records, so later pivots can use them, and from the TXT records tells the user which SaaS
platforms the organisation has verified domain ownership with.

## Behaviours

1. A `dnsroot` stage, available under `--passive`, performs one check per input root that is in
   scope and per record type (NS, SOA, TXT, CAA), through the same public resolvers as `resolve`,
   so a type that keeps failing does not block the others. Zone transfers are never attempted.
2. Each answer is a row in `resolutions.csv` with its type and value. A CAA value is written as
   `<flags> <tag> "<value>"`. An SOA value is the primary name server and the administrative
   mailbox written as an email address, with an escaped dot in the local part preserved
   (`john\.doe.example.com` becomes `john.doe@example.com`).
3. NS and SOA target names that are in scope are recorded as hostnames and are then resolved,
   probed and port-checked like any other hostname. NS targets outside scope are recorded in
   `third-parties.csv` with mechanism `ns`, the provider name when known and the domain otherwise,
   and are not candidates.
4. A root TXT record matching one of a fixed, case-insensitive prefix list is one row in
   `third-parties.csv` per platform and root, with mechanism `txt-verification` and the platform
   name. The list covers at least Google (`google-site-verification=`), Microsoft 365 (`MS=`),
   Atlassian, DocuSign, Facebook, Apple, Stripe, Adobe, HubSpot, Zoom, Dropbox, Salesforce, Have
   I Been Pwned and Cisco Webex, and is named in the README. The token appears in
   `resolutions.csv` (it is public DNS) but not in `third-parties.csv`.
5. A TXT record matching no pattern still appears in `resolutions.csv`; nothing else is inferred
   from it.
6. `third-parties.csv` is written only when it has rows and ends with the standard `current`,
   `first_seen` and `last_seen` columns. After `--redo dnsroot`, a record no longer present is
   marked not current.
7. NODATA and NXDOMAIN complete a type's check with no rows. SERVFAIL or a timeout is a transient
   failure for that type's check only.
8. The console `+` line for a new third party reads `third-party <platform> via txt-verification
   on <root>`; the `--json` `found` event carries the platform, mechanism and root.

# Design

**Status:** ready to build (wave 1). **Depends on:** nothing. **Owns for later specs:** the
`third_party` kind and `third-parties.csv` (Specs 9, 19), the `provider` domain and TXT tables
(9, 16), `Kind.Found` (4, 7), egress `TypeNS`/`TypeSOA`/`TypeCAA` and the `dnsroot` stage (16, 19).

## Decisions

- **`dnsroot` is a DNS stage** beside `resolve` (`internal/stages/dns/dnsroot.go`, using the
  package's `base`). One check per in-scope input root and type, keyed `<root>|<TYPE>`, so one
  failing type never blocks the others and Spec 19 can add a type without repeating these.
- **Answers are `resolution` records** keyed `name|TYPE|value` like today's. The inventory reads
  only `A`, `AAAA` and `CNAME` rows, so the new types cannot change what is contacted. The
  wildcard stage is the other reader: `Wildcard.Checks` takes zones from the name of every
  `resolution` row, so it is changed to read only `A`, `AAAA` and `CNAME` rows. Both readers are
  pinned by tests, because Specs 7 and 19 rely on them.
- **Value formats are produced in egress `rdata`**: CAA as `<flags> <tag> "<value>"`; SOA as
  `<mname> <mailbox>`, where the mailbox's first unescaped dot becomes `@` and `\.` becomes `.`.
- **Third parties are their own kind**, `third_party`, keyed `<root>|<mechanism>|<name>`, with
  attributes `root`, `mechanism`, `domain`, `provider`, `depth`. It is printed, counted under
  `third parties`, shown while `root` is in scope and, through a new showing rule
  `Kind.OutsideAttr: "domain"`, only while `domain` is not in scope. The rule is evaluated on read,
  so a root added later hides the row without a re-run.
- **One file for every mechanism**: `third-parties.csv` with columns `root`, `mechanism`,
  `domain`, `provider`, `depth`. An `ns` row has the name server's registrable domain and the
  provider when known; a `txt-verification` row has the platform in `provider` and no domain (the
  token never leaves `resolutions.csv`).
- **Knowledge stays in `provider`**: two new lists in `providers.yaml`. `txt:` maps a
  case-insensitive TXT prefix to a platform; `domains:` maps a domain suffix to a provider name
  (managed DNS now, mail and SaaS in Spec 9). Both are pure lookups (`provider.Verification`,
  `provider.DomainOwner`).
- **A kind may describe its own found line.** `Kind.Found func(store.Record) (text string, fields
  map[string]any)` is optional; the runner uses it for the `found` event, and the console prints
  `+ <text>` when the event carries `text`. This replaces a special case per kind in the runner
  and is what `docs/todo.md` asks for.
- **NS and SOA targets**: the check input carries the `*scope.Scope` (as the crawl does); an
  in-scope target is a `hostname` observation, any other NS target a `third_party` observation.

## Changes

- `internal/egress/dns.go`: `TypeNS`, `TypeSOA`, `TypeCAA`; `rdata` cases for SOA and CAA.
- `internal/egress/egresstest/dns.go`: the three types in the fake server.
- `internal/stages/dns/dnsroot.go`: the stage. `wildcard.go`: the row-type filter. `internal/cli/cli.go`: registered after `ipowner`.
- `internal/kinds/kinds.go`: `Kind.OutsideAttr`, `Kind.Found`. `internal/kinds/visibility.go`: the
  rule. `internal/kinds/thirdparty.go`: the kind.
- `internal/provider/provider.go` and `providers.yaml`: `txt:` and `domains:` lists and lookups.
- `internal/output/thirdparties.go`: the file; one line in `Default()`.
- `internal/run/runner.go`: `onNewRecord` uses `Kind.Found`. `internal/report/report.go`: `text`.
- `README.md`: `third-parties.csv`, the platform list, `resolutions.csv` wording, `dnsroot`.

## Tests

`internal/cli/dnsroot_test.go`, with `egresstest`:

- NS, SOA, TXT and CAA rows appear in `resolutions.csv` with the stated formats, including the
  escaped-dot mailbox.
- An in-scope NS target becomes a hostname and is resolved and probed; an out-of-scope one is a
  `third-parties.csv` row with its provider or domain, and is not in `candidates.csv`.
- Each listed TXT prefix (case-insensitive) yields one row per platform and root without the
  token; an unmatched TXT yields only its `resolutions.csv` row.
- NODATA and NXDOMAIN complete; SERVFAIL fails only that type and is retried.
- `--redo dnsroot` marks a vanished record not current; `--passive` runs the stage.
- The `+` line and the `found` event fields (behaviour 8).
- `internal/inventory`: NS, SOA, TXT and CAA rows do not affect addresses, wildcards or
  port eligibility.
- NS, SOA, TXT and CAA rows create no wildcard checks.
- `internal/egress`: `AXFR` and `IXFR` are still refused.

## Out of scope

SRV (Spec 19), SPF and DMARC third parties (Spec 9), using NS data for relatedness (Spec 16).

# Implementation

## Develop

Built as designed, with these specifics:

- **egress**: `TypeNS/SOA/CAA`; `rdata` writes SOA as `<mname> <mailbox>` (`mailbox` turns the first
  unescaped dot into `@` and `\.` into `.`, lower-casing the domain half) and CAA as
  `<flags> <tag> "<value>"`. `egresstest` gained `NS`, `SOA`, `CAA`, `RcodeType`/`ClearRcodeType`
  (a response code for one type of one name, so SERVFAIL can hit TXT alone) and `ClearRoot`.
- **`dnsroot`** (`internal/stages/dns/dnsroot.go`), registered after `ipowner`. Checks are keyed
  `<root>|<TYPE>` and carry the scope. SERVFAIL returns an error; NODATA and NXDOMAIN are empty
  results. An in-scope NS or SOA target is a `hostname`; an out-of-scope NS target is a `third_party`
  keyed by its registrable domain (falling back to the host for a public suffix); an out-of-scope
  SOA primary adds nothing.
- **Kinds**: `third_party` (`HostAttr: "root"`, `OutsideAttr: "domain"`, `Found`), `Kind.OutsideAttr`
  evaluated in `Visibility.shown`, and `Kind.Found` used by the runner's `onNewRecord`. `Kind` now
  holds a func, so it is no longer comparable; the one `kind == kinds.ExcludedKind` comparison in
  `output.go` compares names. `ThirdPartyOf` fills root, mechanism and domain/provider from the key,
  because the store keeps attributes only from current observations.
- **provider**: `txt:` and `domains:` in `providers.yaml`, `DB.Verification` and `DB.DomainOwner`
  (methods on `DB`, like `CNAME`, reached through `provider.Default()`).
- **Output/report**: `third-parties.csv` (own file, one line in `Default()`); the console prints
  `+ <text>` when a found event carries `text`.
- **Wildcard** reads only A, AAAA and CNAME rows.

Fixes beyond the design:

- The store drops the attributes of records that are no longer current, which `--redo` (behaviour 6)
  exposes: `resolutionRows` reads name, type and value from the key when the attributes are empty,
  and `thirdPartyRows` asks the showing rule with the root and domain the key gives back.
- An NS or SOA answer whose owner is not the root (the root is an alias, so the resolver followed it
  to the target's zone) is skipped, so a root is never recorded as depending on its alias target's
  name servers. TXT and CAA answers are kept.

Tests, all in `internal/cli/dnsroot_test.go` unless stated: record formats and the SOA mailbox
cases (behaviour 2); in-scope and out-of-scope name servers, no candidate, no resolution of an
out-of-scope server, port eligibility (3); one row per platform and root for every prefix in both
cases, in chunks of five because the fake DNS server answers over UDP only and fourteen TXT records
overflow a datagram (4); an unmatched TXT (5); file columns, not written when empty, redo marks
vanished rows not current (6); NODATA, NXDOMAIN, SERVFAIL for one type and its retry, `--passive`,
excluded roots (1, 7); the `+` line, the `found` fields and no repeat announcement (8); the summary
count and the read-time hide when a root later covers the domain. `internal/inventory`: the new row
types change nothing; `internal/cli`: they create no wildcard checks; `internal/egress`: AXFR and
IXFR refused and the new types queryable; `internal/provider`, `internal/kinds` and
`internal/report` unit tests. The inventory, AXFR/IXFR and registry-order tests pin existing
behaviour and passed before the code was written.

The Salesforce prefix is not confirmed against a live record (noted in `providers.yaml`).

Simplification: the CAA `rdata` case went (miekg's own text is the same and escapes target-supplied
bytes), the SOA mailbox uses `dns.NextLabel`, `Kind.Found` returns one map with `text` in it, and the
stage's NS and SOA cases are merged.

Mutation checks (`## Tests` marks none, so these are the riskiest guards): removing the wildcard
row-type filter fails `TestDNSRoot_RowsCreateNoWildcardChecks`; treating SERVFAIL as a result fails
`TestDNSRoot_Outcomes`; dropping the outside-domain rule fails `TestThirdPartyShown`,
`TestThirdPartyCountedAndPrinted` and `TestDNSRoot_DomainInScopeHidesRow`.

## Known limitations

- **Behaviour 3**: Amazon Route 53 name servers (`awsdns-NN.<tld>`) have no provider name, because
  the `domains:` list matches suffixes and the number is in the label; they are recorded by domain.
- **Behaviours 1 and 3**: the check key `<root>|<TYPE>` does not include the scope, so a name server
  that a root added later brings into scope does not become a hostname until `--redo dnsroot`.
- **Behaviour 3**: the `domains:` lookup is given the name server's registrable domain, so a suffix
  deeper than that (`dns.hoster.com`) never matches.
- **Behaviour 4**: a TXT value split over several strings is matched on the strings joined (egress
  joins them); a prefix split across strings still matches.

# Verification

## Result

Checked against the goal, behaviours 1 to 8 and `## Out of scope` by reading every changed file and
running `make test` (passes). The goal is met. For each in-scope input root, `dnsroot` records NS,
SOA, TXT and CAA answers as `resolution` rows. Those rows cannot change what is contacted (the
inventory and the wildcard stage read only A, AAAA and CNAME rows, and both are pinned by tests).
TXT verification records become `third-parties.csv` rows naming the platform. The stage order
matches the build-order registry, and the `third-parties.csv` columns match its column order.

- **B1 met.** `dnsroot` is a `ThirdParty` stage registered after `ipowner`, so it runs under
  `--passive`. Its checks are keyed `<root>|<TYPE>` over `Inputs().Roots` that classify as in scope
  (an excluded root is not queried). Queries go through `egress` like `resolve`'s, and egress still
  refuses AXFR and IXFR.
- **B2 met.** CAA is miekg's presentation text (`0 issue "letsencrypt.org"`). SOA is
  `<mname> <mailbox>`, with the first unescaped dot turned into `@` and `\.` turned into `.`. Both
  are tested, including a mailbox with several escaped dots.
- **B3 met after one fix.** An in-scope NS target or SOA primary becomes a `hostname` and is then
  resolved, probed and made port-eligible (tested). An out-of-scope NS target becomes a `third_party`
  row keyed by its registrable domain, with the provider when `domains:` knows it. It is not a
  candidate and is never resolved. Known limitation 1 stands: Route 53 name servers are listed by
  domain with no provider name. B3 allows this ("the provider name when known and the domain
  otherwise"), so it is not a gap. *Fixed:* known limitation 2, where a not-current `ns` row stayed
  in `third-parties.csv` after a later root brought its domain into scope. `thirdPartyRows` now
  applies the showing rule using the root and domain recovered from the key when the record has no
  attributes. `TestDNSRoot_DomainInScopeHidesNotCurrentRow` covers this, and it fails without the fix.
- **B4 met.** All fourteen platforms are in `providers.yaml` and in the README, and matching is
  case-insensitive. Each root gets one row per platform, even when a platform has two tokens, and the
  token appears only in `resolutions.csv` (tested in both cases). Most prefixes match published
  formats. A web search showed Zoom records as `zoom-domain-verification=ZOOM_verify_…`, which the
  prefix matches. The Salesforce prefix is still unconfirmed (Follow-ups). Known limitation 3 (a TXT
  split over several strings is matched after joining) matches how DNS clients read TXT, so it is
  not a gap.
- **B5 met.** An unmatched TXT is a `resolutions.csv` row only (tested).
- **B6 met.** `third-parties.csv` is written only when it has rows, and its header ends with
  `current, first_seen, last_seen`. After `--redo dnsroot`, vanished TXT and NS rows are marked not
  current, and their key-derived columns are filled in (tested).
- **B7 met.** NODATA and NXDOMAIN complete with no rows. SERVFAIL, and REFUSED (which egress maps to
  SERVFAIL), return an error for that type's check alone, and it is retried on the next run (tested).
  A timeout is an egress error and therefore transient. This path is shared with `resolve` and has
  no separate test.
- **B8 met.** The console prints `+ third-party <platform> via <mechanism> on <root>`. The `found`
  event carries `platform`, `mechanism`, `root` and `text`. A known third party is not announced
  again (tested).

*Also changed:* the `ResolutionAttrs` doc comment in `internal/kinds/table.go` said it held only A,
AAAA and CNAME values. It now names the root types and says only A, AAAA and CNAME rows decide what
is resolved, contacted or checked for wildcards.

Not covered by the spec, and left alone: answers are not filtered by owner name. If an input root is
itself a CNAME, the target's TXT (and NS) answers are recorded as the root's, which is what any
verifying service following the CNAME would also see.

# Follow-ups

- **Store keeps no attributes for a record that is no longer current.** This feature adds three
  key-parsing fallbacks for it (`ThirdPartyOf`, `splitResolutionKey`, the key-derived root and domain in
  `thirdPartyRows`), beside the existing ones in `findings`. Keeping a record's last attributes when it
  loses its last observation (a `records.attrs` column and one migration) would remove all of them
  It changes store semantics, so land it as its own `fix:`.
- **`Kind` is no longer comparable** (it holds `Found`). Comparing two `kinds.Named` values with `==`,
  or using one as a map key, compiles but panics at runtime. Nothing does either today; specs that
  build on `Kind.Found` should compare `Name()`.
- Writing NS, SOA, TXT and CAA rows as `resolution` records raises that kind's version, so the
  runner rebuilds the scope and inventory after a pass that wrote them, though they cannot change it.
