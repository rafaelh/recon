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
