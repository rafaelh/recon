# Spec 2 of 6: recon (Go) — Domains, DNS and scope

## Goal

Build the list of the target's hostnames and IPs from domains, organisation names and netblocks,
using third-party sources and DNS, and classify each by ownership so later stages contact only the
target's own infrastructure. Depends on Spec 1 (definitions of scope, candidates, checks and the
passive boundary).

## Behaviours

1. Subdomains of in-scope roots are gathered from keyless passive sources (e.g. CT logs, web
   archives). Keyed sources run when a key is configured and are shown as not-configured otherwise.
2. Permutations of subdomain labels found by sources, certificates, crawling or reverse DNS, plus a
   configurable wordlist, are resolved via public resolvers. This is on by default (including in
   passive-only mode) and can be disabled. Permutations are never generated from other
   permutations.
3. Discovered names are resolved (A/AAAA/CNAME). Names that don't resolve are recorded as unresolved.
   A resolution timeout is a transient failure (Spec 1.8), not a takeover signal.
4. Names that resolve only because of a wildcard record are identified and excluded from later
   stages, except that one representative name per wildcard is HTTP-probed.
5. Names whose CNAME points at a known cloud/SaaS provider are passed to takeover checks (Spec 5.1),
   whether or not the chain resolves.
6. Organisation-name pivots (CT certificate organisation; reverse WHOIS as a keyed source) record new
   root domains as candidates, and ASN lookups for the organisation record netblocks as candidates.
   Candidates are not enumerated.
7. User-supplied ASNs/CIDRs are in scope. Hostnames for in-scope IPs are found via reverse DNS and
   passive sources; those not under an in-scope root are recorded against the IP and as candidates.
   IPv4 netblocks are swept in full (subject to Spec 1.15); for IPv6 netblocks, only addresses found
   by other stages are checked.
8. Hosts and IPs recognised as shared provider infrastructure (AWS/Azure/GCP PaaS, CDNs, SaaS
   platforms, shared hosting) are labelled with provider and service.
9. An IP is eligible for port checks only if it is an in-scope IP, or an in-scope hostname resolves
   to it and it is not recognised as shared provider infrastructure. Other IPs are recorded with
   their owner (provider or ASN name) but never port-checked. IPv4 and IPv6 are treated alike.

# Design

## Decisions

| # | Decision | Answer | Rationale |
|---|----------|--------|-----------|
| D1 | Stage granularity | One `run.Stage` per source. Every Spec 2 stage is `ThirdParty`, so all of them run under `--passive` | `Configured()` and console state are per stage, so each keyed source shows `not-configured (no key)` on its own (B1, Spec 1 B17) |
| D2 | (user) Keyless subdomain sources | `crtsh`, `wayback` (CDX) and `commoncrawl` (index). Check key = root | B1 names CT logs and web archives. Only hostnames are taken from archives; recording URLs is Spec 3.6 |
| D3 | (user) Keyed sources | `virustotal`, `securitytrails` (subdomains per root), `shodan` (hostnames for in-scope netblocks via `net:<cidr>` search) and `whoisxml` (reverse WHOIS, org → roots). Keys are `keys.<source>`, attached by egress | B1, B6 and B7 |
| D4 | Key and quota failures | A 401, 403 or 429 returns an error wrapping `run.ErrAbortStage`. The stage shows `failed`, nothing is recorded, and it is retried next run. There is no "completed because not entitled" outcome | A bad or expired key must not be recorded as done: the check key doesn't contain the key, so fixing the key would never re-run it (Spec 1 B6) |
| D5 | (user) Org → ASN | `org-asn` stage: RIPEstat `searchcomplete` for the org, keep ASNs whose holder name contains every token of the normalised org name (cap 10 ASNs per org), then `announced-prefixes` for each. Emits `netblock` observations. Check key = org | Candidates only, never enumerated: `runner.asnNetblocks` counts only the `asn` stage under input ASNs, so these are not in scope and the netblock guard ignores them |
| D6 | CT organisation pivot | `ct-org` stage: crt.sh search by organisation, names reduced to eTLD+1 and emitted as `root` observations. Check key = org. The exact crt.sh organisation query parameter is confirmed against the live API in development; fallback is an identity search | B6. Scope classifies the roots as candidates |
| D7 | (user) Reverse WHOIS | `whoisxml` stage: `POST reverse-whois.whoisxmlapi.com/api/v2`, `mode=purchase`, basic search by organisation. Emits `root` observations. Check key = org | B6. One credit spend per org per engagement because the check is remembered. egress gains `KeyBodyField` in `ThirdPartyRequest` so the key goes into the JSON body without the stage touching it. Confirm the field name in development, and use a header if WhoisXML offers one |
| D8 | Resolve stage | `resolve`: one check per in-scope or excluded hostname (never candidates). Queries A and AAAA. Check key = hostname. Emits kind `resolution` (key `name\|type\|value`, attrs name, type, value) using the **queried** name for A/AAAA, kind `ip` per address, one `resolution` row of type CNAME per chain link, and kind `unresolved` (key name, attr `rcode`: NXDOMAIN, NODATA or SERVFAIL) when there is no address. A DNS timeout is an error, so it is transient (B3) | `Answer.Name` is the owner name, which after a CNAME is the chain target. Using it would key addresses to the wrong host and break `buildScope`, `hostAddrs`, exclusion by CIDR and B9. Re-resolution of a name is `--redo resolve` (Spec 1 B6 contract) |
| D9 | CNAME chain in egress | `DNSResult.CNAMEChain []string` becomes `CNAMEs []CNAME{Name, Target}` in answer order, and is populated on NXDOMAIN and NODATA too | Link rows need owner names, and B5 needs dangling chains |
| D10 | Wildcards | `wildcard` stage: one check per parent zone (each in-scope root and each parent of a resolved in-scope name). It queries two random 16-char labels (the label source is injectable). If they answer, it emits one `wildcard` record per zone (key zone, attrs addrs, cname). **Whether a name is wildcard-only is computed on read, not stored** | A check keyed by zone can't see names found later. Computing on read follows Spec 1 D16, so late names are still caught |
| D11 | Wildcard rule | A name directly under a wildcard zone is wildcard-only if its CNAME target equals the zone's, or its address set overlaps the union of both probes' addresses. The representative per zone is the lexicographically smallest wildcard-only name that is in scope and resolves, so it can always be probed | CDN-backed wildcards rotate answers, so exact set equality is fragile. A deterministic representative keeps outputs stable (B4) |
| D12 | Wildcard consumers | `View.ProbeHostnames()` returns resolved, in-scope, non-excluded, non-wildcard-only names plus each zone's representative. `View.InScopeHostnames()` is unchanged and documented as not wildcard-aware. `scope.Config` gains `WildcardOnly`, and wildcard-only names do not make an IP eligible under D18 | Spec 3 must use `ProbeHostnames()`. Egress can't enforce B4 itself |
| D13 | (user) Permutations | `permutations` stage, on by default, disable with `--no-permutations` / `permutations.enabled: false` (not-configured reason `disabled`). Two check kinds. **root:** wordlist words as a new label under the root. **seed:** label+word, word+label, `-`/`.` joins, digit increments, capped at `permutations.max_per_seed` (default 200, validated > 0, shown in help). One A query per generated name: anything other than NXDOMAIN means it exists, and `resolve` then does A/AAAA. Only names that exist are emitted as `hostname` | B2. Check keys include the wordlist hash and the cap (Spec 1 B6). A timeout in a 200-name check fails that seed as a block and it is redone next run. That is accepted because the cost per seed is bounded |
| D14 | Seed rule | A hostname is a seed only if `Record.Stages` contains a stage other than `permutations`, and it is not wildcard-only. Seeds are never derived from permutation-only names, so there are no second-generation permutations | `Record.Attrs` is merged with later stages winning, so an `origin` attr would flip. Spec 1's asn design says to never depend on a mutable attr (B2) |
| D15 | rDNS | `rdns` stage: one PTR check per address in an in-scope IPv4 netblock (the full sweep, already gated by the runner's B15 guard), and one per `ip` record that is inside an in-scope netblock (so found IPv6 addresses are covered). Not run for provider or other third-party IPs. Emits `hostname` and `ip_hostname` (ip, hostname, source) | B7. Restricting to `Scope().InScopeIP` avoids filling candidates.csv with `ec2-…amazonaws.com` names. Shodan also emits `ip_hostname`, so ips.csv shows both sources against the IP |
| D16 | (user) Provider recognition | Embedded `internal/provider/providers.yaml`: CNAME suffix → provider/service, and ASN → provider with a class (`cdn`, `shared-hosting`, `hyperscaler`). Pure `provider.Classify` computed at Scope-build and render time, never stored | B8 and Spec 1 D16 |
| D17 | (user) Hyperscalers | `providerranges` stage fetches AWS `ip-ranges.json` and GCP `cloud.json` (keyless, one check per provider, refreshed by `--redo providerranges`) as `provider_range` records. AWS: an address matching a service other than `AMAZON`/`EC2` (CLOUDFRONT, ELB, S3, API_GATEWAY…) is shared and labelled with that service; `EC2`-only is not shared. GCP ranges carry no service, so GCP gives the label and region only, and GCP addresses are shared (fail closed). Azure has no stable range URL, so Azure ASNs are shared. A hyperscaler address with no range data is shared. A CNAME suffix match is extra evidence | The CNAME-only rule would port-check Route 53 ALIAS / CloudFront apex records (no CNAME, and AS16509 is also EC2) |
| D18 | Shared / eligibility, one function | `scope.Scope.PortEligible(addr, shared, ownerKnown)` returns (bool, reason): in-scope IP, or an address of a non-wildcard-only in-scope hostname that is not shared, and not excluded. `TargetTCP` calls it, and ips.csv `port_eligible` uses the same call. IPs that are not in an in-scope netblock and whose owner is **unknown** are not eligible (fail closed) | B9. One function can't diverge between enforcement and reporting. A RIPEstat/Cymru outage must not turn a CDN edge into a port-check target |
| D19 | (user) IP owner | `ipowner` stage: Team Cymru over the existing `Resolver` (TXT at `<rev>.origin.asn.cymru.com`, `<rev>.origin6.asn.cymru.com`, `AS<n>.asn.cymru.com`), through the public resolvers, so it runs under `--passive`. One check per `ip` record outside in-scope netblocks. Emits `ip_owner` (ip → asn, prefix, holder). The holder lookup is cached in memory per ASN per run | B8 and B9. No new HTTP source, 50 queries/s instead of 1 request/s |
| D20 | B16 for TCP | In `TargetTCP`, an address refused only because it belongs to an excluded hostname is allowed when it is shared **and** otherwise eligible. An excluded CIDR always refuses. This matches `TargetHTTP` and B16's "only the excluded hostname itself" wording | Resolves the open note in Spec 1's verification. An in-scope, shared IP that an excluded host also uses is port-checked |
| D21 | Provider labels in outputs | No `provider_host` record. `inventory.ProviderHosts()` derives provider-hosts.csv rows (hostname, provider, service, evidence `cname`/`range`/`asn`, cname, resolves) from CNAME rows, `ip_owner`, `provider_range` and the embedded YAML. Spec 5 reads `View.ProviderHosts()`, with `resolves=false` for dangling chains (B5) | A stored label would go stale when the YAML changes in a new binary, since the resolve check key is only the hostname |
| D22 | Derived-view package | New `internal/inventory` builds, from store records plus the Scope: wildcard-only set, representatives, `ProbeHostnames`, `ProviderHosts`, and `IPRows`. The runner builds it at each Scope build and for `render` | One place for derived logic that outputs, `View` and Policy all need |
| D23 | Truncated bodies | `ThirdPartyResponse.Truncated bool`, set when the 10 MiB cap cuts the body. Stages that need the whole body treat it as an error. `ThirdPartyRequest.Timeout` (default `HTTPTimeout`, max 120 s) lets crt.sh take longer. crt.sh requests add `exclude=expired&deduplicate=Y` | Silent truncation would make crt.sh fail forever on big roots and make archive lists partial but "complete" |
| D24 | Archive paging | `wayback` and `commoncrawl` page through CDX results inside one check per root (`showNumPages`, `page=N`), up to 30 pages. Beyond the cap, coverage is partial. This is a known limitation (see Out of scope). The Common Crawl index id is recorded as an attr on the check's `hostname` observations | Checks can't be keyed per page because the page count needs network access in `Run`, not `Checks()` |
| D25 | Stage order (`DefaultDeps`) | `asn`, `org-asn`, `ct-org`, `whoisxml`, `crtsh`, `wayback`, `commoncrawl`, `virustotal`, `securitytrails`, `shodan`, `providerranges`, `resolve`, `wildcard`, `permutations`, `rdns`, `ipowner`. Passes repeat, so late discoveries are picked up (Spec 1 D5, B11) | Sources first, then DNS, then derived stages |
| D26 | New kinds | Added to `kinds.Default()`: `ip` (category `ips`, counted), `unresolved` (category `unresolved names`, counted), `wildcard`, `ip_owner`, `ip_hostname`, `provider_range` (all internal, no category). `resolution` stays uncounted. No new printed kinds, since `hostname` already prints | B20 and the Spec 1 console rules |
| D27 | Output files | `output.Default()` gains `subdomains.txt`, `resolutions.csv` (name, type, value), `unresolved.txt`, `wildcard-excluded.txt`, `ips.csv` (ip, asn, owner, provider, service, in_scope, port_eligible, hostnames) and `provider-hosts.csv` (above). `Deps` gains `Files []output.File` instead of the hard-coded `output.Default()` in `cli.go`. `Snapshot` carries the extra kinds and the inventory | The names were reserved in Spec 1 |
| D28 | Performance | A `View` caches `Records(kind)` for its lifetime (one stage pass). `rdns` and `permutations` check enumeration read each kind once | Spec 1 flagged full-kind reads as fine at its volume only. A /20 PTR sweep and many seeds make it real |

## Packages and changes

- `internal/egress`
  - `dns.go`: `CNAMEs []CNAME`, record type constants (`TypeA`, `TypeAAAA`, `TypeCNAME`, `TypePTR`, `TypeTXT`) so stages never import `miekg/dns` (D13 of Spec 1), CNAMEs also on NXDOMAIN/NODATA.
  - `thirdparty.go`: `Truncated`, `Timeout`, `KeyBodyField`.
  - `tcp.go`: call `Scope.PortEligible` and apply D20. `egress.go`: `Policy.Shared` is fed by the provider classifier.
  - Existing tests that read `CNAMEChain` are updated.
- `internal/scope`: `Config.WildcardOnly`, `PortEligible`.
- `internal/provider` (new): embedded `providers.yaml`, `Classify(ip, owner, ranges, cnames)`, unknown-owner fail-closed.
- `internal/inventory` (new): D22.
- `internal/dnsname` (new): reverse names (v4 and v6 nibbles), parent zones, label generation for permutations, eTLD+1.
- `internal/stages/subdomains`: `crtsh`, `wayback`, `commoncrawl`, `virustotal`, `securitytrails` via one table of fetchers over a shared check/enumeration type.
- `internal/stages/orgpivot`: `ct-org`, `whoisxml`, `org-asn`.
- `internal/stages/shodan`: paginated `net:` search per in-scope netblock, key `cidr`.
- `internal/stages/providerranges`: D17.
- `internal/stages/dns`: `resolve`, `wildcard`, `permutations`, `rdns`, `ipowner`.
- `internal/run`: `buildScope` computes the inventory, passes `WildcardOnly` to the Scope and `Shared` to the Policy; `render` adds the new kinds to `Snapshot`; `View` gains `ProbeHostnames`, `ResolvableHostnames` (in-scope and excluded), `ProviderHosts`, and the record cache.
- `internal/config`: settings `permutations.enabled`, `permutations.max_per_seed`; flags `--no-permutations`, `--permutations-max`; validation; help defaults; populate `builtin/wordlist.txt` (about 100 common labels); `keys.virustotal|securitytrails|shodan|whoisxml`.
- `internal/output`, `internal/kinds`, `internal/cli`: D26, D27, D25.

## Test plan

Tests use loopback fake DNS, per-source `httptest` servers via `egress.Options.SourceBaseURLs`, fake range files and an injected random-label source. Integration tests go through `cli.Execute`.

| B | Tests |
|---|-------|
| 1 | each keyless source yields subdomains for its fixture; a keyed stage without a key is `not-configured (no key)` and with one the key reaches the request but never output or `state.db`; 401, 403 and 429 fail the stage (not recorded) and are retried next run, and fixing the key then completes them; a truncated body is an error; crt.sh uses the longer timeout |
| 2 | a permutation is never a seed; a name found by `crtsh` and also generated by `permutations` is a seed; a permutation later seen by `rdns` stays a non-seed only if no other source saw it; `--no-permutations` shows `disabled`; runs under `--passive`; changing the wordlist or the cap creates new checks; invalid cap exits 2; per-seed output is capped |
| 3 | NXDOMAIN, NODATA and SERVFAIL go to `unresolved` with the right rcode; a DNS timeout is a failed check, retried next run; a host behind a CNAME has its A record keyed to the queried name, is port-eligible, and is excluded when the A record is in an excluded CIDR |
| 4 | a wildcard zone excludes its names and one representative reaches `ProbeHostnames`; a name discovered after the zone's check is still wildcard-only; a rotating CDN wildcard is detected by CNAME or address overlap; wildcard-only names do not make an IP eligible |
| 5 | a CNAME into a provider suffix yields a provider-hosts row with `resolves=true`; a dangling chain ending in NXDOMAIN yields `resolves=false`; unrelated suffixes yield no row |
| 6 | `ct-org` and `whoisxml` give `root` candidates (in candidates.csv, zero queries for them afterwards); `org-asn` gives netblock candidates, caps ASNs, ignores unrelated holders, and is not in scope; the netblock guard ignores them |
| 7 | a /30 is PTR-swept in full; an IPv6 /64 only checks addresses found by other stages; an out-of-scope PTR name is a candidate and appears in ips.csv `hostnames`; Shodan hostnames appear there too; rDNS is not run for non-scope IPs |
| 8 | CNAME suffix labels, AWS CLOUDFRONT/ELB ranges and CDN ASNs label hosts and IPs; EC2-only is not shared; an AWS apex ALIAS (A record, no CNAME) into a CloudFront range is shared; GCP and Azure fail closed; a hyperscaler address with no range data is shared |
| 9 | the eligibility table (in-scope IP, hostname-resolved IP, shared, excluded host, excluded CIDR, wildcard-only, unknown owner, IPv4 vs IPv6) through `PortEligible`, and TCP to a refused address is refused by egress; with the owner source returning errors, a CDN edge IP is **not** eligible and shows `owner=unknown`; the ips.csv `port_eligible` column equals the egress decision for the same table |
| 16 (from Spec 1) | an in-scope, shared IP that an excluded host also uses is port-checked (D20); an excluded CIDR always refuses |
| Plumbing | new files are sorted, stable, CSV-safe, and have first/last seen; new kinds appear in the summary categories; the Spec 1 boundary test still passes (no new package imports `net` or `miekg/dns`) |

## Spec amendments made

- **B9 (clarification):** an IP outside in-scope netblocks whose owner could not be determined is treated as not eligible.
- **B16 (TCP):** the shared-infrastructure exception applies to TCP the same way as HTTP (D20).
- **B2 (detail):** the cap is per seed (`permutations.max_per_seed`), not per root, so check keys stay stable as seeds are added.

## Out of scope for Spec 2

- HTTP probing of wildcard representatives (Spec 3), recording archive URLs (Spec 3.6) and takeover fingerprints (Spec 5). Spec 3 must use `View.ProbeHostnames()`.
- A configurable resolver list and per-source rate overrides. VirusTotal's public key (about 4 requests a minute) will hit 429 at the default 1/s and show as failed until `rate.per_source` is lowered.
- Archive coverage beyond 30 CDX pages per root (partial, silently) and Common Crawl's flaky availability (it will often show as failed).
- Refreshing DNS answers, wildcard verdicts and provider ranges automatically: use `--redo resolve|wildcard|providerranges`.
- Azure service ranges, and GCP service-level discrimination.
- Added during development: the WhoisXML, VirusTotal, SecurityTrails and Shodan `net:` request shapes are unverified against live services (see Implementation). Shodan reads at most 10 pages (1,000 results) per netblock.
- Wildcard detection samples two probe labels once, so a wildcard that rotates through many addresses with no common CNAME can leave some names unflagged. `providers.yaml` is a starter list, and the org-to-ASN holder match is a token heuristic.
- Under a wildcard zone with permutations on (the default), every generated name "exists": each is printed as a found host, counted under `hosts`, and listed in `wildcard-excluded.txt` (hundreds of names). They are excluded from `subdomains.txt`, port checks and `ProbeHostnames()`.
- The inventory and its provider ranges are rebuilt from the store after every stage that does work; with the full AWS range list this is the main per-pass cost.

# Implementation (Develop)

## How it was built

Tests first. The red step was a compile failure in every touched package, because the tests used the Design's names before they existed. Then bottom-up: `dnsname`, `provider` (embedded `providers.yaml`), `scope` (`WildcardOnly`, `PortEligible`), `config`, `kinds`, `egress`, `inventory`, the runner (`View` cache and methods, inventory feeding `Scope` and `Policy`), `output`, the stages and `DefaultDeps`/`Deps.Files`. `go vet ./...` is clean and `go test -race ./...` passes, including the unchanged Spec 1 suite and boundary test. Mutating the 401/403/429 abort, the queried-name keying and the seed-parent rule each made the new tests fail.

- **Stages:** one `run.Stage` per source in the D25 order. Packages: `stages/{subdomains,orgpivot,shodan,providerranges,dns}`, plus `stages/httpsrc` for shared status handling (a keyed 401/403/429 wraps `run.ErrAbortStage`).
- **Derived logic:** `internal/inventory` computes wildcard-only names, representatives, seeds, `Shared`/`OwnerKnown`, `ProbeHostnames`, `ProviderHosts` and `IPRows` from plain `Data`, rebuilt at every Scope build, never stored. A CNAME chain into a known provider also marks the name's addresses shared (D17 "extra evidence"), which catches Heroku-style hosts on EC2-only ranges.
- **Egress:** `Policy.Shared` (true shared infrastructure) and a separate `Policy.OwnerUnknown`. TCP passes `shared` and `ownerKnown` separately to `PortEligible`; the excluded-host exception (`Scope.ExcludedFor`, shared by TCP, HTTP and `PortEligible`) uses true-shared only, so an unknown owner never widens it.
- **Test support:** `internal/egress/egresstest`, a scriptable fake DNS server, placed under `internal/egress` so the boundary test allows its `net`/`miekg/dns` imports.

## How each behaviour was tested

- **B1:** `cli` `TestB1_*` (keyless sources, paging, crt.sh flags, Common Crawl index attr, `not-configured (no key)`, key never in any file or output, 401/403/429 abort then complete once the key is fixed, truncated body, crt.sh timeout); `egress` `Truncated`/`Timeout`/`KeyBodyField` tests.
- **B2:** `cli` `TestB2_*` (never a seed, found-by-crt.sh is a seed, apex is not a seed, `disabled`, `--passive`, invalid cap exits 2, per-seed cap, cap and wordlist create new checks); `inventory.TestSeeds`, `dnsname.TestPermute`, `config` tests.
- **B3:** `cli` `TestB3_*` (rcodes, timeout retried, A keyed to the queried name, excluded by CIDR); `egress.TestResolverCNAMEsOnEveryRcode`.
- **B4:** `inventory` wildcard and probe tests; `cli` `TestB4_*` (two random 16-char labels, representative, late name caught, CNAME match, defaults-on permutations, sub-root zones); `stages/dns` label injection.
- **B5, B8:** `provider`, `inventory.TestProviderHosts`/`TestSharedFromRanges`, `cli` `TestB5_*`/`TestB8_*` (suffixes, CLOUDFRONT, EC2-only, apex ALIAS, GCP/Azure/CDN, no range data, CNAME-only Heroku).
- **B6, B7:** `cli` `TestB6_*`, `TestB7_*` (candidates, ASN cap, no enumeration, /30 sweep, IPv6 only found addresses, PTR and Shodan names).
- **B9, B16:** `scope.TestPortEligible`, `egress` TCP table, `TestTCPExcludedHostOnSharedInfra`, `TestHTTPUnknownOwnerIsNotShared`, `inventory.TestIPRowsMatchEgress` (ips.csv equals egress), `cli.TestB9_*`.
- **Plumbing:** `cli.TestPlumbing_FilesAndCounts`, `output` and `kinds` registry tests.

## Deviations from the plan

- **Input roots are resolved**, not only hostname records (Spec 1 says roots are not yet expanded into hostnames). An apex with no address shows in `unresolved.txt`.
- **Seeds need an in-scope parent**, so the apex (parent `com`) is never permuted into other registrants' domains. Wildcard zones are likewise limited to in-scope names.
- **SERVFAIL on a permutation proves nothing** (treated as not existing); D13 said anything but NXDOMAIN exists.
- **Shodan reads at most 10 pages per netblock**; WhoisXML 402 is a plain failed check, not an abort.
- **ct-org reads `common_name`.** Live, a crt.sh `O=` search returns the organisation in `name_value` and the certificate name in `common_name`; no identity-search fallback was needed.
- New names the Design left open: `inventory.*` (scope-dependent methods take the `*scope.Scope`), `View.Seeds(generator)`, `output.Snapshot.Inv`, `config.Settings.{WordlistWords,WordlistHash,Permutations}`, `provider.{Owner,Range,Result}`. Team Cymru's trailing `, CC` is stripped from holders.

## External facts

- **Confirmed live:** RIPEstat `searchcomplete`, AWS and GCP range files, crt.sh `O=` (shape above).
- **Confirmed from vendor docs:** Team Cymru TXT formats, Shodan `host/search`.
- **Not confirmed (docs unreachable):** WhoisXML `apiKey` body field and request shape (D7), VirusTotal, SecurityTrails, Shodan `net:`, Wayback `showNumPages`, Common Crawl `collinfo.json`/`showNumPages`. These follow the providers' documented behaviour as remembered and are tested only against fakes of the same shape, so they need a live check with real keys.

# Verification

**Result: the goal and all nine behaviours are met.** Each behaviour was traced through the code (stages, `inventory`, `scope.PortEligible`, `provider.Classify`, egress `TargetTCP`, outputs) and its tests. `go vet ./...` is clean and `go test -race ./...` passes.

- **B1–B9** are implemented as designed. Keyed sources show `not-configured (no key)`. A 401, 403 or 429 aborts the stage. Addresses are keyed to the queried name. Wildcard-only status is computed on read, with one representative per zone in `ProbeHostnames()`. Dangling provider CNAMEs reach `ProviderHosts()` with `resolves=false`. Candidates are never enumerated, and only in-scope netblocks are swept or searched. Egress and ips.csv share a single, fail-closed eligibility decision.
- **Develop deviations reviewed:** input roots are resolved, seeds need an in-scope parent, a SERVFAIL on a permutation proves nothing, and Shodan reads at most 10 pages. All are consistent with the behaviours.
- **Still open:** the live request shapes listed under External facts (WhoisXML, VirusTotal, SecurityTrails, Shodan `net:`, Wayback/Common Crawl paging) have only been tested against fakes.

## Fixes made during verification

- **AWS `AMAZON`-only addresses (B8, B9).** An address that matched only the `AMAZON` superset range was labelled `EC2` and treated as dedicated, so it was port-eligible. Only an `EC2` range now marks an address as dedicated. `AMAZON`-only is shared (fail closed, as for GCP). Test: `provider.TestClassify`.
- **Wildcard probe SERVFAIL (B4).** If both probes got SERVFAIL, the zone was recorded as "not a wildcard" and never re-checked, so every name under a real wildcard (including permutations) became probe-eligible and port-eligible. When no probe answered and any probe got SERVFAIL, the check now fails and is retried next run. A probe that did answer still records the wildcard. Tests: `stages/dns.TestWildcardServFailIsAnError` and `TestWildcardAnswerWinsOverServFail`.
- **Wayback page count (B1).** A non-numeric `showNumPages` response (such as an HTML error page with status 200) was read as zero pages, and the check was recorded as complete. It is now an error, as Common Crawl already handles it. Test: `cli.TestB1_UnreadableWaybackPageCountIsAnError`.

Each new test fails when its fix is reverted.
