# Spec 5 of 6: recon (Go) — Risk findings

## Goal

Turn what Specs 2–4 discover into a severity-ranked list of obvious exposures, without exploiting
anything. Depends on Specs 1–4.

## Behaviours

1. Every finding has a severity (high, medium or low). Each finding type has a documented default
   severity. Unattributed storage findings are never listed in the summary as high or medium.
2. **Takeover candidates:** DNS records pointing at cloud/SaaS resources that look unclaimed according
   to known fingerprints are flagged. In passive-only mode only DNS evidence is used.
3. **Cloud storage, attributed:** buckets/containers referenced by in-scope DNS records or discovered
   URLs are reported as attributed, recording whether they exist, are public, and are listable. For
   listable ones, an object count and the first few key names are recorded, never object contents.
4. **Cloud storage, unattributed:** names guessed from company and domain names (capped per root,
   configurable) are checked on AWS, Azure and GCP and reported separately as unattributed, never as
   attributed findings. Storage checks run in passive-only mode.
5. **Exposed sensitive paths:** each path in a configurable list is requested once per live web
   service per run, and not again on later runs unless the earlier request failed transiently or the
   stage is redone. This applies to company hosts behind CDNs, on shared hosting and on
   company-specific PaaS hostnames, but not to hostnames served by third-party SaaS platforms.
   Responses matching the path's expected signature are flagged, recording URL, status, size and the
   matched signature; response bodies are not stored.
6. **Email posture:** MX, SPF, DMARC and common DKIM selectors are read for each in-scope root.
   Flagged: SPF missing, `+all`/`?all`, or more than 10 DNS lookups; DMARC missing or `p=none`; a root
   with no MX lacking a `v=spf1 -all` record. DKIM selectors found are recorded; not finding one is
   informational only.
7. **Risky open ports:** open ports on a configurable list (e.g. RDP, SMB, Telnet, database ports) are
   flagged.
8. **Certificate issues:** expired certificates, certificates expiring within a configurable number
   of days, and self-signed certificates are flagged.

# Design

## Decisions

| # | Decision | Answer | Rationale |
|---|----------|--------|-----------|
| D1 | (user) Findings are derived | Stages store **evidence** records only. New pure package `internal/findings` has `Derive(Input) []Finding`. `Input` holds the evidence kinds below plus `open_port`, `web_service`, `resolution`, `unresolved`, `wildcard`, the Scope, the Inventory, the Settings and today's date. It holds the one severity table (D2), the unattributed rule (B1) and visibility filtering: `output.PortVisible` for ports, `output.WebVisible` for web, certificate and sensitive-path findings, and `ClassifyHost == InScope` for hostnames. The runner stores the result as `finding` records through a pseudo-stage `findings` with the single check key `derived`: `st.Complete("findings", "derived", obs)`, exactly as `guard` does. So a finding no longer derived becomes not-current, `first_seen` is kept, and `store.OnNew` prints each new finding's found line. **When:** after every stage that executed ≥1 check (where `buildScope` already re-runs), and in `render()` before the files are written, including the interrupt and exit paths. Derive reads only the kinds it needs. After the `Complete`, `render` flushes and re-reads `finding` before writing files and totals | (user) Risky-port findings depend on `risky_ports`, certificate findings on today's date, and every finding on scope; derived on read, none goes stale (Spec 1 D16). One table makes B1 checkable. It replaces Spec 4 D9's "register a PortKey finding kind". It also closes the existing gap where `emitSummary` lists findings without visibility filtering |
| D2 | (user) Severities | Fixed in code, documented in `--help` and the README, and not configurable:<br>**takeover:** high; a missing bucket referenced only by `<a href>`/`<area href>` is low (user)<br>**storage, attributed:** listable high; public but not listable medium; exists and private low<br>**storage, unattributed:** public or listable, low always (D9)<br>**sensitive path:** the matched entry's `severity` (default medium)<br>**email:** SPF `+all` high; SPF missing, `?all` or invalid (several `v=spf1` records, or an unresolvable include) medium; SPF > 10 lookups low; DMARC missing medium; DMARC `p=none` (or applicable `sp=none`) low; a root with no MX (a null MX counts as none) lacking `v=spf1 -all` low<br>**risky open port:** medium<br>**certificate:** expired medium; expiring within N days low; self-signed low | (user) B1. Unattributed findings are low by construction, so they never reach the summary's high/medium list. DKIM is never a finding (B6) |
| D3 | Finding record | Key `<category>\|<target>` for takeovers (one per hostname), otherwise `<category>\|<type>\|<target>`. Attrs: `category` (`takeover`, `storage`, `storage-unattributed`, `sensitive-paths`, `email`, `ports`, `certificates`), `type`, `severity`, `target`, `detail`, plus the category's file columns (D13). `finding` stays Printed under the `findings` category | The found line already shows `finding <category>: <target>` with severity (`runner.onNewRecord`) |
| D4 | Stages and order | `cli.defaultStages()`: … `ipowner`, **`email`** (ThirdParty), `httpprobe`, `crawl`, **`storage`** (ThirdParty), **`takeover`** (Target), **`sensitive-paths`** (Target), `ports`. Risky ports and certificates need no stage | Storage runs after crawl, so references found in the same pass are checked. The Target stages run before the hours-long port sweep (Spec 4 D1). Passes repeat, so later finds are picked up |
| D5 | Provider table (one table) | `internal/provider/providers.yaml` changes:<br>**cname entries:** gain optional `class` (`saas`), `nxdomain: true` (claimable when the chain dangles) and `body` (RE2 regex marking an unclaimed resource)<br>**asn entries:** may have class `saas`<br>**address ranges:** a new `ranges:` list (CIDR → provider, service, class) for SaaS reached by apex A records (e.g. GitHub Pages `185.199.108.0/22`)<br>**initial SaaS set:** Shopify (including its ASN), Zendesk, Statuspage, Squarespace, Wix, ReadMe, Unbounce, Ghost, GitHub Pages (Squarespace and Wix ASNs/ranges confirmed in development)<br>**fingerprints:** a hand-curated starter set: S3 `NoSuchBucket`, Heroku, GitHub Pages, Shopify, Zendesk, Statuspage, Unbounce, Ghost, ReadMe bodies; Azure `cloudapp.net`/`cloudapp.azure.com`/`azurewebsites.net`/`trafficmanager.net`/`blob.core.windows.net` and Elastic Beanstalk `nxdomain`.<br>`inventory.SaaSServed(host)` is true if any match is `saas`: a CNAME chain, an address's ASN or an address range. Takeover reads `View.ProviderHosts()` (Spec 2 D21), which gains the matched entry | One matcher and one table; Spec 2 B5/D21 named `ProviderHosts()` as Spec 5's input. Apex hosts on SaaS usually have no CNAME (B5) |
| D6 | Takeover, DNS (B2) | Derived, with no new queries, so it works under `--passive`. A `ProviderHosts()` entry with `Resolves=false`, a matched cname entry with `nxdomain: true`, and an `unresolved` record with rcode NXDOMAIN for the host is a takeover (`type` includes `dns-nxdomain`). Another kind of DNS evidence: an attributed bucket (D8) whose `storage` record has `exists=false` (`storage-missing`; its severity is set by the kind of reference, D2). All evidence for one hostname, or for a URL-only bucket, forms **one** finding whose `type` lists each kind (`dns-nxdomain;storage-missing`) | `resolve` already records the chain and the rcode. Deduplication stops one dangling Azure or S3 CNAME from appearing two or three times in the summary |
| D7 | Takeover, HTTP (B2) | Target stage `takeover`. One GET `/` (`egress.Root`) per current, visible `web_service` whose host's `ProviderHosts()` match has a `body`. Key `<service-url>\|fp=<sha256(matched entry)[:8]>`. A match emits `takeover_http` (host, url, status, service). No match, `NoService` or `Refused` completes with nothing; errors are transient. Not-configured under `--passive` through the existing gate | Hashing only the matched entry re-checks only the services an edited fingerprint affects. httpprobe stays unchanged |
| D8 | (user) Storage references (B3) | New pure package `internal/cloudstorage`. `ParseRef(url or host)` → provider, bucket or account, container, object. It recognises S3 virtual-host, path-style, regional and website hosts; GCS `storage.googleapis.com`, `<b>.storage.googleapis.com`, `storage.cloud.google.com` and the `c.storage.googleapis.com` CNAME (bucket = alias name); Azure `<acct>.blob.core.windows.net` and `<acct>.web.core.windows.net` (container `$web`). **References:**<br>(a) CNAME chains of in-scope, non-excluded, non-wildcard-only hostnames<br>(b) `storage_ref` observations: crawl emits one for every storage URL in any `a`, `area`, `link`, `script`, `img`, `iframe`, `source`, `form` target of a fetched page; httpprobe emits one for each redirect hop to a storage URL. Attrs: provider, name, container, object, page, page_host and `via` (`cname`, `link` for `a`/`area`, otherwise `asset`). No extra requests.<br>A reference counts only while its page host is `WebHostInScope`. A bucket is **attributed** iff it has a current reference | B3. Today the crawl drops off-scope link hosts. `via` drives D2's link-only rule. Derive never scans `url`. Existing engagements need `--redo crawl` (the crawl key is not bumped) |
| D9 | (user) Unattributed names (B4) | `cloudstorage.Guess(base, cap)` takes the names in priority order and keeps the first `storage.max_names`, per root and per org input:<br>**bases:** for a root, its registrable label (`example`), `example-com` and `example.com`; for an org, `acmecorp` and `acme-corp`<br>**order:** each base, then `base-<word>`, then `<word>-base`, for the words `backup backups dev prod staging test assets static media files uploads public private data logs www web cdn images docs`<br>**provider rules:** S3/GCS names are 3–63 chars `[a-z0-9.-]`; Azure account names have `-` and `.` removed and are 3–24 chars, otherwise dropped<br>**file:** storage-unattributed.csv lists every existing guessed name that is not attributed<br>**findings:** only public or listable ones (low) | (user) Guessed buckets may belong to anyone. A guessed name that is also referenced is the same check, so it is attributed and never also listed as unattributed |
| D10 | Storage checks (B3, B4) | ThirdParty stage `storage`, which runs under `--passive`.<br>**Checks:**<br>`s3\|<bucket>`, `gcs\|<bucket>`: list<br>`azure-account\|<acct>`: DNS A of `<acct>.blob.core.windows.net`; emits `storage_account` (exists)<br>`azure\|<acct>/<container>`: yielded for existing accounts only (next pass), for the fixed list `$web $root public assets static media images files uploads backup data logs` (user) and for every container named in a reference<br>`<provider>-obj\|<name>/<object>`: one anonymous **HEAD**, for the first listed key or each referenced object; emits `storage_object` (public yes/no)<br>**Requests:**<br>S3 path-style `https://s3.amazonaws.com/<b>?list-type=2&max-keys=1000`; on 301 or 307, follow `x-amz-bucket-region` (validated `^[a-z0-9-]+$`), else the region in the `Location` host or the error body's `<Endpoint>`, to `s3.<region>.amazonaws.com`<br>GCS `https://storage.googleapis.com/<b>?max-keys=1000`<br>Azure `?restype=container&comp=list&maxresults=1000`<br>**Outcomes:** 404 NoSuchBucket/ContainerNotFound → `exists=false`; 401/403 → exists, not listable; Azure 404 ResourceNotFound or 409 PublicAccessNotPermitted → existence unknown, not listable (completes; neither a finding nor a takeover); 200 → listable, `object_count` (`1000+` if truncated) and `first_keys` (first 5). Other statuses are transient.<br>**Record:** `storage`, keyed `<provider>\|<name>`. `public` is derived: yes/no from `storage_object`, else unknown. Object contents are never fetched | Keying by bucket only keeps `public` and `listable` from going stale (the store merges attrs in check-key order) and avoids re-listing. Path-style avoids TLS failures on dotted names (U3: "public" = an anonymous HEAD succeeds) |
| D11 | Sensitive paths (B5) | YAML entries are `{path, signature (RE2 over the ≤1 MiB body) and/or magic (hex prefix, bytes.HasPrefix), status (default 200), severity (default medium)}`. Entries without `signature` or `magic`, and plain strings, fail validation (exit 2): Spec 1 marked the format provisional. `Settings.SensitivePathList` stays `[]string` for egress, with a parallel `SensitivePathEntries`.<br>**Checks:** one per (current, visible `web_service` not `SaaSServed`, entry), keyed `<service-url>\|<path>\|<sha256(signature,magic,status)[:8]>`; `Input` carries the index; path-major order. GET via `egress.SensitivePath`.<br>**Results:** a match emits `sensitive_hit` (url, path, status, size, signature). No match, `NoService` or `Refused` completes; errors are transient. Severity comes from the current entry with the same path and hash (medium if none). A hit counts only while its service is current and visible.<br>**Built-in list:** about 20 entries (`.git/config`, `.env`, `.DS_Store`, `server-status`, `phpinfo.php`, `actuator/env`, `.aws/credentials`, `wp-config.php.bak`, `.svn/entries`, `.htpasswd`, backup archives by magic bytes, …) | B5: once per service per run, not again unless transient or redone. Signatures stop catch-all-200 sites from flagging everything. Go RE2 decodes UTF-8, so binary magic needs bytes. No body is stored |
| D12 | Email (B6) | ThirdParty stage `email`, one check per in-scope input root, keyed `<root>\|dkim=<hash(selectors)>`.<br>**Queries** (egress Resolver): MX, TXT at the root, TXT `_dmarc.<root>`, then `_dmarc.<eTLD+1>` with `sp=` (falling back to `p=`) when the root is a subdomain; TXT `<sel>._domainkey.<root>` for a built-in selector list (`google selector1 selector2 k1 k2 default dkim mail s1 s2 smtp mandrill`, …).<br>**SPF lookups:** counted per RFC 7208 §4.6.4 (`include a mx ptr exists redirect`), following include/redirect recursively with loop detection and a hard stop.<br>**Failures:** a timeout or SERVFAIL on MX, root TXT, an SPF include or redirect, or the `_dmarc` lookups is transient (an include's is an RFC 7208 temperror). On a selector it is recorded in `dkim_errors`. An include that does not exist, has no single SPF record or is not a domain name marks SPF invalid (permerror); a macro include is counted but not followed. A `redirect=` is counted only when the record has no `all`. A selector counts only for a DKIM key with a non-empty `p=`.<br>**Record:** `email_posture`, keyed by root (mx, spf, spf_records, spf_all, spf_lookups, dmarc, dmarc_policy, dmarc_source, dkim_selectors, dkim_errors). Egress adds `TypeMX` and an MX rdata case (`<pref> <host>`) | A permanently SERVFAILing `_domainkey` name must not block a root's SPF and DMARC findings forever |
| D13 | Outputs | Added to `output.Default()`:<br>**email-posture.csv:** root, mx, spf, spf_lookups, dmarc, dmarc_policy, dkim_selectors<br>**storage-unattributed.csv:** provider, name, url, exists, public, listable, object_count, first_keys, generated_from, severity<br>**risk-takeover.csv:** severity, target, type, service, cname, detail<br>**risk-storage.csv** (attributed only): severity, provider, name, url, exists, public, listable, object_count, first_keys, referenced_by<br>**risk-sensitive-paths.csv:** severity, url, path, status, size, signature<br>**risk-email.csv:** severity, root, type, detail<br>**risk-ports.csv:** severity, ip, port, banner, hostnames<br>**risk-certificates.csv:** severity, url, type, tls_subject, tls_issuer, tls_expiry<br>risk-*.csv list **every** `finding` record of their category with `current`, first_seen and last_seen | Spec 1 B20 reserved these names. Spec 1 says CSVs list all records, so fixed findings stay on record |
| D14 | Risky ports, certificates (B7, B8) | Derived. **Ports:** `open_port` passing `output.PortVisible` with port ∈ `risky_ports`. **Certificates:** a visible `web_service` with `tls_expiry` < today (expired), `tls_expiry` < today + `cert_expiry_days` (expiring), or `tls_self_signed` (one finding per service) | B7 and B8. Expiry moves with the clock and needs no new requests |
| D15 | Settings | `storage.max_names` / `--storage-max-names`, default 50, > 0 (user). `cert_expiry_days` / `--cert-expiry-days`, default 30, ≥ 0. The `sensitive_paths` format (D11). All shown in help | B4, B8 and Spec 1 B5 |
| D16 | Egress | `ThirdPartyHTTP` allows HEAD.<br>**Source patterns:** gain a single-label middle wildcard (`s3.*.amazonaws.com`, label `[a-z0-9-]+`). The storage stage's sources are `s3.amazonaws.com`, `s3.*.amazonaws.com`, `storage.googleapis.com` and `*.blob.core.windows.net`.<br>**Candidate exemption:** new optional stage interface `run.CandidateExempt{ CandidateExemptSources() []string }`. Hosts matching those patterns (storage: `*.blob.core.windows.net`) skip only the candidate refusal; an in-scope or excluded host is still refused. They still appear in candidates.csv.<br>**Test hook:** `Options.SourceBaseURLs` also accepts exact hosts, checked before patterns, so tests can tell Azure accounts apart | A redirect to `acct.blob.core.windows.net` records that host as a candidate, which would make the storage check impossible. Narrow patterns keep EC2, ELB and API Gateway customer hosts out of reach |
| D17 | Kinds | Internal, with no category: `takeover_http`, `storage`, `storage_account`, `storage_object`, `storage_ref`, `sensitive_hit`, `email_posture` | Spec 1 B18 totals cover findings, not evidence |

## Packages and changes

- `internal/findings` (new): `Derive`, the severity table, attribution and dedup (D1–D3, D6, D8, D9, D14).
- `internal/cloudstorage` (new, pure): `ParseRef` and `Guess` (D8 and D9).
- `internal/stages/risk` (new): stages `email` (D12), `storage` (D10), `takeover` (D7) and `sensitive-paths` (D11). It imports no `net`.
- `internal/stages/web`: crawl emits `storage_ref` for every recognised link or asset; httpprobe emits it for redirect hops (D8).
- `internal/provider`: the `providers.yaml` schema changes (`class`, `nxdomain`, `body`, `ranges`) and the starter fingerprints (D5).
- `internal/inventory`: `SaaSServed`, and `ProviderHosts` carries the matched entry.
- `internal/run`:
  - the `findings` pseudo-stage, derivation after stages that did work and in `render()` (with the flush and re-read);
  - `View` accessors for evidence kinds;
  - the `CandidateExempt` interface passed to egress.
- `internal/egress`: HEAD on third-party requests, `TypeMX` and MX rdata, single-label source wildcard, the candidate exemption, exact-host `SourceBaseURLs` (D16).
- `internal/config`: `storage.max_names`, `cert_expiry_days`, and the sensitive-path entry format and validation. The built-in `sensitive_paths.yaml` and the DKIM selector list are populated.
- `internal/output`: the eight files (D13). `internal/kinds`: D17. `internal/cli`: the stage order (D4) and help text listing the severity table.
- Existing tests that assert the stage list, the file registry, the help text or the sensitive-path format are updated.

## Test plan

Integration tests go through `cli.Execute` with:
- the loopback fake DNS;
- per-source `httptest` fakes for S3, GCS and Azure (exact-host mapping), which count GET and HEAD per path;
- DialMap'd loopback web services;
- an injected clock.

| B | Tests |
|---|-------|
| 1 | `findings` table test: every type has a severity and matches D2. An unattributed listable bucket is low and absent from the summary. Mutating a severity fails a test |
| 2 | A dangling CNAME into an `nxdomain` provider gives one high takeover under `--passive` with zero target requests. A resolving provider host whose body matches gives a takeover through the `takeover` stage; a non-matching body gives none. Under `--passive`, `takeover` is `not-configured (passive-only)`. A CNAME to a missing S3 bucket, or to a dangling Azure account, gives exactly one finding listing both kinds of evidence. A missing bucket in `script src` is high and one only in `<a href>` is low. Editing one fingerprint re-checks only the services it matches |
| 3 | CNAME, crawl `script src` and redirect references are attributed. A listable bucket records `object_count`, `1000+` when truncated, and the first 5 keys, with object GETs = 0 and HEAD = 1. 403 is exists-private and public unknown. The region redirect is followed. An Azure account is found by DNS, then the fixed containers are tried. A new referenced object adds one HEAD check, does not re-list the bucket, and does not leave a stale `public` |
| 4 | Guessed names are capped per root and per org, in priority order, and checked on all three providers. Changing the cap adds only new checks. They run under `--passive`. Unattributed names appear in storage-unattributed.csv and never in risk-storage.csv; a private one is not a finding. A guessed name that is also referenced is attributed |
| 5 | Each path is requested exactly once per live service, zero times on a re-run, again after a transient failure, and again after `--redo sensitive-paths`. A SaaS host (by CNAME, and an apex by address range) is skipped. CDN, PaaS and IP-literal services are requested. A match records url, status, size and signature, and the body never reaches `state.db`. A catch-all 200 without a match is not flagged. A gzip `magic` entry matches. Invalid entries exit 2. A hit whose service is no longer current is not a finding |
| 6 | Table of SPF, DMARC and MX cases: `+all`, `?all`, missing, several records, an include chain over 10, an include loop, null MX, no MX without `-all`, `p=none`, a subdomain root with `sp=`. SERVFAIL on `_dmarc` is a failed check retried next run. SERVFAIL on a DKIM selector or an include does not fail the check. A selector that is found is recorded; finding none produces no finding |
| 7 | A risky open port is flagged medium. An exclusion added later makes it not-current in risk-ports.csv and removes it from the summary |
| 8 | Expired, expiring and self-signed certificates are flagged. Advancing the clock turns an expiring certificate into an expired one with zero new requests. `--cert-expiry-days` changes the window |
| Plumbing | The new files are sorted, CSV-safe and dated. A fixed finding stays as a `current=false` row. The summary lists exactly the current high and medium findings. A found line is printed once per engagement, including for a finding derived on the SIGINT render path. Help shows the new settings and the severity table. The boundary test still passes |

## Spec amendments made

- **B2:** DNS-only takeover evidence is a dangling CNAME (NXDOMAIN) into a provider marked claimable, or a referenced bucket that does not exist. A missing bucket referenced only by a plain link is low (user).
- **B3:** "public" means an anonymous HEAD of a known object succeeds. It is unknown when no object is known.
- **B5:** every sensitive-path entry needs a `signature` or `magic`.
- **Spec 1:** takeover is one Target stage, `takeover`, plus derived DNS evidence (not `takeover-dns`/`takeover-http`). `ThirdPartyHTTP` allows HEAD. Azure storage account hosts may be contacted by the storage stage even when recorded as candidates; they are provider endpoints, not target systems.
- **Spec 4 D9:** risky-port findings get port visibility through derivation, not a `PortKey` finding kind.

# Implementation (Develop)

Built test-first: every new test failed (most did not compile) before any code was written; after the code, the whole suite passes except `TestWebB3_AllAttributes` and `TestWebB3_ExpiredAndSelfSignedCertificatesAreRecorded`, which fail identically without this change (Go's stricter x509 checks on the test certificates).

## How it was built

- **`internal/cloudstorage`** (pure): `ParseRef`, `ParseCNAME`, `RootBases`/`OrgBases`/`Guess`, `ProviderName`, `Key`, `URL`, `PublicState`. `Guess` orders names as all bases, then base-major `base-<word>`, then `<word>-base`, so raising the cap only adds names.
- **`internal/findings`** (pure): `Derive(Input)`, the one severity table (`SeverityTable`, `Severity`, `HelpTable`), `References` and `Attribution`. A takeover is one finding per hostname (or per URL-only bucket) whose `type` lists each kind of evidence (`dns-nxdomain`, `http-fingerprint`, `storage-missing`, `storage-missing-link`), with the highest severity. Certificates likewise give one finding per service (`expired;self-signed`).
- **`internal/run`**: `deriveFindings` stores the result through the `findings` pseudo-stage (`Complete("findings","derived",…)`) after every stage that executed checks and in `render()`, before the files are written, then flushes and re-reads. A signature of every kind's store version (except `finding`), the date, the Scope and the Inventory skips redundant derivations. `View` gained `StorageRefs` and `SaaSServed`; `CandidateExempt` is passed to egress through the new `Egress.ClientsWith`. `render()` also builds `Snapshot.Storage` (attribution) for `storage-unattributed.csv`.
- **`internal/stages/risk`**: `email`, `storage`, `takeover`, `sensitive-paths` (no `net` import). Evidence kinds registered in `internal/kinds` (D17).
- **`internal/stages/web`**: the crawl records a `storage_ref` for every storage URL in `a`, `area`, `link`, `script`, `img`, `iframe`, `source` and `form` (off-scope hosts included; `a`/`area` are `via=link`, the rest `asset`); httpprobe records one per redirect hop.
- **`internal/provider`/`inventory`**: `providers.yaml` gained `class`, `nxdomain`, `body`, `ranges` and the starter SaaS/fingerprint set; `provider.Entry` (with `Hash`, `BodyMatches`), `DB.CNAMEEntry`, `Result.Class`, `ProviderHost.Entry`, `Inventory.SaaSServed`.
- **`internal/config`**: `storage.max_names`, `cert_expiry_days`, the sensitive-path entry format (`SensitivePath` with `Match` and `Hash`; invalid entries fail validation, exit 2), a built-in list of 24 entries, the DKIM selector list.
- **`internal/egress`**: HEAD on third-party requests, `TypeMX` and MX rdata, single-label middle wildcard, `ClientsWith` candidate exemption, exact-host `SourceBaseURLs`.
- **`internal/output`**: the eight files (D13). **`internal/cli`**: stage order (D4) and the severity table in `--help`.

## How each behaviour is tested

| B | Tests |
|---|-------|
| 1 | `findings.TestSeverityTable` (golden table; unattributed always low); `TestRiskB1_UnattributedNeverInSummary` |
| 2 | `TestRiskB2_*` (passive DNS takeover with `takeover`/`sensitive-paths` not-configured; HTTP fingerprint match and non-match, check keys carry `fp=`; missing S3 bucket and dangling Azure account each give one finding with both kinds of evidence; script vs link-only references), `findings.TestTakeoverDNS`, `TestMissingBucketReferences`, `provider.TestEntryHash`, `TestRiskDerivationKeepsFirstSeen` |
| 3 | `TestRiskB3_*` (CNAME, script and redirect references; 1000+ and five keys; 403; region redirect; Azure account by DNS then the 12 fixed containers, with the account host recorded as a candidate; a new object adds one HEAD, no re-list, no stale `public`), `cloudstorage.TestParseRef`, `TestRiskD8_*` |
| 4 | `TestRiskB4_*` (cap per root and per org in priority order on all three providers, under `--passive`; a wider cap adds exactly the new checks; unattributed vs attributed), `cloudstorage.TestGuess*` |
| 5 | `TestRiskB5_*` (once per service, zero on re-run, retried after a transient failure, again after `--redo`; SaaS by CNAME and by range skipped; CDN, PaaS and IP-literal services requested; no body stored; catch-all 200 not flagged; magic entry; invalid entries exit 2; a hit needs a current, visible service), `config.TestSensitivePath*` |
| 6 | `TestRiskB6_*` (SPF `+all`/`?all`/missing/several/over 10/loop/missing include, null MX, no MX, `p=none`, subdomain root with `sp=`, SERVFAIL on `_dmarc` retried, SERVFAIL on a selector or include not fatal), `findings.TestEmailFindings`, `egress.TestResolverMX` |
| 7 | `TestRiskB7_*`, `findings.TestRiskyPorts` |
| 8 | `TestRiskB8_Certificates` (clock advance, zero new requests, `--cert-expiry-days`), `findings.TestCertificates` |
| Plumbing | `output.TestRiskFiles`/`TestStorageUnattributedFile`/`TestDefaultRegistry`, `TestRiskPlumbing_*` (files written, sorted, CSV-safe, dated; found line once across an interrupt and resume; help shows settings and table), `TestRiskD4_StageRegistry`, the unchanged boundary test |

Existing tests updated: stage order (`TestPortsD1`), the sensitive-path format (`config.TestValidation`), help text (`TestHelp`), the file registry. The shared CLI worlds leave the four new stages out unless a test asks (`newRisk`), because `sensitive-paths` would add about 20 requests per service to every existing request-count assertion; the storage sources are always faked, answering "no such bucket".

## Deviations from the plan

- **Not-current findings carry no attributes** (the store merges attributes only from current observations), so `risk-*.csv` rows for a fixed finding show only what its key identifies (category, type, target and the columns derived from them); severity, detail and the rest are blank. Category is read from the key, not an attribute.
- **`email_posture` has an extra `spf_error` attribute** (why SPF is invalid), alongside the attributes D12 lists; an include loop, an unresolvable or failing include and several records all set it.
- **Sensitive-hit records are keyed `<service>|<path>|<hash>`** (the hash added so an edited entry's hit does not merge with the old one). Their `type` in a finding is the path, so the key is `sensitive-paths|<path>|<url>`.
- **Link-only missing buckets have the type `storage-missing-link`** so the severity table distinguishes them from `storage-missing`.
- **Object HEADs are made only for buckets known to exist**, not for every referenced object.
- **`storage-unattributed.csv` lists every existing, unattributed name that some root or organisation input would guess**, computed on read (`generated_from` is derived from the current inputs and cap, not stored in the record).
- **Provider data:** the Squarespace/Wix ASNs and Squarespace ranges, and every body fingerprint, come from published documentation and memory; they were not confirmed against live services in this environment (the spec says "confirmed in development").
- The README is not updated: it still describes the Python tool and is Spec 6's job. The severity table is in `--help`.

# Out of Scope

- NS and MX delegation takeovers; certificate hostname-mismatch and unknown-authority findings; bucket write or ACL probing; exploitation of any kind.
- Automatic refresh of evidence. Use `--redo email|storage|takeover|sensitive-paths|httpprobe`. A certificate renewed after its probe stays "expired" until `--redo httpprobe`.
- Known limitations:
  - Fingerprints and SaaS ranges change only with the binary.
  - Lowering `storage.max_names` does not remove names already checked.
  - Certificate findings are per service, so a certificate shared by N services gives N findings.
  - Not addressed in this implementation:
    - "Editing one fingerprint re-checks only the services it matches" is pinned by the per-entry hash (`provider.TestEntryHash`) and the `fp=` check keys, but there is no end-to-end test: `provider.Default()` is not injectable into a CLI run.
    - Fingerprints, ASNs and ranges are unverified against live data (see Deviations).
    - A finding no longer derived keeps only its key-identified columns in `risk-*.csv`; its severity and detail are not retained.
    - `Guess` uses the same word list for roots and organisations; there is no way to configure the words.
    - An S3 listing that answers neither 200, 301/307, 403 nor a 404 `NoSuchBucket` (for example a 400 for an unusual name) is a transient failure retried on every run.
    - Derivation re-derives every finding after each stage that did work, though it re-reads only the evidence kinds whose store version changed.
    - `TestWebB3_AllAttributes` and `TestWebB3_ExpiredAndSelfSignedCertificatesAreRecorded` fail on this Go toolchain independently of Spec 5.

# Verification

**Result:** the goal and all eight behaviours are met. Every behaviour has integration tests through `cli.Execute` plus unit tests in `findings` and `cloudstorage`. `go vet` is clean, and the suite passes except `TestWebB3_AllAttributes` and `TestWebB3_ExpiredAndSelfSignedCertificatesAreRecorded`, which fail the same way on a clean `HEAD` checkout (the macOS x509 verifier), so Spec 5 did not cause them.

| B | Verdict |
|---|---------|
| 1 | Met. One fixed severity table, shown in `--help`. Unattributed storage is always low, and the summary lists only current high and medium findings. |
| 2 | Met (one fix below). DNS evidence is derived with no queries, so it works under `--passive`. HTTP fingerprints come from the Target `takeover` stage. All evidence for a host forms one finding. |
| 3 | Met (one fix below). CNAME, crawl and redirect references are attributed. Listing records the count (`1000+` when truncated) and the first 5 keys. `public` comes from one HEAD request, and object contents are never fetched. |
| 4 | Met. Guessed names are capped per root and per org, in priority order, on all three providers, under `--passive`. They appear only in storage-unattributed.csv, and only public or listable ones become (low) findings. |
| 5 | Met. Each path is requested once per current, visible, non-SaaS service, and again only after a transient failure or `--redo`. A hit needs its signature or magic, and bodies are not stored. |
| 6 | Met. MX, SPF (RFC 7208 lookup count, loop detection), DMARC with org `sp=`, and DKIM selectors are read. A DKIM selector or include failure does not fail the check. |
| 7 | Met. Risky ports are medium and filtered by `PortVisible`. A later exclusion makes the finding not-current. |
| 8 | Met. Expired, expiring and self-signed certificates are flagged. The clock moves findings with no new requests, and `--cert-expiry-days` sets the window. |

**Corrected during verification**
- **Findings were derived only once per pass,** in `render()`, not after every stage that did work (D1; the Develop section said otherwise). Findings from the email, storage and takeover stages would wait for the hours-long port sweep. `passes()` now calls `deriveFindings` after each stage that executed checks. New test: `TestRiskD1_DerivedAfterEachStage`.
- **False takeover from a missing Azure container:** a missing container in an *existing* account was treated as takeover evidence, giving a high `storage-missing` finding. Only the account owner can create that container, so only a missing account is claimable now. New test: `findings.TestMissingAzureContainerIsNotTakeover`.
- **Zoned Azure static-website hosts were not recognised:** `ParseRef` did not accept `<acct>.z<n>.web.core.windows.net`, the form Azure actually issues, so references to those hosts were dropped. A `cloudstorage.TestParseRef` case now covers it.

**Corrected after code review (2026-11-05)**
- **Superseded evidence stayed current:** the `takeover`, `sensitive-paths` and `email` check keys carry a hash, but an edited entry left the old check's observation in place, so a fixed fingerprint or tightened signature kept its finding, and old email attributes could overwrite new ones. These stages implement `run.Retiring`: after a pass that enumerated cleanly, the runner retires (`Store.Retire`) completed checks the stage no longer yields, with their observations. Tests: `store.TestRetireUnlistedChecks`, `TestRiskB5_EditedEntrySupersedesOldHit`.
- **A transient DNS failure on an SPF include was a permanent `spf-invalid`.** It now fails the check, which is retried. Test: `TestRiskB6_IncludeServfailIsTransient`.
- **`+all` was hidden behind `spf-invalid`.** The record's own `all` is now reported even when the SPF is invalid.
- **Path-style provider endpoints recorded as candidates** (by a redirect) blocked every S3 or GCS check. All of the storage stage's sources are now candidate-exempt. Test: `TestRiskB3_PathStyleEndpointCandidateIsContacted`.
- **Azure 404 ResourceNotFound and 409 PublicAccessNotPermitted** were transient, so a real account's 12 containers retried on every run. They now complete with existence unknown. Test: `TestRiskB3_AzureUnknownContainersComplete`.
- **An S3 307 with only `Location`** was an error. The region now also comes from `Location` or `<Endpoint>`. Test: `TestRiskB3_RegionFromLocation`.
- **Smaller fixes:** `redirect=` is not counted beside an `all`; revoked DKIM keys and non-DKIM records are not selectors; a sensitive hit larger than the 1 MiB cap reports its `Content-Length` (or `1048576+`); findings and storage attribution share one derivation, and derivation re-reads only changed kinds.

- The known limitations already listed under Out of Scope still apply. In particular, rows for fixed findings lose their severity and detail, and the fingerprints and ranges have not been checked against live services.
