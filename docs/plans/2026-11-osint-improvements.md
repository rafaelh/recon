# Plan: improving OSINT and reconnaissance coverage

Written 2026-11-10 against the stage registry in `internal/cli/cli.go`. Each numbered item is
sized to become one `/spec-define` spec. Everything proposed stays inside the passive boundary
described in `README.md`: third-party sources, DNS lookups, TCP handshakes and GET/HEAD to
in-scope hosts. Nothing here adds a new kind of contact with the target.

## Where the tool stands

Inputs are domains, organisations, ASNs and netblocks. Discovery comes from crt.sh, Wayback,
Common Crawl, VirusTotal and SecurityTrails (subdomains), Shodan `net:` search (hostnames on
in-scope netblocks), RIPEstat (ASN prefixes, org to ASN), WhoisXML reverse WHOIS, Team Cymru (IP
origin AS), and AWS and GCP published ranges. DNS does A, AAAA, CNAME and PTR, wildcard
detection, permutations off a 105-word list, and MX, SPF, DMARC and DKIM for the roots. Against
the target it probes HTTP (title, server, Wappalyzer technologies, TLS SANs and expiry), crawls,
requests a 23-entry sensitive-path list, does TCP handshakes with banner capture, and
fingerprints takeover pages. Findings cover takeover, cloud storage, sensitive paths, email
posture, risky ports and certificates.

The architecture makes most of what follows cheap. A new third-party source is a `fetch`
function on the existing `subdomains.Stage`, a new DNS record type is one constant in `egress`,
and a new finding is a pure function over evidence kinds. The gaps are in coverage and pivoting,
not in plumbing.

## Gaps, by what a tester would notice

1. **Too few free passive sources.** Four of the nine discovery sources need a key. A run with no
   keys sees crt.sh, two web archives and RIPEstat. Comparable tools pull from fifteen or more
   unkeyed sources.
2. **No reverse pivots from addresses.** An in-scope IP found by resolution is never asked "what
   else lives here". Shodan is only used for netblock inputs, not for resolved addresses.
3. **Shallow DNS.** No NS, SOA, TXT, CAA or SRV. Root TXT records alone reveal which SaaS
   platforms an organisation has verified ownership with, and NS and MX point at self-hosted
   infrastructure that other domains of the same organisation share.
4. **Weak organisation pivoting.** `--org` uses RIPEstat and crt.sh `O=` only. RDAP, which is
   free and structured, is not used for netblock or registrant lookups, so netblocks registered
   to the organisation outside RIPE's region are missed, and the owners of out-of-scope addresses
   are not fed back as candidate organisations.
5. **No passive port or service view.** Under `--passive` there is no port information at all,
   although Shodan (already keyed) answers for every in-scope address without any target contact.
6. **Origin exposure is not detected.** Hosts behind a CDN whose origin address is also directly
   reachable are the single most common high-value recon result and nothing looks for them.
7. **Recorded but unread web content.** `script[src]` URLs are recorded, never fetched, so the
   API hostnames and paths inside first-party JavaScript are missed. Response headers are
   fingerprinted for technology only; security posture (HSTS, CSP, cookie flags, directory
   listings) is not reported.
8. **Candidates are unranked.** `candidates.csv` has no confidence or evidence count, so the
   user cannot tell a candidate seen by four independent sources from a one-off crt.sh match.
9. **Small built-in lists.** 105 permutation words and 23 sensitive paths.
10. **Provider ranges cover AWS and GCP only.** Azure, Cloudflare, Fastly, DigitalOcean, Oracle
    and Linode publish ranges too, so hosts there are classified by ASN alone.

## Phase 1: breadth with no new contact (all passive, mostly unkeyed)

Highest value per hour. Every item is a `ThirdParty` stage or a DNS lookup, available under
`--passive`.

### 1.1 More unkeyed subdomain sources

Add `fetch` functions to `subdomains.New()` for sources that need no key and have stable JSON
APIs: AlienVault OTX passive DNS (`otx.alienvault.com/api/v1/indicators/domain/<d>/passive_dns`),
HackerTarget (`api.hackertarget.com/hostsearch/?q=<d>`, 50 queries/day unkeyed, so treat 429 and
the "API count exceeded" body as `ErrAbortStage`), urlscan.io search
(`urlscan.io/api/v1/search/?q=domain:<d>`), Anubis (`jldc.me/anubis/subdomains/<d>`), RapidDNS
(HTML, needs a tolerant parser; lowest priority) and Cert Spotter
(`api.certspotter.com/v1/issuances?domain=<d>&include_subdomains=true&expand=dns_names`, unkeyed
with a low rate limit, keyed otherwise). Each becomes its own stage name so `--redo` and
`not-configured` work per source. Behaviour to specify: a source that rate-limits aborts its own
stage only, and `subdomains.txt` is unchanged in shape.

### 1.2 Keyed sources that reuse keys the user already has

Shodan `dns/domain/<d>` (subdomains and their records) and Censys certificate search as an
optional keyed source. Also Chaos (ProjectDiscovery) as a new key `keys.chaos`. Keep the rule
that a key never appears in a flag or in output.

### 1.3 Root DNS records: NS, SOA, TXT, CAA

Add `TypeNS`, `TypeSOA`, `TypeCAA` and `TypeSRV` to `egress`. A new `ThirdParty` stage
`dnsroot` (one check per in-scope root, key includes the record-type list) stores a
`Resolution` row per record so `resolutions.csv` gains NS, SOA, TXT and CAA rows. From TXT, derive
on read a **SaaS verification inventory**: `google-site-verification`, `MS=`, `atlassian-domain-
verification`, `docusign`, `facebook-domain-verification`, `apple-domain-verification`,
`_github-challenge`, `stripe-verification` and the like, matched by a table in a pure package
(`provider` is the natural home). Output rows in `third-parties.csv` (one file for every third-party mechanism). SOA `rname` is recorded as an
administrative contact address for later pivoting (1.6).

### 1.4 Passive ports and hostnames per address via Shodan

A keyed `ThirdParty` stage `shodan-host`, one check per in-scope address (`host/<ip>`,
one credit each, capped by a setting). It stores `OpenPort` observations with a `source` attribute
(`shodan`) and `IPHostname` rows, so `open-ports.csv` and `risk-ports.csv` are populated under
`--passive`. The ports stage must distinguish its own handshake-confirmed rows from Shodan's so
that a port Shodan saw last month but which is now closed is marked not current when the active
check runs. Decide in the spec whether a Shodan-only risky port is a finding or a lower-severity
"reported by third party" finding.

### 1.5 More provider ranges

Extend `providerranges` with Cloudflare (`www.cloudflare.com/ips-v4` and `-v6`), Fastly
(`api.fastly.com/public-ip-list`), DigitalOcean (`digitalocean.com/geo/google.csv`), Oracle
(`docs.oracle.com/iaas/tools/public_ip_ranges.json`) and Linode (`geoip.linode.com`). Azure's
weekly JSON sits behind a dated download URL; use the Service Tags discovery page only if a stable
link exists, otherwise skip Azure and say so in the README. Each range feeds the existing
`provider.DB` classification so `ips.csv` and takeover logic improve for free.

### 1.6 Larger built-in lists

Replace the 105-word permutation list with a curated 2,000 to 5,000 word list (the common
subdomain names from public wordlists, deduplicated and lowercased) and widen the sensitive-path
list to roughly 150 entries with their signatures. Both are already hashed into check keys, so
the first run after upgrading repeats the permutation checks once (the wordlist hash is part of each check); sensitive-path checks are per entry so only new entries run. Add a `permutations.max_names` guard so a
large list times a large seed set cannot explode.

## Phase 2: pivoting to find what the organisation owns

These turn single facts into related assets. Most results are candidates, which scope records but
never contacts.

### 2.1 RDAP for netblocks and registrants

A `ThirdParty` stage `rdap` using the IANA bootstrap (`data.iana.org/rdap/ipv4.json`) to reach
the right registry, then `ip/<addr>` for each in-scope address outside the input netblocks and
`entity`/`ips?name=` searches for each `--org`. Store the registering organisation name and the
registered netblock. A netblock registered to an input organisation becomes an in-scope netblock
candidate; an organisation name seen on three or more in-scope addresses becomes a candidate
organisation. This fills the non-RIPE gap left by RIPEstat and replaces Cymru's one-line holder
string with structured data.

### 2.2 Reverse lookups from in-scope addresses

For each in-scope address: HackerTarget `reverseiplookup` (unkeyed, rate-limited), Shodan
`host/<ip>` hostnames (shared with 1.4), and SecurityTrails `ips/nearby` when keyed. Hostnames
whose registrable domain is in scope are hostnames; the rest are candidate roots with
`source=reverse-ip`. Shared hosting and CDN addresses (`inventory.Shared`) are skipped, otherwise
every Cloudflare address yields thousands of unrelated names.

### 2.3 Shared infrastructure as a relatedness signal

Derived on read from 1.3 and the email stage: two roots that share a self-hosted NS or MX host
(not on a known provider) are related. For an in-scope root, every other root sharing its NS set
is a candidate. The reverse source is SecurityTrails `domain/<ns>/` lists when keyed, otherwise
only the roots already on record are compared.

### 2.4 Third parties from SPF and DMARC

Flatten SPF `include:` chains (bounded depth, already partly done for the email finding) and
record each included domain and each DMARC `rua`/`ruf` mailbox domain as a `ThirdPartyService`
record with the mechanism that revealed it. Output `third-parties.csv`. This is the mail half of
the SaaS inventory from 1.3.

### 2.5 Historical DNS and origin exposure

SecurityTrails `history/<host>/dns/a` (keyed) stores historical addresses with their date range.
Then a derived finding, **origin exposure**: an in-scope host whose current address is on a CDN or
WAF provider and which has a non-provider address (historical, or from another in-scope hostname's
A record, or from a TLS SAN match on a directly addressed service) that answers HTTP with the same
title or certificate. The confirmation step is a GET to an in-scope address, within the boundary.
Severity medium. This is the one item in the plan that most changes what a tester gets from a run.

### 2.6 Web identifiers as evidence

From probed and crawled pages record Google Analytics and Tag Manager IDs, Facebook pixel IDs,
favicon MurmurHash3 (Shodan's hash) and the copyright line. Store as `WebIdentifier` evidence.
With a Shodan key, `http.favicon.hash:<h>` and `http.html:"UA-xxxx"` searches pivot to candidate
hosts. Without one, the identifiers still appear in `web-services.csv` for manual pivoting.

### 2.7 Code and paste search

GitHub code search (`keys.github`, `search/code?q="<root>"`) for each in-scope root, recording the
repository and path where the domain is mentioned. Hostnames found in the matched fragments are
hostname observations. No secrets detection: record where the domain appears, not what is near
it. Mark clearly in the README that this queries GitHub, not the target.

## Phase 3: depth on each in-scope service (Target contact, GET/HEAD only)

### 3.1 JavaScript endpoint extraction

A `Target` stage `jsparse`, one check per recorded same-host `script[src]` URL (key includes the
URL and a parser version). GET the script, extract absolute URLs, `//host/path` references,
quoted `/api/...` paths and hostnames matching in-scope roots. Paths become `URL` rows with
`source=javascript` (recorded, not requested; the crawl may request them within its existing
depth and page limits). Hostnames are hostname observations. Bound the body size to the existing
10 MiB limit and the count per service with a setting.

### 3.2 Web posture evidence and low-severity findings

From responses the probe already has: missing HSTS on HTTPS, cookies without `Secure` or
`HttpOnly`, `Index of /` directory listings, `Server` and `X-Powered-By` disclosing versions, and
`X-Frame-Options`/CSP absence. Store `WebPosture` evidence, derive low findings, write
`risk-web-posture.csv`. Keep the list short and the signatures exact; this is not a scanner.

### 3.3 End-of-life software

The probe already captures `Nginx:1.25.3`-style versions. Embed a small table of product
end-of-life dates (from endoflife.date's published JSON, vendored into `builtin/`), derive a
medium finding for a version past its end-of-life date, using the fixed engagement date so tests
are stable. Extend to SSH, FTP and SMTP banners from the ports stage.

### 3.4 TLS detail

Record the negotiated protocol version and cipher from the probe's handshake (no extra
connections), plus self-signed and hostname-mismatch states already in `TLSError`. Derive low
findings for TLS 1.0/1.1 and mismatched certificates. Certificate issuer and SAN count go to
`web-services.csv`.

### 3.5 Service records

`SRV` lookups for a fixed list on each root (`_sip._tls`, `_sipfederationtls._tcp`,
`_autodiscover._tcp`, `_ldap._tcp`, `_kerberos._tcp`, `_xmpp-server._tcp`, `_caldav._tcp`,
`_minecraft._tcp`), recording targets as hostnames and ports as port eligibility hints. Also the
well-known hostnames `autodiscover`, `lyncdiscover`, `enterpriseenrollment`,
`enterpriseregistration` and `_mta-sts` as fixed permutation entries. Cheap and often finds
mail and identity infrastructure the wordlist misses.

## Phase 4: making results usable

### 4.1 Ranked candidates

Add `evidence_count`, `sources` and a derived `confidence` (low, medium, high by number of
independent sources and signal strength: a registrant match outranks a crt.sh `O=` match) to
`candidates.csv`. Console summary lists the high-confidence candidates with the input flag to
promote each.

### 4.2 What changed

A `changes.csv` listing records first seen or marked not current in this run, and a console
"new since last run" block. The data exists (`first_seen`, `last_seen`, `current`); this is an
output and report change only.

### 4.3 Whole-engagement export

`recon export -e <name> --format json` writing every current record with kind and attributes,
for feeding other tooling. Keeps the CSV columns free to change as the README promises.

## Suggested order and effort

| Item | Effort | Needs key | New contact | Value |
|---|---|---|---|---|
| 1.1 unkeyed sources | S each | no | none | high |
| 1.3 root DNS + SaaS inventory | M | no | DNS only | high |
| 1.4 Shodan per address | S | shodan | none | high under `--passive` |
| 1.5 provider ranges | S | no | none | medium |
| 1.6 larger lists | S | no | DNS, existing paths | medium |
| 2.5 historical DNS + origin exposure | L | securitytrails for history | GET to in-scope addr | very high |
| 2.1 RDAP | M | no | none | high for `--org` |
| 2.4 SPF/DMARC third parties | S | no | none | medium |
| 2.2 reverse IP | M | optional | none | medium |
| 3.1 JS endpoints | M | no | GET same-host scripts | high |
| 3.2 web posture | M | no | none (existing responses) | medium |
| 2.6 web identifiers | M | shodan for pivot | none | medium |
| 3.3 EOL versions | M | no | none | medium |
| 4.1 ranked candidates | S | no | none | medium |
| 2.3 shared NS/MX | M | optional | none | low-medium |
| 2.7 GitHub | M | github | none | medium |
| 3.4 TLS detail | S | no | none | low |
| 3.5 SRV | S | no | DNS only | low-medium |
| 4.2 changes, 4.3 export | S, M | no | none | medium |

Do 1.1, 1.3, 1.4 and 1.5 first: a week of work that roughly doubles passive coverage. Then 2.5,
which is the most valuable single finding. Then 3.1 and 2.1.

## Cross-cutting work the phases depend on

- **egress record types:** `TypeNS`, `TypeSOA`, `TypeCAA`, `TypeSRV`, with `DNSResult.Answers`
  carrying the typed value as a string (`priority target` for SRV).
- **Source quota handling:** several unkeyed sources rate-limit by IP. `httpsrc.Get` already
  aborts a stage on 429 for keyed requests; extend that to unkeyed sources that document a quota,
  and surface "quota exhausted, retried next run" rather than a failed check.
- **Observation source attribution:** `OpenPort`, `IPHostname` and `Hostname` need a `source`
  attribute where they do not have one, so third-party claims and confirmed observations can be
  told apart in outputs and findings. Attribute JSON names must stay stable once added.
- **Settings:** per-source caps (`shodan.max_hosts`, `jsparse.max_scripts`,
  `permutations.max_candidates`), all in `--help`, all validated as positive integers.
- **Tests:** each new source gets a loopback fake through `SourceBaseURLs`; each new DNS type a
  case in `egresstest`; each new finding a table test in `findings`. The harness canaries already
  catch any stage that contacts something it should not.
- **README:** the passive boundary section lists every third party by name. Keep it exact as
  sources are added, and list which items need which key.

## Deliberately out of scope

- Screenshots or any headless browser (needs an external tool, and the project ships one binary).
- Search-engine scraping (terms of service) and sources that need the user to prove domain
  ownership (Have I Been Pwned domain search).
- People-focused OSINT (employee names, email harvesting from Hunter.io or LinkedIn). Possible
  as a keyed source but raises privacy questions the tool has not taken a position on. Decide
  separately before specifying.
- Anything that sends data to the target beyond GET/HEAD: no `Origin` headers for CORS tests, no
  HTTP methods probing, no TLS downgrade probing with extra handshakes, no UDP.

## Open decisions to settle in `/spec-define`

1. Is a risky port reported only by Shodan a finding, a lower-severity finding, or inventory only?
2. Does origin exposure confirm by requesting the suspect address directly (one GET with the
   in-scope `Host` header), or report on evidence alone?
3. Do unkeyed rate-limited sources (HackerTarget) ship enabled by default, given 50 queries a day
   may be spent in one run?
4. Is `third-parties.csv` one file for SPF, DMARC, TXT verifications and CNAME SaaS, or several?
