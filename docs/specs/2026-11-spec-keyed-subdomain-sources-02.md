# Spec 2: keyed subdomain sources that reuse existing keys

## Goal

Users who already hold a Shodan key get its subdomain data, and users with Censys or Chaos
subscriptions can plug them in, through the same keyed-source rules as today, without any
third-party DNS claim ever deciding what recon contacts.

## Behaviours

1. A `shodan-dns` stage uses `keys.shodan` to fetch each in-scope input root's subdomains and
   their A, AAAA, CNAME, MX and NS records. It is on whenever the key is set; the README states
   that each root costs one Shodan query credit per result page. Names under the root are
   recorded as hostnames (Spec 1 behaviour 3). In-scope CNAME, MX and NS targets are recorded as
   hostnames too.
2. DNS records known only from Shodan are shown in `resolutions.csv`, which gains a `source`
   column (`resolve`, `shodan`, or `resolve;shodan` when both saw the record). They never decide
   which addresses are contacted, port-checked or probed; they do not make a name resolved; they
   do not feed wildcard, provider, takeover or exclusion results. Only `resolve`'s own answers do
   those things. A name `resolve` finds NXDOMAIN but Shodan lists appears in both
   `unresolved.txt` and `resolutions.csv` (source `shodan`). A test with the harness canaries pins
   that a Shodan-only address is never contacted.
3. A `censys` stage uses `keys.censys` (a Censys personal access token) to search certificates
   whose names fall under each in-scope input root, recording the names under the root as
   hostnames (Spec 1 behaviour 3).
4. A `chaos` stage uses `keys.chaos` to fetch each in-scope input root's subdomain list; labels
   are joined to the root and normalised. A 404 or an empty list is an empty result.
5. Each stage is `not-configured (no key)` when its key is absent. A 401, 403 or 429 stops that
   stage for this run as for other keyed sources. No key, no part of a key and no encoding of a key
   appears in any output, event, file or warning.
6. Each stage follows result pages up to `<stage>.max_pages` (default 10). The cap is part of the
   check, so raising it repeats the checks; reaching it completes the check with a `--verbose`
   warning that the result was truncated. The existing sources' fixed page limits are unchanged.
7. The README's keyed-sources list adds `censys` and `chaos`; `--help` lists the stages.

# Design

**Status:** ready to build (wave 2). **Depends on:** Spec 1 (`ErrQuota`, `Warnf`, `CleanName`,
`KeyPrefix`, the `maxPages` field of `subdomains.Stage`); re-check those names once it has merged.
**Owns for Spec 7:** the `dns_claim` kind and the `source` column of `resolutions.csv`.

## Decisions

- **`censys` and `chaos` are fetchers on `subdomains.Stage`** (keyed), in a new file
  `sources_keyed.go`. Chaos: `GET https://dns.projectdiscovery.io/dns/<root>/subdomains` with the
  key as the `Authorization` header; labels are joined to the root; a 404 or empty list is empty.
  Censys: the Platform API's certificate search with the personal access token as
  `Authorization: Bearer`, query on certificate names under the root, following the cursor.
- **Page caps**: `shodan_dns.max_pages`, `censys.max_pages` and `chaos.max_pages` (default 10,
  minimum 1) are in the check key (`<root>|pages=<n>`). Chaos currently answers with the whole
  list in one response, so its cap has no effect today; it exists because behaviour 6 asks for it
  on every stage and the README says it is not reached.
- **`shodan-dns` is its own stage** in `internal/stages/shodan/dns.go`, because it records more
  than names. It reads `GET /dns/domain/<root>?page=<n>` with the existing `key` parameter.
- **A third party's DNS records are a different kind from recon's own.** They are stored as
  `dns_claim` (key `name|TYPE|value`, attributes `name`, `type`, `value`, `source`), never as
  `resolution`. The inventory, scope and egress policy do not read `dns_claim`, so by construction
  a Shodan record cannot resolve a name, make an address eligible, or feed wildcard, provider,
  takeover or exclusion logic. The stage records no `ip` observation, so a Shodan-only address is
  not in `ips.csv` and no stage can enumerate it.
- **`resolutions.csv` merges the two kinds by key** and adds `source`: `resolve` when recon's own
  lookup holds the record (any DNS stage), `shodan` for a claim alone, `resolve;shodan` for both.
  Dates and `current` come from recon's record when there is one.
- **Hostnames**: names under the root, and CNAME, MX and NS targets that are in scope (the check
  input carries the scope), are `hostname` observations after `httpsrc.CleanName`.

## Changes

- `internal/stages/subdomains/sources_keyed.go`; two lines in `subdomains.New()`.
- `internal/stages/shodan/dns.go`; registered after `shodan`.
- `internal/kinds/dnsclaim.go`. `internal/output/output.go`: `resolutionRows` merge and column.
- `internal/config/config.go`: the three `max_pages` settings.
- `README.md`: keyed sources, the credit cost per page, `--help` stage list.

## Tests

`internal/cli/sources_keyed_test.go`:

- Each stage is `not-configured (no key)` without its key; 401, 403 and 429 stop only that stage;
  the key value appears in no event, file or warning.
- Chaos 404 and empty list complete with nothing; Censys and Shodan page caps complete with a
  truncation warning and raising the cap repeats the checks.
- A record only Shodan holds appears in `resolutions.csv` with source `shodan`; one both hold
  shows `resolve;shodan`; a name `resolve` finds NXDOMAIN is in both `unresolved.txt` and
  `resolutions.csv`.
- **Canary test:** a Shodan-only address is never dialled, is not in `ips.csv`, is not
  port-checked or probed, and does not make its name resolved or wildcard-tested.
- In-scope CNAME, MX and NS targets become hostnames; out-of-scope ones do not become candidates.

## To verify while building

The current Censys Platform search endpoint, query field and paging shape; whether a free token
has search access (a 403 is handled as a stopped stage either way).

## Out of scope

Shodan DNS records as inputs to any decision; Censys host data.

# Implementation

## Develop

- **Subdomain stages**: `censys` and `chaos` are fetchers in `sources_keyed.go`, registered after
  `certspotter`. Both use `pageCap`, so the check key is `<root>|pages=<n>` and raising the cap repeats
  the checks. Censys is a `POST /v3/global/search/query` with `Authorization: Bearer <token>` (through
  `KeyPrefix`), body `{"query": "cert.names: \"<root>\"", "page_size": 100, "page_token": …}`, names read
  from `result.hits[].certificate_v1.resource.names` and paged by `result.next_page_token`. Chaos is a
  `GET /dns/<root>/subdomains` with the raw key in `Authorization`, labels joined to the root by
  `httpsrc.JoinLabels` (the bare `*` and empty labels are the root, so dropped); a 404 is empty.
  A truncation warning is given only when the source reports more pages at the cap, not whenever
  the cap is reached (Cert Spotter's rule), because both sources say whether there are more.
- **`shodan-dns`** (`internal/stages/shodan/dns.go`, after `shodan`): reads `GET /dns/domain/<root>?page=<n>`
  with the `key` parameter, follows `more` up to `shodan_dns.max_pages`, and records names from `subdomains`
  and `data` as hostnames. For A, AAAA, CNAME, MX and NS `data` entries it stores a `dns_claim`
  (`internal/kinds/dnsclaim.go`); no `ip` or `resolution` is written. In-scope CNAME, MX and NS
  targets are hostnames too; the scope is carried in the check input. A 404 is empty.
- **Output**: `resolutionRows` merges `resolution` and `dns_claim` records by key and adds `source`.
- **Config**: `shodan_dns.max_pages`, `censys.max_pages`, `chaos.max_pages` (minimum 1), flags
  `--shodan-dns-max-pages`, `--censys-max-pages`, `--chaos-max-pages`, through one `config.PagedSource` type.
- **README** lists the keyed sources, the credit cost and the `source` column.
- **Tests** (all in `internal/cli/sources_keyed_test.go`): 1 `TestShodanDNS_TargetsBecomeHostnamesOnlyInScope`,
  `TestKeyed_NamesAreRecordedAndKeySent`; 2 `TestShodanDNS_RecordsAreShownWithTheirSource`,
  `TestShodanDNS_ClaimedAddressIsNeverContacted` (the canary test: a listener on the Shodan-only address
  that must see no connection, with the real ports and web stages); 3 and 4 `TestKeyed_NamesAreRecordedAndKeySent`,
  `TestKeyed_RequestShapes`, `TestKeyed_ChaosNothingForTheRoot`; 5 `TestKeyed_NotConfiguredWithoutKey`,
  `TestKeyed_RejectionStopsOnlyThatStage`, `TestKeyed_WrongShapeIsAnError` (the key and its URL-escaped, base64
  and `Bearer` forms appear in no file or output); 6 `TestKeyed_PageCap`, `TestKeyed_PageCapNotReached`,
  `TestKeyed_ChaosCapIsInTheCheck`, `TestKeyed_MaxPagesMustBePositive`; 7 `TestKeyed_RegistryOrderAndHelp`,
  `TestKeyed_ReadmeNamesTheSources`. `world_test.go` lists the two new hosts, and the
  `resolutions.csv` header in `TestPlumbing_FilesAndCounts` gained `source`.
- **Mutation checks**: `## Tests` marks no behaviour for one, so these were chosen for the passive
  boundary and the caps. Each was broken by hand, caught, and undone: `shodan-dns` also writing an `ip`
  record (`TestShodanDNS_RecordsAreShownWithTheirSource` and `…ClaimedAddressIsNeverContacted` failed);
  a claim stored as a `resolution` (those two and `…TargetsBecomeHostnamesOnlyInScope` failed); the
  in-scope guard on CNAME, MX and NS targets removed (`…TargetsBecomeHostnamesOnlyInScope` failed); the page
  cap off by one (`TestKeyed_PageCap` failed).
- **External facts** (read from the services' documentation; no live request was made with a key):
  - Chaos answers `{"domain", "subdomains": [labels relative to the root], "count"}` and takes the raw key in
    `Authorization`. Its docs show no 404 or empty example; both are treated as empty.
  - Censys's global search takes a personal access token as a Bearer token. The organisation id is optional
    (`organization_id` query parameter or `X-Organization-ID` header) and is not sent; the stage does not
    support organisation-scoped tokens.

## Known limitations

- Behaviour 3: the query field and form (`cert.names: "<root>"`) were not confirmed against the live API: the
  docs reached do not show a certificate query, and an exact-name match would miss subdomain certificates.
  The empty form of `next_page_token` at the last page is also unconfirmed; an empty string, null or an absent
  field all end the paging. Whether a free token has search access is unknown (a 403 stops the stage).
- Behaviour 2: a wildcard record (`*` or `*.x` subdomain) is not stored as a claim; its name is dropped.
  Only A, AAAA, CNAME, MX and NS are kept, as Spec 1's wording lists them.
- Behaviour 1: a Shodan 402 (no query credits) is an ordinary failed check, not a stopped stage, so each
  remaining root is still tried.
- Behaviour 2: a claim and a resolution with the same key merge, but the claim's own dates are not shown
  when recon holds the record.

## Simplify

Fixed: `config.Certspotter` replaced by `PagedSource` (one type for all four caps) with one raw type for
the settings; `resolutionRows` no longer sorts (the renderer does); `input.IPLiteral` for A and AAAA values
(a zoned address is dropped); SecurityTrails joins labels with `httpsrc.JoinLabels`; Censys hit parsing
without a pointer; the README bullet parser, `resolveAll` and the default check key shared in the tests.
Skipped: a shared in-scope-roots helper for the three `Checks` loops, a shared paging helper, and
dropping `dnsObs`'s duplicate filter (each is a wider refactor, or matches the other stages' style); folding
a per-source setting table into config.

# Verification

## Result

Checked against the goal, B1–B7 and `## Out of scope` by reading every changed file. `make test`
passes. The goal is met. The three stages are `ThirdParty` stages that are `not-configured` without
their key. A Shodan DNS record is stored only as `dns_claim`, and the scope, the inventory, the egress
policy, the wildcard and takeover stages, and the findings read only `resolution` and `ip`. So a
third party's claim cannot decide what recon contacts. To confirm the canary test is meaningful, I
stored A claims as `resolution` records by hand: `TestShodanDNS_ClaimedAddressIsNeverContacted`
failed, showing the address dialled four times, put in `ips.csv` and its name probed. I then undid
the change.

- **B1 mostly met.** `shodan-dns` reads `/dns/domain/<root>?page=<n>` with `keys.shodan`. Names from
  `subdomains` and `data` become hostnames, and so do in-scope CNAME, MX and NS targets (an MX
  preference is stripped). The README states the cost of one query credit per page per root. Gaps:
  a record on a wildcard name (`*`, `*.x`) is dropped, not shown. The scope used for the CNAME, MX and
  NS targets is the one in force when the check ran, so a target that later becomes in scope (a root
  added afterwards) becomes a hostname only if the check runs again.
- **B2 met.** `resolutions.csv` has a `source` column in the order the build plan gives. It merges
  by the `name|TYPE|value` key, which `resolve` also uses (IPv6 values are canonicalised the same
  way), and shows `resolve`, `shodan` or `resolve;shodan`. Dates and `current` come from recon's own
  record when there is one. A name that returns NXDOMAIN is in both `unresolved.txt` and
  `resolutions.csv`. The canary test runs the real web and ports stages, and a listener on the
  Shodan-only address receives no connection.
- **B3 met as far as can be checked offline.** The request is `POST /v3/global/search/query` with a
  Bearer personal access token, and names are read from `result.hits[].certificate_v1.resource.names`.
  I checked this against the Censys docs (docs.censys.com/docs/censys-query-language and the
  `v3-globaldata-search-query` reference). The `## Known limitations` worry that
  `cert.names: "<root>"` is an exact match does not fit the docs. CenQL's `:` is a tokenised match,
  and `cert.names` uses a "subdomain analyzer" that indexes `a.example.com` under `example.com` too, so
  the query should find subdomain certificates. The docs give no example of this exact query, do not
  say what `next_page_token` looks like on the last page, and do not say whether a free token may
  search. A live request is still needed (Follow-ups).
- **B4 met.** Chaos sends the raw key in `Authorization`. Labels are joined to the root and pass
  through `CleanName`. A 404 or an empty list completes with no names and no warning.
- **B5 met.** Each stage reports `not-configured (no key)`. A 401, 403 or 429 aborts only that stage
  (`httpsrc.Get`). The key and its URL-escaped, base64 and `Bearer` forms appear in no file or
  output, and egress scrubs keys from transport errors. A Shodan 402 (no credits left) is an
  ordinary failed check, which B5 allows because it names only 401, 403 and 429.
- **B6 met.** `shodan_dns.max_pages`, `censys.max_pages` and `chaos.max_pages` default to 10 with a
  minimum of 1 and are in the check key, so raising one repeats the checks. Reaching a cap while the
  source still reports more pages completes the check with a `--verbose` "truncated" warning. A
  result that ends exactly at the cap gives no warning, because nothing was cut off. The fixed limits
  of the existing sources (`maxPages = 30`, Cert Spotter's) are unchanged. Chaos's cap is in the check
  but can never be reached.
- **B7 met.** The README's keyed-sources bullet names `censys` and `chaos` and explains `shodan-dns`.
  `--help` lists the three stages and their `--*-max-pages` flags. The registry order matches the
  build plan.

I made no corrections in this pass. `golangci-lint` could not run because the local build is v1.64.8,
built with Go 1.26, and the config targets Go 1.27.

# Follow-ups

- Decide whether `chaos.max_pages` should exist: Chaos answers in one response, so raising it repeats
  checks for the same result. It is kept because behaviour 6 asks for a cap on every stage.
- Decide whether a claim's `source` should come from `Record.Stages` instead of an attribute: a second
  claim source reporting the same record would overwrite the first's `source` attribute.
- Three paged sources now hand-roll the cap and the truncation warning, with two truncation rules
  (Cert Spotter warns whenever the cap is reached, the others only when more is reported); a shared
  helper in `httpsrc` would unify them.

- Make one request with a real Censys token and a real Chaos key, and correct the Censys query and the
  Chaos no-data answer if they differ from the above.
- The `shodan-dns` check key does not carry the scope, though the scope decides which CNAME, MX and NS
  targets become hostnames: a root added later does not repeat a completed check, so a target that has
  since come into scope is not recorded from Shodan until `--redo shodan-dns`. Putting the scope in the key
  would spend a query credit per page on every scope change; decide which is wanted.
- A claim that is no longer current still adds `;shodan` to the `source` of a current `resolve` row;
  decide whether only current claims should count.
- Spec 7 reads `dns_claim` and the `source` column; both are in place.
