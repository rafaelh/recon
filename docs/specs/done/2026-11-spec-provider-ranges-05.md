# Spec 5: more published provider address ranges

## Goal

`ips.csv` names the provider and, where published, the service or region for addresses on
Cloudflare, Fastly, DigitalOcean, Oracle Cloud and Linode even when the owner lookup fails, and
DigitalOcean addresses are classified as the customer's own machines rather than wholesale as
shared hosting.

## Behaviours

1. The `providerranges` stage fetches the published range lists of Cloudflare (IPv4 and IPv6, two
   checks), Fastly, DigitalOcean, Oracle Cloud and Linode in addition to AWS and GCP. Each list is
   its own check, fetched once per engagement and refreshed only by `--redo providerranges`. On an
   existing engagement the new lists are fetched and AWS and GCP are not re-fetched.
2. A published range takes precedence over the ASN classification; a CNAME into a known provider
   still makes a host shared. Cloudflare and Fastly addresses are shared infrastructure and are
   not port-checked. DigitalOcean and Linode addresses are dedicated and port-eligible, which for
   DigitalOcean is a change from today and means the next active run may handshake addresses it
   previously skipped; the README notes this. Oracle ranges tagged as object storage or Oracle
   services are shared; the rest are dedicated. Which hosts are requested for sensitive paths is
   unchanged. An address covered by two lists shows both providers `;`-joined.
3. Azure is not fetched. The README's list of range publishers names the seven providers and says
   Azure is classified by ASN only because Microsoft publishes its ranges at a changing URL.
4. A list that fails to download, or downloads but yields no ranges, is a failed check: the
   previously fetched ranges still apply and the usual `--verbose` failed-check warning names the
   provider. Nothing is reported as a finding because of a missing list.
5. The README passive-boundary section names every range publisher contacted.

# Design

**Status:** ready to build (wave 1). **Depends on:** nothing. **Used by:** Spec 7 (Cloudflare and
Fastly addresses are recognised as CDN).

## Decisions

- **One check per list, keyed by a stable name**: `aws` and `gcp` unchanged (so they are not
  re-fetched), plus `cloudflare-v4`, `cloudflare-v6`, `fastly`, `digitalocean`, `oracle`, `linode`.
  The stage becomes a table of `{key, url, parse}`; each parser is a small pure function over the
  body.
- **An empty parse is an error**, so the check fails, is retried, and the ranges of the last
  successful fetch keep applying (their observations are untouched).
- **Classification stays in `provider.Classify`** and becomes a per-provider rule table instead of
  a switch: Cloudflare and Fastly are shared with class `cdn`; DigitalOcean and Linode are known
  and dedicated; Oracle is shared when the range's tag is `OSN` or `OBJECT_STORAGE`, dedicated
  otherwise; AWS and GCP keep today's rules. `Result.Class` gains `cdn` beside `saas`.
- **Ranges before ASN** is already the order in `Classify`; the DigitalOcean ASN entry stays as
  the fallback when the list is missing. A CNAME into a provider still wins in the inventory.
- **Two lists covering one address**: each provider first settles its own lists by its own rule
  (so an EC2 range still wins over the AMAZON superset that also covers it); then, across
  providers, names are joined with `;` in name order and the address is shared if any provider's
  result is shared (fail closed).
- **The class is passed through for every class**, not only `saas`: today `Classify` drops `cdn`
  from ASN entries, so the CDN ASNs already in `providers.yaml` (Akamai among them) never reach a
  caller. Spec 7 needs them.
- **URLs** (verify each still answers 200 without a redirect before merging, since the
  third-party client does not follow redirects): `https://www.cloudflare.com/ips-v4` and
  `/ips-v6`, `https://api.fastly.com/public-ip-list`,
  `https://digitalocean.com/geo/google.csv`,
  `https://docs.oracle.com/iaas/tools/public_ip_ranges.json`, `https://geoip.linode.com/`.

## Changes

- `internal/stages/providerranges/providerranges.go`: the table, six parsers, `Sources()`.
- `internal/provider/provider.go`: rule table in `Classify`, `Result.Class` values, joined
  providers. `providers.yaml`: comment that DigitalOcean's ASN entry is the fallback.
- `README.md`: the seven publishers in the passive-boundary section, the Azure note, and the note
  that DigitalOcean addresses may now be port-checked.

## Tests

- `internal/stages/providerranges`: each parser on a recorded sample, and on an empty and a
  malformed body.
- `internal/provider`: the classification table, including Oracle tags, two overlapping lists and
  range-over-ASN precedence; an EC2 address also inside AMAZON stays dedicated and
  port-eligible; a CDN ASN entry reports class `cdn`.
- `internal/cli/providerranges_test.go`: an existing engagement fetches only the six new lists; a
  failed list leaves earlier ranges in force and warns under `--verbose`; a DigitalOcean address
  of an in-scope hostname becomes `port_eligible` and is handshaken, a Cloudflare one is not;
  `ips.csv` shows provider and region when the owner lookup failed.

## Out of scope

Azure ranges; any change to which hosts sensitive paths are requested from.

# Implementation

## Develop

Built as designed, with these specifics:

- **Stage** (`providerranges.go`): a `lists` table of `{key, provider, url, parse}` in check order
  (`aws`, `gcp`, `cloudflare-v4`, `cloudflare-v6`, `fastly`, `digitalocean`, `oracle`, `linode`).
  `Checks`, `Run` and `Sources()` (the distinct hosts, so seven) all read the table. Five parsers
  cover the eight lists: AWS, GCP, Fastly and Oracle each have one, and Cloudflare, DigitalOcean and
  Linode share `parseLines` (one range a line, `#` lines skipped, region taken from the third comma
  field when there is one: the geofeed format of DigitalOcean and Linode). `list.observations` turns
  entries into `provider_range` observations and returns an error when none has a valid prefix, so an
  empty, HTML or truncated body is a failed check. Observation keys keep the existing
  `provider|prefix|service` form, which is why AWS and GCP are not re-fetched or re-recorded.
- **Oracle** gives one observation per tag, so a range tagged `OSN` and `OBJECT_STORAGE` is two
  records and each tag is a service of its own.
- **`provider.Classify`**: `rangeRules`, a per-provider table (`aws`, `gcp`, `cloudflare`, `fastly`,
  `digitalocean`, `linode`, `oracle`) whose rules fill in only `Shared`, `Service`, `Region` and
  `Class`; `wholeListRule(shared, class)` covers the five providers whose every range means the
  same. `classifyRanges` groups the covering ranges by provider, settles each group by its rule,
  then sets the rest, joining names (and services and regions) with `;` in name order, and is shared
  if any group is. A provider with no rule is ignored, as before, and `provider.HasRangeRule` lets
  the stage's tests check every list's provider has one. `Result` gained `Region` and `ClassCDN`
  (`"cdn"`). The class of an ASN or static-range entry is passed through whatever it is (`saas`,
  `cdn`, `hyperscaler`, `shared-hosting`). The Oracle rule picks the range to report by service
  then region.
- **`ips.csv`**: the spec's "service or region" is one cell. `IPRow.Service` is the service, falling
  back to the region when a provider publishes none (`inventory.IPRows`). No column was added: the
  build-order plan fixes `ips.csv`'s column order and has no region column. This also changes GCP
  rows, which show their scope (`europe-west1`) where the cell was empty.
- **README**: a paragraph in the passive-boundary section naming the seven publishers, the
  fetch-once and `--redo` behaviour, the failed-list rule and the Azure note; the `ips.csv` row
  says what a range does and that DigitalOcean addresses may now be port-checked.
- **`providers.yaml`**: the header's `asn:` description says a published range list takes
  precedence, so the ASN classes are the fallback when a list is missing, naming DigitalOcean. (The
  design asked for a comment on the DigitalOcean entry; the header was wrong for it, so the header
  carries the note instead.)

Deviations and facts that differed from `# Design`:

- **Two URLs redirect.** Checked 2026-11-14: `https://digitalocean.com/geo/google.csv` answers 301 to
  `https://www.digitalocean.com/geo/google.csv`, and `https://docs.oracle.com/iaas/tools/public_ip_ranges.json`
  answers 302 to `/en-us/iaas/tools/public_ip_ranges.json`. The third-party client does not follow
  redirects, so the stage uses the final URLs; both answer 200 with no redirect. Cloudflare (both
  files), Fastly and Linode answer 200 directly.
- Linode's list is a geofeed with `#` comment lines, not a bare prefix list. Some DigitalOcean lines
  have only two fields (`168.144.228.0/22,None`), so the region is empty there.
- The `testdata` samples are trimmed from the live files; Oracle's is compacted onto fewer lines but
  keeps the real structure and the three tag combinations (`OCI`, `OSN`, `OSN`+`OBJECT_STORAGE`).

Tests:

- `internal/stages/providerranges/providerranges_test.go` (behaviours 1, 3, 4): each new parser on
  its recorded sample; Oracle's tag handling; AWS and GCP unchanged; empty and malformed bodies for
  all eight lists (the error names the provider); unparseable lines skipped; one check per list;
  `Sources()` names the seven hosts and nothing for Azure.
- `internal/provider/ranges_test.go` (2): the rule table including Oracle tags, an OCI range inside
  an OSN one, Cloudflare over IPv6, range over ASN and the ASN fallback, two overlapping lists
  (joined, name order, fail closed, order of input irrelevant), EC2 inside AMAZON, every ASN class
  passed through (`cdn`, `saas`, `shared-hosting`, `hyperscaler`), and an unknown provider's range
  ignored. `providerranges_test.go` also checks every list's provider has a rule. `provider_test.go`'s expectations gained regions, `cdn` and
  `hyperscaler`, and its linear-scan oracle now classifies the covering ranges through an index of only
  those, because the hand-copied switch no longer described `Classify`.
- `internal/cli/providerranges_test.go` (1, 2, 4, 5): each list a check fetched once and refreshed
  only by `--redo`; an existing engagement fetches only the new lists; three failure shapes (500,
  empty, no ranges) keep the earlier ranges, warn naming `digitalocean` under `--verbose`, fail the
  check and produce no finding; DigitalOcean and Linode (with the owner lookup unanswered) are
  handshaken and Cloudflare and Fastly are not; DigitalOcean without its list stays shared by ASN;
  `ips.csv` provider, service or region and owner with the owner lookup failing; a CNAME into Heroku
  still makes a DigitalOcean-range address shared; the README names every publisher, Azure by ASN and
  the DigitalOcean port-check note.
- Existing tests changed: `world_test.go` serves the five new hosts; `discovery_test.go` expects the
  GCP region in `ips.csv`; `saas_test.go` expects a CDN ASN to report `cdn`;
  `TestGet_RangePublisher429StaysAFailedCheck` serves the new lists so it still isolates AWS's 429.
- Tests that pin existing behaviour and passed before the code: `TestProviderRanges_DigitalOceanWithoutItsListStaysShared`,
  `TestClassify_UnknownProviderRangeIsIgnored` and `TestClassifyIndexMatchesLinearScan`.
- Which hosts are requested for sensitive paths (behaviour 2) is untouched: nothing in
  `internal/stages/risk` reads the provider result, so no test was added for it.

Mutation checks: `## Tests` marks none, so none was required. Two were run by hand on the guards
the design leans on most, each undone by hand afterwards. Removing the empty-parse error in
`list.observations` (behaviour 4) fails `TestParsers_EmptyAndMalformedBodiesFail`; dropping `OSN`
from Oracle's shared tags (behaviour 2) fails `TestClassify_PublishedRangeRules` (two cases).

## Known limitations

- **Behaviour 2**: when two providers cover an address, `Service` and `Region` are the non-empty
  values joined in provider order, so a reader cannot tell which provider a lone value belongs to.
- **Behaviour 2**: `ips.csv` shows one of service or region, so an Oracle `OCI` range shows `OCI`
  and its region (`us-phoenix-1`) is recorded but not shown.
- **Behaviour 4**: a text list cut off at a line boundary parses as a shorter, valid list. JSON
  lists that are cut off fail to parse, and a body over the 10 MiB cap is already an error.

## Simplify

Four reviewers (efficiency, reuse, altitude, simplification) read the diff.

Fixed:

- `parseLines` uses `input.ParseList` instead of its own blank and comment skipping.
- `Result.Class` passes every class through (the design's wording), instead of an allowlist of
  `saas` and `cdn` that this build had added; the two ASN expectations in `TestClassify` gained
  `hyperscaler` and a test pins all four classes.
- Rules fill in only `Shared`, `Service`, `Region` and `Class`; `classifyRanges` sets `Known`,
  `Evidence` and the provider name. `sharedRule` and `dedicatedRule` became `wholeListRule`.
  `oracleRule` no longer clones or stable-sorts.
- `provider.HasRangeRule` and `TestLists_EveryProviderHasARule`: a list whose provider has no rule
  was silently ignored.
- `listByKey` replaces the duplicated lookup in `Run` and the test helper.
- `classifyRanges` returns early when no range covers the address, and `list.observations` formats
  each prefix once.
- The `providers.yaml` header no longer says shared-hosting is always shared.
- Tests: typed `ProviderRangeAttrs` decoding in the parser tests; `rangeHosts` from `Sources()`;
  `allRangeChecksBut`; `slices.ContainsFunc`; `ip()` in place of `netip.MustParseAddr`; a renamed
  shadowing variable; `TestReadme_NamesTheNewSources` uses the shared `readmeSection`.

Skipped:

- Sorting every provider's ranges in `classifyRanges` so all rules, not only Oracle's, are
  independent of record order: record order is already `ORDER BY key`, so it is deterministic, and
  the change would alter which AWS range is reported.
- Deriving `list.provider` from `list.key`: it would tie the provider name to how keys are spelt.
- Replacing `sourcePatterns` in `world_test.go` with the stage's `Sources()`: the list mirrors every
  other source's hand-written host.
- Moving the service-or-region merge out of `inventory.IPRows`, and a one-pass minimum in
  `oracleRule`: the reviewers found nothing to gain.

# Verification

## Result

Checked against the goal, behaviours 1 to 5 and `## Out of scope` by reading every changed file,
`CLAUDE.md` and `docs/plans/2026-11-build-order.md` (the spec has no `## Conventions`), and running
`make test` (passes). On 2026-11-14 all eight URLs the stage uses answered 200 with no redirect, and
the live DigitalOcean, Linode and Oracle lists have no duplicate `prefix|service` keys (Oracle's tags
are only `OCI`, `OSN` and `OBJECT_STORAGE`). The goal is met. A published range names the provider
in `ips.csv`, and the owner column falls back to it when the owner lookup fails. The service column
shows the service, or the region when the list gives no service. DigitalOcean addresses are
dedicated when its list is present.

- **B1 met.** There are eight checks, one per list. The keys `aws` and `gcp` are unchanged, and so
  are their observation keys (`provider|prefix|service`). An existing engagement therefore fetches
  only the six new lists, and `--redo providerranges` refreshes them all (tested).
- **B2 met.** `classifyRanges` runs before the static ranges and the ASN, so a range takes
  precedence. The inventory still lets a CNAME into a provider override a dedicated range (tested
  with Heroku on a DigitalOcean range). Cloudflare and Fastly are shared with class `cdn`, and
  egress refuses to handshake them (canary-tested). DigitalOcean and Linode are dedicated and get
  handshaken. Linode is handshaken even when its owner lookup is never answered. Oracle `OSN` and
  `OBJECT_STORAGE` are shared and `OCI` is dedicated. An `OCI` range inside an `OSN` one fails
  closed. Two providers' covering ranges are `;`-joined in name order, and the result is shared if
  either one is. Sensitive-path selection still depends only on `SaaSServed`, which compares the
  class with `saas`. The new lists never yield `saas`, so nothing changes for the current data.
  One theoretical case remains: if a published CDN list ever covered one of the static SaaS ranges in
  `providers.yaml` (GitHub Pages, Squarespace), that address would lose `saas`. The live Fastly and
  Cloudflare lists cover none of them today. AWS and GCP ranges already had this precedence before
  this change. Known limitations 1 and 2 concern which service or region is shown. B2 asks only that
  both providers are shown, so neither is a gap. The live Linode list has a risk that matches the
  spec. It includes about 739 /24s in 104.64.0.0/10, which Team Cymru gives as AS20940
  (`providers.yaml`: Akamai, `cdn`). Because ranges win, these addresses become dedicated and
  port-eligible. They are most likely Akamai Connected Cloud compute, and a host that reaches Akamai's
  CDN through a CNAME (`edgekey.net`, `edgesuite.net`, `akamaiedge.net`) still stays shared. An apex A
  record pointing straight at an Akamai edge in those blocks would be handshaken (Follow-ups).
- **B3 met.** No Azure URL is fetched (tested), and the README says why.
- **B4 met.** Each of these is an error, so the check is retried and its earlier observations stay
  current: a non-200 answer (including the redirect the third-party client does not follow), a body
  cut off mid-transfer (egress), a body over the size cap, and a parse that yields no valid prefix.
  The `--verbose` warning names the provider, and no finding results (tested for 500, an empty body
  and an HTML body, after `--redo`). Known limitation 3 (a text list served complete but shorter)
  still yields ranges, so B4 does not cover it.
- **B5 met.** The passive-boundary section names all seven publishers (tested).

Nothing was changed by verification before the code review.

## Code review

`/code-review high --fix` found six issues, all in `internal/provider/provider.go`, and fixed one.
`make test` passes afterwards.

Fixed:

- `classifyRanges` no longer has a redundant `len(covering) == 0` early return, because the
  `len(by) == 0` check covers that case. This affects B2 only in form; behaviour is unchanged.

Left unfixed:

- **Linode's list covers AS20940 (Akamai `cdn`) space**, so those addresses become dedicated
  (B2). Spec B2 says a range beats the ASN and Linode is dedicated, so changing this would deviate
  from the spec. It is a decision for the user (Follow-ups).
- **Joined services and regions drop empty values**, so for example `aws;oracle` shows the service
  `OCI` with no sign of whose it is (B2, known limitation 1). Changing this would change how
  `ips.csv` displays rows, which the spec does not ask for.
- **A published range overrides a static SaaS range** in `providers.yaml`. If they ever overlapped,
  sensitive paths would be requested from a SaaS host (B2's "unchanged"). This is latent: no live
  list overlaps those ranges today, and AWS and GCP already had this precedence.
- **Linode object storage** (`*.linodeobjects.com`) addresses are in Linode's list and count as
  dedicated. This is not a regression, because Linode had no ASN entry before. The fix would be a
  CNAME entry, which is outside this spec (Follow-ups).
- **`provider.HasRangeRule`** is exported only for a test in another package. Moving it would
  need test restructuring for no behavioural gain.

# Follow-ups

1. Decide whether a dedicated published range (Linode) should stay shared when the address's ASN
   is a `cdn` entry, such as Akamai AS20940, which covers about 739 /24s in Linode's live list
   (104.64.0.0/10). Today the range wins, as B2 says, so an in-scope apex A record on an Akamai edge
   in those blocks is port-checked. If you want it kept shared, amend B2 and change
   `provider.Classify` in `internal/provider/provider.go`. Check the live list with
   `curl -s https://geoip.linode.com/ | grep -c '^104\.6[4-7]\.'`.
2. Decide whether `ips.csv` should keep service and region aligned per provider when two
   providers cover an address (known limitation 1), and whether Oracle `OCI` rows should also show
   their region (known limitation 2). Either change is in `classifyRanges` (`internal/provider/provider.go`)
   and `inventory.IPRows` (`internal/inventory/inventory.go`). A region column would also need an
   entry in the `ips.csv` column order in `docs/plans/2026-11-build-order.md`.
3. Consider adding `{suffix: linodeobjects.com, provider: linode, service: Object Storage}` under
   `cname:` in `internal/provider/providers.yaml`, so hosts on Linode object storage are shared
   rather than dedicated.
4. Fix the `.claude/hooks/go-check.sh` hook for worktrees. It builds the package path from the main
   checkout, so `go vet` cannot find the worktree package. Also reinstall `golangci-lint` built with
   go1.27 (the installed v1.64.8 was built with go1.26.1, and `go.mod` targets 1.27.3), for example
   `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest`. Then run
   `golangci-lint run ./...` in this worktree, because it has not been run on this branch.
