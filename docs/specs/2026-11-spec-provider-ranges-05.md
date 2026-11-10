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
