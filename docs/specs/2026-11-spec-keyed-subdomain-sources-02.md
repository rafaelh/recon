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
