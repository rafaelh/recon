# Spec 16: shared name servers and mail hosts as a relatedness signal

## Goal

Root domains that share an organisation's own name servers or mail hosts are found and offered as
candidates, because self-hosted DNS and mail are strong signs of common ownership, without ever
resolving a candidate.

## Behaviours

1. A name server or mail host is **self-hosted** only if it is in scope, or its address is inside
   an in-scope netblock or is a port-eligible dedicated address. Name servers and mail hosts on
   known providers, or whose address is shared infrastructure or of unknown owner, are never a
   signal and nothing is fetched for them. `resolutions.csv` NS rows and `email-posture.csv` MX
   entries gain a `self_hosted` marker.
2. An `nsreverse` stage, keyed on `keys.securitytrails` and available under `--passive`, fetches
   the domains hosted on each self-hosted name server and the domains whose MX is each
   self-hosted mail host, and records each as a candidate root with source `shared-ns` or
   `shared-mx`. Candidate roots are never resolved; this lookup is the only discovery path.
3. If a server has more than `nsreverse.max_domains` domains (default 1,000), none are recorded,
   the server is treated as not self-hosted for this purpose, and a `--verbose` warning names it.
   Changing the setting re-fetches. Quota exhaustion stops the stage as for other keyed sources.
4. A candidate found this way is at least `medium` confidence (Spec 15). Excluded roots stay
   excluded.
5. Without the key, the stage is `not-configured (no key)` and only the `self_hosted` marker is
   produced.

# Design

**Status: review before building (wave 3).** This design depends on three specs that are not
built yet and has one open point. It is filled in as far as practical; after Specs 3, 9 and 15
merge, re-read the items marked *Review*. **Depends on:** Spec 3 (NS rows from `dnsroot`), Spec 9
(the email check it edits), Spec 15 (the `shared-ns`/`shared-mx` sources and the medium rule).

## Open point to settle at review

A name server or mail host outside scope has no address on record, because `resolve` looks up
only in-scope and excluded names. Deciding whether such a host is self-hosted "by address" needs
its A and AAAA records. This design proposes that `dnsroot` and `email` look those up through the
public resolvers and store them in a kind nothing else reads. That is a DNS lookup of a name that
is not in scope: allowed by the passive boundary (a public resolver is asked, the host is not
contacted), but new for recon. The alternative is to treat only in-scope hosts as self-hosted and
drop the address clauses of behaviour 1. Confirm before building.

## Decisions

- **Server addresses are their own kind**, `server_address` (key `host|addr`; `host`, `addr`,
  `role` `ns` or `mx`), written by `dnsroot` for NS targets and by the email check for MX hosts.
  The inventory, scope and egress policy do not read it, so a looked-up server never becomes
  resolved, probed or port-checked because of it.
- **Self-hosted is derived on read**: `inventory.SelfHosted(host, sc)` is true when the host is in
  scope, or any `server_address` of it is inside an in-scope netblock or is port-eligible, and
  false when the host's domain is a known provider (`provider.DomainOwner`) or its address is
  shared or of unknown owner. *Review:* `DomainOwner`'s final name and data.
- **Markers**: `resolutions.csv` gains `self_hosted` (`yes`/`no` on NS rows, blank otherwise);
  `email-posture.csv` gains `mx_self_hosted` (the self-hosted MX hosts, `;`-joined). Both are
  computed when the file is written. *Review:* column order in the build-order plan.
- **`nsreverse`** (`internal/stages/nsreverse`, keyed on `securitytrails`, third-party) yields one
  check per self-hosted name server (`ns|<host>|max=<n>`) and mail host (`mx|<host>|max=<n>`).
  `Run` asks SecurityTrails' domain search filtered by that server, reads the total first, and if
  it is above `nsreverse.max_domains` (default 1,000) records nothing and warns; otherwise it
  records each domain's registrable domain as a `root` observation. A 429 is `ErrQuota`.
- **Evidence**: `Evidencer` returns (`shared-ns` or `shared-mx`, the server). Spec 15's rules
  already make one such pair `medium`. *Review:* the family table entry.
- **Candidate roots are never resolved**: the stage emits only `root` observations, which
  `resolve` does not look up. Excluded roots stay excluded by the scope's existing rule.

## Changes

- `internal/kinds/serveraddress.go`. `internal/stages/dns/dnsroot.go` and
  `internal/stages/risk/email.go`: the address lookups (*Review:* both files as built).
- `internal/inventory/inventory.go`: `SelfHosted`; `inventory.Data` gains the server addresses.
- `internal/stages/nsreverse/`; registered after `email`.
- `internal/output/output.go`, `evidence.go`: the two columns.
- `internal/config/config.go`: `nsreverse.max_domains`. `README.md`.

## Tests

- `internal/inventory`: `SelfHosted` for an in-scope host, an address in a netblock, a
  port-eligible address, a provider-hosted server, a shared address and an unknown owner.
- `internal/cli/nsreverse_test.go`: markers in both files with and without the key; nothing is
  fetched for provider-hosted servers; candidates carry `shared-ns` or `shared-mx` and are
  `medium`; above the cap nothing is recorded, a warning names the server, and changing the cap
  re-fetches; quota stops the stage; without the key the stage is `not-configured (no key)`;
  **canary:** no candidate root is resolved and no looked-up server address is contacted.

## Out of scope

Comparing NS sets across roots already on record; SOA mailbox pivots.
