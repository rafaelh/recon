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

**Status: review before building (wave 3).** Specs 3 and 15 have merged, and the items that
waited on them were settled against the code on 2026-11-14. Spec 9 has not merged: after it
does, re-read the one item still marked *Review*. The open point below still needs the user's
answer. **Depends on:** Spec 3 (NS rows from `dnsroot`), Spec 9 (the email check it edits),
Spec 15 (the family table and the medium rule).

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
  shared or of unknown owner. As built, `provider.Default().DomainOwner(name)` matches the
  `domains:` list by suffix. Route 53 name servers (`ns-123.awsdns-45.com`) match no entry,
  because the number is inside the label, so they are not ruled out by name: they are ruled out
  by address (shared), which costs their address lookups if the open point is answered that way.
- **Markers**: `resolutions.csv` gains `self_hosted` (`yes`/`no` on NS rows, blank otherwise);
  `email-posture.csv` gains `mx_self_hosted` (the self-hosted MX hosts, `;`-joined). Both are
  computed when the file is written. The build-order plan gives the order: `self_hosted` follows
  `source` in `resolutions.csv` and comes before Spec 7's two date columns, and `mx_self_hosted`
  follows Spec 9's `mta_sts` in `email-posture.csv`.
- **`nsreverse`** (`internal/stages/nsreverse`, keyed on `securitytrails`, third-party) yields one
  check per self-hosted name server (`ns|<host>|max=<n>`) and mail host (`mx|<host>|max=<n>`).
  `Run` asks SecurityTrails' domain search filtered by that server, reads the total first, and if
  it is above `nsreverse.max_domains` (default 1,000) records nothing and warns; otherwise it
  records each domain's registrable domain as a `root` observation. A 401, 403 or 429 already
  aborts a keyed stage in `httpsrc.Get`, which is the quota rule of behaviour 3; the stage adds
  no quota code.
- **Evidence**: `Evidencer` returns (`shared-ns` or `shared-mx`, the server), which is what puts
  those two names in the `sources` column (behaviour 2), and leaves the key's `max=` out of the
  item. As built, the family table holds this stage under its stage name, `nsreverse`, and looks
  a source up by exact name, so `shared-ns` and `shared-mx` would each be a family of its own:
  the shared-infrastructure medium rule would never fire, and a root both found would count as
  two families. This spec replaces the `nsreverse` entry with `shared-ns` and `shared-mx`, both
  shared infrastructure. One such pair is then `medium` by the rule as built.
- **Candidate roots are never resolved**: the stage emits only `root` observations, which
  `resolve` does not look up. Excluded roots stay excluded by the scope's existing rule.

## Changes

- `internal/kinds/serveraddress.go`. `internal/stages/dns/dnsroot.go` and
  `internal/stages/risk/email.go`: the address lookups (*Review:* both files as built).
- `internal/inventory/inventory.go`: `SelfHosted`; `inventory.Data` gains the server addresses.
- `internal/stages/nsreverse/`; registered after `email`.
- `internal/candidates/candidates.go`: `shared-ns` and `shared-mx` in place of `nsreverse` in the
  family table.
- `internal/output/output.go`, `evidence.go`: the two columns.
- `internal/config/config.go`: `nsreverse.max_domains`. `README.md`: the stage, the setting, the
  two columns, the `--redo` notes, and `shared-ns` and `shared-mx` as `sources` values in place of
  the reserved `nsreverse`.

## Tests

- `internal/inventory`: `SelfHosted` for an in-scope host, an address in a netblock, a
  port-eligible address, a provider-hosted server, a shared address and an unknown owner.
- `internal/cli/nsreverse_test.go`: markers in both files with and without the key; nothing is
  fetched for provider-hosted servers; candidates carry `shared-ns` or `shared-mx` and are `medium`;
  a root found by both is still one family; above the cap nothing is recorded, a warning names the
  server, and changing the cap re-fetches; quota stops the stage; without the key the stage is
  `not-configured (no key)`; **canary:** no candidate root is resolved and no looked-up server
  address is contacted.

## Carried from built specs

Follow-ups and limits of the specs already built that bear on this one.

- **Family table (Spec 15, follow-up 2).** `nsreverse` was reserved in the table for this stage.
  The entry changes as the Evidence decision says; update the README sentence that lists the
  reserved names.
- **`Score` already assumes this stage reports only self-hosted servers (Spec 15).** Its medium
  rule fires on any shared-infrastructure evidence. The stage must never emit a root for a server
  that is not self-hosted, or that is above the cap.
- **The `dnsroot` check key does not carry the scope (Spec 3).** A name server that a root added
  later brings into scope becomes a hostname only after `--redo dnsroot`. Its `self_hosted`
  marker is computed on read, so it is right at once; its `nsreverse` check appears once it is
  self-hosted by either test.
- **`dnsroot` checks are per root and type (Spec 3)**, keyed `<root>|<TYPE>`. The NS address
  lookups of the open point join the `NS` check, so adding them to an existing engagement needs
  a token on that key, or they arrive only with `--redo dnsroot`. Decide which with the open
  point. *Review:* the same question for the email check, whose key Spec 9 changes.
- **Kinds the scope build reads (Spec 3, follow-up 3).** `inventory.Data` gains the server
  addresses, so `server_address` joins the kinds the scope build reads (`scopeKinds` in
  `runner.go`, or `run.BuildScope` once Spec 21 has merged). A pass that writes one then rebuilds
  the scope and inventory, as a pass that writes `resolution` rows already does. Nothing that
  decides contact may read it, and the canary test pins that.
- **A record that is no longer current has no attributes (Spec 3, follow-up 1).** The `self_hosted`
  marker is blank on a not-current `resolutions.csv` row.
- **`Kind` is not comparable (Spec 3).** Compare `Name()`.
- **Console text (Spec 22).** If Spec 22 has merged, the `--verbose` warning of behaviour 3 is a
  WARN line, shown without a flag.

## Out of scope

Comparing NS sets across roots already on record; SOA mailbox pivots.
