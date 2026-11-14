# Spec 19: service records and well-known hostnames

## Goal

Mail, identity, voice, collaboration and game infrastructure advertised through SRV records and
well-known hostnames is discovered for each in-scope root, without widening what recon connects to.

## Behaviours

1. The `dnsroot` stage (Spec 3) also queries, as its own check per root, a fixed SRV list:
   `_sip._tls`, `_sip._tcp`, `_sipfederationtls._tcp`, `_autodiscover._tcp`, `_ldap._tcp`,
   `_kerberos._tcp`, `_xmpp-server._tcp`, `_xmpp-client._tcp`, `_caldav._tcp`, `_carddav._tcp`,
   `_imaps._tcp`, `_submission._tcp`, `_matrix._tcp`, `_minecraft._tcp`. Adding SRV to an
   existing engagement runs the new check once; nothing already recorded is re-queried.
2. Each SRV answer is a row in `resolutions.csv` with type `SRV`, the service name as the name and
   `priority weight port target` as the value. SRV service names are not hostnames and are not
   tested as wildcard zones. A target of `.` records nothing. An in-scope target is recorded as a
   hostname; any other target is a row in `third-parties.csv` with mechanism `srv` and the
   target's registrable domain, not a candidate.
3. SRV ports are reported, never connected to: `ips.csv` gains an `srv_ports` column listing the
   ports SRV records advertise for the address's hostnames. The `ports` stage keeps to the
   configured port list and the README boundary text is unchanged.
4. The permutations stage always tries `autodiscover`, `lyncdiscover`, `enterpriseenrollment`,
   `enterpriseregistration` and `mta-sts` under each root, even when the wordlist lacks them,
   and only when permutations are enabled. These fixed labels are part of the permutation check
   like any wordlist change.

# Design

**Status:** ready to build (wave 2). Specs 3 and 6 have merged, and the design was re-checked
against them on 2026-11-14: `dnsroot` and the permutations stage are described below as built.
**Depends on:** Spec 3 (the `dnsroot` stage, `third_party`) and Spec 6 (it reordered and budgeted
the permutations stage this spec also edits).

## Decisions

- **SRV is one more check per root in `dnsroot`**, keyed `<root>|SRV|<hash of the service list>`.
  The existing type checks keep their keys, so nothing recorded is re-queried, and editing the
  list later re-runs only this check. A SERVFAIL or timeout on any service fails the check. As
  built, `dnsroot` yields one check per in-scope input root and per row of its `rootTypes` table
  (NS, SOA, TXT, CAA), keyed `<root>|<TYPE>`. SRV is not a row of that table, because its check
  makes one query per service name; it is yielded beside them.
- **Egress** gains `TypeSRV` with the value `priority weight port target`.
- **Rows** are `resolution` records with the service name (`_sip._tls.example.com`) as the name
  and type `SRV`. The inventory reads only `A`, `AAAA` and `CNAME` rows and the wildcard stage
  derives zones from hostnames, so service names are never treated as hostnames or wildcard
  zones; a test pins both.
- **Targets**: `.` records nothing; an in-scope target is a `hostname` observation; any other is a
  `third_party` observation with mechanism `srv` and the target's registrable domain. The row
  uses the kind as built: key `<root>|srv|<domain>`, depth 0 (the root's own records), `provider`
  from `provider.DomainOwner` as for `ns` rows. `srv` becomes a mechanism constant beside
  `MechanismNS`, and `kinds.ThirdPartyOf` gains it in its key fallback (the key's last part is
  the domain), so a row that is no longer current still shows its root, mechanism and domain.
- **`srv_ports` is derived on read** in the inventory: for each current SRV row whose target is an
  in-scope hostname, the port is attached to that hostname's addresses, and `ips.csv` lists them
  `;`-joined. Nothing reads the column back: the ports stage and the egress policy keep to the
  configured list.
- **Fixed labels** are a constant in the permutations stage, appended to the root check's words
  after the wordlist (deduplicated). The root check's key hashes the wordlist and the fixed
  labels together, so adding them repeats the root checks once, as a wordlist change does. As
  built, the root key is `root|<root>|wl=<hash>` and the seed key
  `seed|<seed>|wl=<hash>|max=<n>`, from the same hash. Only the root key changes: seed checks do
  not use the fixed labels and must not be repeated. A root check's `Cost` is the number of names
  it queries, so it counts the fixed labels too. A root that is a known wildcard zone gets no
  root check, as today, so the labels are not tried under it: every name under it exists.

## Changes

- `internal/egress/dns.go`, `egresstest/dns.go`: SRV.
- `internal/stages/dns/dnsroot.go`: the SRV check. `permutations.go`: fixed labels and key.
- `internal/kinds/thirdparty.go`: the `srv` mechanism constant and the `ThirdPartyOf` fallback.
- `internal/inventory/inventory.go`: `IPRow.SRVPorts`. `internal/output/output.go`: the column.
- `README.md`: the service list, `srv_ports`, the fixed labels, and `srv` among the mechanisms in
  the `third-parties.csv` row.

## Tests

`internal/cli/srv_test.go`, with `egresstest`:

- Each answer is a `resolutions.csv` row with the stated value; `.` records nothing; an in-scope
  target becomes a hostname; another is a `third-parties.csv` row and not a candidate.
- An existing engagement runs only the new check; NS, SOA, TXT and CAA are not re-queried.
- `ips.csv` shows `srv_ports`; **canary:** an SRV port outside the configured list is never
  connected to; no wildcard check is made for a service name.
- The five fixed labels are tried with a custom wordlist that lacks them, and not at all with
  `--no-permutations`. Adding them to an existing engagement repeats the root checks once and no
  seed check.

## Carried from built specs

Follow-ups and limits of the specs already built that bear on this one.

- **The repeat spends the per-run budget (Spec 6).** The permutations stage is `Budgeted` by
  `permutations.max_names` (default 200,000), and a root check costs its whole word count, about
  4,900 with the built-in list. Repeating every root check once therefore fits about 40 roots in
  one run; the rest are deferred and shown under `Deferred to the next run`. The README's note
  on the fixed labels says so.
- **The `dnsroot` check key does not carry the scope (Spec 3).** An SRV target that a root added
  later brings into scope becomes a hostname only after `--redo dnsroot`. Its `third-parties.csv`
  row hides itself at once, because the showing rule is evaluated on read.
- **`resolution` rows cost a scope rebuild (Spec 3, follow-up 3).** The scope build reads the
  `resolution` kind, so a pass that writes SRV rows rebuilds the scope and inventory although
  they cannot change it, as NS, SOA, TXT and CAA rows already do. That is accepted here.
- **A record that is no longer current has no attributes (Spec 3, follow-up 1).**
  `splitResolutionKey` already reads `name|TYPE|value` for such a `resolutions.csv` row, and an
  SRV value holds spaces, not bars, so it needs no change.
- **Column order.** `srv_ports` is the last column of `ips.csv`, after the three Spec 8 adds.
- **`Kind` is not comparable (Spec 3).** Compare `Name()`.

## Out of scope

Connecting to SRV ports; SRV lookups under subdomains.
