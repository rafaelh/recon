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

**Status:** ready to build (wave 2). **Depends on:** Spec 3 (the `dnsroot` stage, `third_party`)
and Spec 6 (it reorders the permutations stage this spec also edits). Re-check `dnsroot`'s check
shape once Spec 3 has merged.

## Decisions

- **SRV is one more check per root in `dnsroot`**, keyed `<root>|SRV|<hash of the service list>`.
  The existing type checks keep their keys, so nothing recorded is re-queried, and editing the
  list later re-runs only this check. A SERVFAIL or timeout on any service fails the check.
- **Egress** gains `TypeSRV` with the value `priority weight port target`.
- **Rows** are `resolution` records with the service name (`_sip._tls.example.com`) as the name
  and type `SRV`. The inventory reads only `A`, `AAAA` and `CNAME` rows and the wildcard stage
  derives zones from hostnames, so service names are never treated as hostnames or wildcard
  zones; a test pins both.
- **Targets**: `.` records nothing; an in-scope target is a `hostname` observation; any other is a
  `third_party` observation with mechanism `srv` and the target's registrable domain.
- **`srv_ports` is derived on read** in the inventory: for each current SRV row whose target is an
  in-scope hostname, the port is attached to that hostname's addresses, and `ips.csv` lists them
  `;`-joined. Nothing reads the column back: the ports stage and the egress policy keep to the
  configured list.
- **Fixed labels** are a constant in the permutations stage, appended to the root check's words
  after the wordlist (deduplicated). The root check's key hashes the wordlist and the fixed
  labels together, so adding them repeats the root checks once, as a wordlist change does.

## Changes

- `internal/egress/dns.go`, `egresstest/dns.go`: SRV.
- `internal/stages/dns/dnsroot.go`: the SRV check. `permutations.go`: fixed labels and key.
- `internal/inventory/inventory.go`: `IPRow.SRVPorts`. `internal/output/output.go`: the column.
- `README.md`: the service list, `srv_ports`, the fixed labels.

## Tests

`internal/cli/srv_test.go`, with `egresstest`:

- Each answer is a `resolutions.csv` row with the stated value; `.` records nothing; an in-scope
  target becomes a hostname; another is a `third-parties.csv` row and not a candidate.
- An existing engagement runs only the new check; NS, SOA, TXT and CAA are not re-queried.
- `ips.csv` shows `srv_ports`; **canary:** an SRV port outside the configured list is never
  connected to; no wildcard check is made for a service name.
- The five fixed labels are tried with a custom wordlist that lacks them, and not at all with
  `--no-permutations`.

## Out of scope

Connecting to SRV ports; SRV lookups under subdomains.
