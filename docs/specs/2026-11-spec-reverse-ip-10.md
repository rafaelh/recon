# Spec 10: reverse lookups from in-scope addresses

## Goal

Every dedicated address recon has recorded is asked which other hostnames point at it, so sibling
sites and related domains hosted on the organisation's own servers are found.

## Behaviours

1. A `reverseip` stage, available under `--passive`, performs one check per recorded address
   that is inside an in-scope netblock or port-eligible, is not excluded, has a known owner and is
   not shared provider infrastructure. It never enumerates every address of a netblock. It asks
   HackerTarget's reverse IP lookup (unkeyed, IPv4 only) and, when `keys.securitytrails` is set,
   SecurityTrails' list of domains whose current A or AAAA record is the address.
2. A returned name under an in-scope root is recorded as a hostname. Any other name contributes
   its registrable domain as a candidate root in `candidates.csv` (the hostname itself is not
   kept). An excluded name is recorded as excluded. No names, or HackerTarget's "no records"
   reply, completes the check with nothing.
3. If one address returns more than `reverseip.max_domains` distinct registrable domains (default
   100), none are recorded and a `--verbose` warning names the address: it is treated as
   unrecognised shared hosting.
4. HackerTarget's quota behaviour is as in Spec 1 behaviour 5. Hostnames already obtained from
   Shodan (Spec 4) are not fetched again here.
5. A candidate root found on two or more distinct addresses contributes the reverse-IP signal
   defined in Spec 15.
6. Each address is queried once per engagement; new results arrive only with `--redo reverseip`.
   The README's passive-boundary section names HackerTarget.
