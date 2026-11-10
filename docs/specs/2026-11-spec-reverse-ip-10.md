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

# Design

**Status:** ready to build (wave 2). **Depends on:** Spec 1 (`ErrQuota`, `Warnf`, `CleanName`) and
Spec 15 (candidate evidence). Independent of Spec 4: behaviour 4's second sentence is read as "this stage
never calls Shodan" (confirm that reading; the alternative is to skip addresses `shodan-host` has
already answered, which would make this spec wait for Spec 4).

## Decisions

- **One stage, `reverseip`**, in `internal/stages/reverseip`, always configured, with sources
  `api.hackertarget.com` and `api.securitytrails.com`.
- **Checks** come from `View.IPs`, keeping an address that is in an in-scope netblock or
  port-eligible, not excluded, with a known owner and not shared. It never iterates
  `Scope.IPv4Addrs()`. Key: `<addr>|max=<n>`. An IPv6 address is yielded only when the
  SecurityTrails key is set, since HackerTarget cannot answer it; it gets its check when a key is
  added. As for Cert Spotter in Spec 1, a key added later applies to checks not yet done.
- **`Run`** asks HackerTarget (`reverseiplookup/?q=<addr>`, IPv4) and, when keyed, SecurityTrails'
  domain search filtered by the address, and merges the names through `httpsrc.CleanName`.
  HackerTarget's quota body or a 429 is `ErrQuota`.
- **Recording**: a name the scope classifies in scope or excluded is a `hostname` observation
  (scope then lists it as a subdomain or as excluded); any other name contributes its registrable
  domain as a `root` observation and the hostname is dropped. The check input carries the scope.
- **The shared-hosting guard counts distinct registrable domains**; above
  `reverseip.max_domains` (default 100, minimum 1) nothing is recorded and `run.Warnf` names the
  address. The cap is in the key, so changing it re-asks.
- **Evidence**: `Evidencer` returns (`reverse-ip`, the address), so a root seen on two addresses
  has two pairs and meets Spec 15's medium rule with no extra code.

## Changes

- `internal/stages/reverseip/`. `internal/cli/cli.go`: registered after `shodan-host`'s place.
- `internal/config/config.go`: `reverseip.max_domains`.
- `internal/candidates`: `reverse-ip` is already in the family table; confirm.
- `README.md`: HackerTarget in the passive-boundary list, the stage, the setting.

## Tests

`internal/cli/reverseip_test.go`:

- Only dedicated, known-owner, non-excluded addresses are asked; a netblock's unrecorded addresses
  are not; shared and unknown-owner addresses are not.
- In-scope names become hostnames, others become candidate roots without the hostname, excluded
  names land in `excluded.csv`; "no records" completes with nothing.
- More than the cap records nothing and warns; changing the cap re-asks.
- HackerTarget quota stops the stage and retries next run; with a SecurityTrails key both are
  asked and IPv6 is covered; the key never appears in output.
- A root on two addresses is `medium` in `candidates.csv`; once per engagement until
  `--redo reverseip`; **canary:** no candidate root is resolved or contacted.

## Out of scope

Shodan as a reverse source (Spec 4 covers it); enumerating netblocks.
