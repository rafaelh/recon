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

**Status:** ready to build (wave 2). Specs 1 and 15 have merged, and on 2026-11-14 the evidence
source was corrected to the name the family table holds (`reverseip`, not `reverse-ip`).
**Depends on:** Spec 1 (`ErrQuota`, `Warnf`, `CleanName`) and Spec 15 (candidate evidence).
Independent of Spec 4: behaviour 4's second sentence is read as "this stage
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
  HackerTarget's quota body or a 429 is `ErrQuota`: the 429 through `httpsrc.GetQuota`, and the
  quota body, which arrives with a 200, by the reply rules the `hackertarget` subdomain stage
  already has (`hackertargetNames` in `internal/stages/subdomains`). Move that function to
  `httpsrc` and call it from both stages; do not write the rules twice.
- **Recording**: a name the scope classifies in scope or excluded is a `hostname` observation
  (scope then lists it as a subdomain or as excluded); any other name contributes its registrable
  domain as a `root` observation and the hostname is dropped. The check input carries the scope.
- **The shared-hosting guard counts distinct registrable domains**; above
  `reverseip.max_domains` (default 100, minimum 1) nothing is recorded and `run.Warnf` names the
  address. The cap is in the key, so changing it re-asks.
- **Evidence**: `Evidencer` returns (`reverseip`, the address). `reverseip` is the stage's own
  name and the reverse IP entry of the family table as built; any other spelling would be a
  family of its own and the medium rule would never fire. The item leaves out the key's `max=`,
  so changing the cap does not count an address twice. A root seen on two addresses has two pairs
  and meets Spec 15's medium rule with no extra code.

## Changes

- `internal/stages/reverseip/`. `internal/cli/cli.go`: registered after `shodan-host`'s place.
- `internal/config/config.go`: `reverseip.max_domains`.
- `internal/candidates`: nothing. `reverseip` is in the family table.
- `internal/stages/httpsrc/httpsrc.go`: HackerTarget's reply rules, moved from `subdomains`.
- `README.md`: HackerTarget in the passive-boundary list, the stage, the setting, the
  `--redo reverseip` note, and `reverseip` moved out of the sentence that lists the reserved
  source names.

## Tests

`internal/cli/reverseip_test.go`:

- Only dedicated, known-owner, non-excluded addresses are asked; a netblock's unrecorded addresses
  are not; shared and unknown-owner addresses are not.
- In-scope names become hostnames, others become candidate roots without the hostname, excluded
  names land in `excluded.csv`; "no records" completes with nothing.
- More than the cap records nothing and warns; changing the cap re-asks.
- HackerTarget quota stops the stage and retries next run; with a SecurityTrails key both are
  asked and IPv6 is covered; the key never appears in output.
- A root on two addresses is `medium` in `candidates.csv` with `reverseip` in `sources`, and stays
  at two pairs after the cap is changed and both addresses are asked again; once per engagement
  until `--redo reverseip`; **canary:** no candidate root is resolved or contacted.

## Carried from built specs

Follow-ups and limits of the specs already built that bear on this one.

- **Family table (Spec 15, follow-up 2).** `reverseip` was reserved in the table for this stage.
  Take it out of the README sentence that lists the reserved names.
- **Keyed aborts.** `httpsrc.Get` aborts a keyed stage on a 401, 403 or 429. A rejected
  SecurityTrails key therefore stops the whole stage, HackerTarget lookups included, until the
  key is fixed or removed. Say so in the README beside the key.
- **The check key does not carry the scope (Specs 2 and 3)**, as for `shodan-dns` and `dnsroot`.
  A hostname under a root the user promotes later was dropped when its address was asked, so it
  is recorded only after `--redo reverseip`. Putting the scope in the key would ask every address
  again on every scope change, against a small unkeyed quota. The README's `--redo reverseip`
  note says so.
- **Hostname cleaning (Spec 1).** `httpsrc.CleanName` strips `*.` before it validates, so a
  wildcard name gives its parent. The hostname helpers are merged in one change after Specs 4,
  10, 13 and 17.
- **Console text (Spec 22).** If Spec 22 has merged, the `--verbose` warning of behaviour 3 is a
  WARN line, shown without a flag.

## Out of scope

Shodan as a reverse source (Spec 4 covers it); enumerating netblocks.
