# Spec 7: historical DNS and origin exposure

## Goal

recon records the historical addresses of CDN-fronted hostnames, and when such a hostname's
origin server is also reachable directly it reports the exposed origin as a medium finding,
confirmed by one GET to an address recon is already allowed to contact.

## Behaviours

1. A `dnshistory` stage, keyed on `keys.securitytrails` and available under `--passive`, fetches
   the historical A and AAAA records of each in-scope hostname that currently resolves to a known
   CDN or WAF provider, up to `dnshistory.max_hosts` per run (default 200, in hostname order,
   remainder deferred and reported in the summary). Each historical address is a row in
   `resolutions.csv` with type `A-historical` or `AAAA-historical` and `historical_first_seen` and
   `historical_last_seen` columns from the source. Historical addresses appear in `ips.csv` but
   are never treated as current addresses: they are not probed, port-checked or used for
   wildcard detection by virtue of being historical.
2. An **origin candidate** for a fronted hostname is an address whose owner is known and is not
   provider infrastructure, and which is either a historical address of that hostname, or the
   current address of another in-scope, non-wildcard-only hostname that is not itself behind a
   CDN or WAF and whose certificate names the fronted hostname or whose non-empty page title
   equals the fronted hostname's. At most `origincheck.max_candidates` (default 5) per hostname
   are checked: historical addresses most recent first, then siblings.
3. An `origincheck` stage (target contact, skipped under `--passive` and until authorisation)
   performs one check per (fronted hostname, candidate) pair, but only when the candidate is
   inside an in-scope netblock, or is the current address of an in-scope non-wildcard-only
   hostname with a known, non-shared owner (the port-eligibility rule), and is not excluded. Any
   other candidate is reported as an unconfirmed possible origin and never contacted. No check is
   created until the probe has a 2xx result for the fronted hostname; if that title or
   certificate later changes, the pair is checked again.
4. The check is one HTTPS GET of `/` on port 443 with both the TLS server name and the Host
   header set to the fronted hostname, falling back to one HTTP GET on port 80 only when nothing
   answers on 443 (not on a TLS error). Redirects are not followed and a 3xx confirms nothing. At
   most one GET per scheme per check.
5. The exposure is **confirmed** when the response's non-empty title equals the fronted
   hostname's probe title and that title is not on a built-in list of CDN, WAF and default-server
   titles, or when the response has the same status as the probe and a body length within 10% of
   it and the certificate names the fronted hostname. The probe records body length to support
   this. A certificate match alone, or any other outcome, leaves the pair a possible origin.
6. `risk-origin-exposure.csv` has one row per (hostname, address): the CDN or WAF provider, the
   address, how the candidate was found (`historical`, `sibling-certificate`, `sibling-title`,
   `;`-joined), what confirmed it, and `confirmed` (`yes`/`no`). Confirmed rows are medium
   findings; possible origins are low. The console `+` line reads `medium origin exposure
   <hostname> -> <address> (behind <provider>)`. The README output table and `--help` severity list
   include them.
7. A finding is marked not current when the pair no longer qualifies (the hostname is no longer
   behind a CDN or WAF, the address becomes provider infrastructure, or the sibling no longer
   matches) or when `--redo origincheck` fails to confirm it.
8. Without a SecurityTrails key, `dnshistory` is `not-configured (no key)` and `origincheck` runs
   over sibling-derived candidates only.
9. The README's passive-boundary section says recon may send one GET of `/` to an address it is
   already allowed to contact, with an in-scope hostname as the server name and Host header, and
   why; `origincheck` joins the list of stages skipped under `--passive`.

# Design

**Status: review before building (wave 3).** Specs 2, 5 and 6 have merged, and the items that
waited on them were settled against the code on 2026-11-14. Spec 18 has not merged: after it
does, re-read the one item still marked *Review*. The point under "Settle before building" needs
an answer first. **Depends on:** Spec 5 (Cloudflare and Fastly ranges, the class passed through
as `Result.Class`, `provider.ClassCDN`), Spec 6 (`run.Budgeted`), Spec 18 (the target TLS
configuration and `Response` TLS accessors), Spec 2 (the `resolutionRows` merge it extends).

## Settle before building

**Akamai addresses in Linode's published list (Spec 5, follow-up 1).** A published range beats
the ASN, and Linode's list holds about 739 /24s in 104.64.0.0/10 that AS20940 (Akamai, class
`cdn`) announces. Those addresses are therefore dedicated. That is wrong twice for this spec. A
hostname whose A record is one of them is not `Fronted` by the address test. And such an address
counts as "not provider infrastructure", so it can be chosen as an origin candidate, be contacted
(it is port-eligible) and confirm an exposure that is not one, because the CDN edge serves the
fronted site's own title. Recommended: in `provider.Classify`, an address whose ASN entry has
class `cdn` stays shared, with that class, even inside a dedicated published range. That amends
behaviour 2 of Spec 5, so it is the user's decision. If the answer is no, this spec needs another
way to keep those addresses out of the origin candidates, and a test either way.

## Decisions

- **"Behind a CDN or WAF" is an inventory question.** `inventory.Fronted(host) (provider string,
  ok bool)` is true when a CNAME on the host's chain matches an entry of class `cdn` or `waf`, or
  one of its addresses classifies as `cdn`. CNAME entries in `providers.yaml` gain those classes
  (CloudFront, Azure Front Door, Cloudflare, Fastly, Akamai, and WAF providers). As built,
  `Result.Class` carries the class of the range rule or ASN entry that classified the address
  (`provider.ClassCDN` for Cloudflare's and Fastly's ranges and for every `cdn` ASN entry), so the
  address test is `Class == provider.ClassCDN`. CNAME entries carry only `class: saas` today and
  no `waf` class exists. This spec adds `provider.ClassWAF` and the `cdn` and `waf` classes on
  CNAME entries. `SaaSServed` compares the class with `saas`, so the new classes change nothing
  for sensitive paths. If an `asn:` entry is ever given `waf`, it must be shared, as `cdn` is.
- **`dnshistory`** (`internal/stages/dnshistory`, keyed on `securitytrails`, third-party) yields one
  check per fronted in-scope hostname in name order, `Budgeted` by `dnshistory.max_hosts` (default
  200): `Budget` returns the setting and each check has `Cost` 1. It records `historical_address`
  (`host`, `addr`, `type`, `first_seen`, `last_seen`) and an `ip` observation for each address.
  Nothing that decides contact reads `historical_address`; the `ip` record makes the address appear
  in `ips.csv` and get an owner lookup, and it stays ineligible for ports and probing unless the
  existing rules already allow it.
- **Candidate selection is pure**, in a new package `internal/origin`:
  `Candidates(fronted, historical, services, inv, scope, max)` returns, per fronted hostname, up
  to `origincheck.max_candidates` (default 5) addresses with how each was found and whether it may
  be contacted (inside an in-scope netblock, or port-eligible; and not excluded). The same function
  feeds the stage's checks and the findings, so they cannot disagree.
- **`origincheck`** (target contact) yields a check per contactable pair once the fronted
  hostname's HTTPS service has a 2xx status, keyed `<host>|<addr>|<hash of the probe's title and
  certificate subject>`; the stage is `Retiring`, so a changed title or certificate re-checks and
  retires the old evidence.
- **The request is a new, narrow egress constructor**, `egress.OriginCheck(host, scheme, addr)`:
  GET `/` on 443 or 80, dialling `addr`, with the server name and Host header `host`. The policy
  enforces what the stage intends: `host` is in scope, and `addr` is not excluded and is inside an
  in-scope netblock or port-eligible. It does not require `addr` to be one of `host`'s resolved
  addresses, which is the one way it differs from `RootAt`. HTTP on 80 is tried only when 443 gave
  `NoService` with a reason other than `tls-failed`. *Review:* Spec 18's TLS configuration applies
  because the request goes through `targetHTTP.do`.
- **Evidence**: `origin_check` (key `host|addr`): `scheme`, `status`, `title`, `body_len`,
  `cert_names_host`. The probe records `body_len` of its first response in `WebServiceAttrs`.
- **Findings** (`internal/findings/origin.go`, category `origin-exposure`, key
  `origin-exposure|<host>|<addr>` so the row is stable when it moves between possible and
  confirmed): `confirmed` (medium) by the rules of behaviour 5 with a built-in list of CDN, WAF
  and default-server titles in `internal/origin`; otherwise `possible` (low), including pairs that
  may not be contacted. The finding carries a `line` attribute that the runner's finding
  announcement prints (findings cannot use `Kind.Found`: `kinds` cannot import `findings`).
- **`resolutions.csv`** shows historical rows as `A-historical`/`AAAA-historical` with the two
  date columns. As built, `resolutionRows` (`internal/output/output.go`) merges `resolution` and
  `dns_claim` records by key into `name`, `type`, `value`, `source`. Historical rows are appended
  from `historical_address`. Their type is their own, so they never share a key with either kind.
  Their `source` is `dnshistory`. The two date columns are the last columns of the file, after
  `source` and after Spec 16's `self_hosted` if that has merged, and are blank on every other row.

## Changes

- `internal/provider/providers.yaml`, `provider.go`; `internal/inventory/inventory.go`: `Fronted`.
- `internal/stages/dnshistory/`, `internal/stages/web/origincheck.go`, `internal/origin/`.
- `internal/egress/http.go`: `OriginCheck` and its policy branch.
- `internal/kinds/origin.go` (`historical_address`, `origin_check`); `body_len` on
  `WebServiceAttrs`. `internal/findings/origin.go`, `table.go`, `records.go`.
- `internal/output/output.go`: resolution rows. `internal/config/config.go`: two settings.
- `internal/cli/cli.go`: `dnshistory` after `reverseip`, `origincheck` before `ports`.
- `README.md`: boundary text, the passive-mode stage list, the file, the severity table.

## Tests

- `internal/egress`: `OriginCheck` is refused for an address outside the netblocks and not
  port-eligible, an excluded address, a candidate or excluded host, and under `--passive`; it
  sends exactly one GET per scheme and never follows a redirect.
- `internal/origin`: candidate selection, ordering and the cap; confirmation rules, including the
  default-title list, the 10% body rule and "certificate alone is not enough".
- `internal/cli/origin_test.go` (loopback fakes, `DialMap`): a historical origin confirmed by
  title; a sibling found by certificate and by title; an uncontactable candidate reported as
  possible and **(canary)** never contacted; no check before the probe's 2xx; a changed title
  re-checks; the HTTP fallback only when 443 does not answer; findings going not current for each
  reason in behaviour 7; no key leaves sibling candidates only; the `dnshistory` cap and its
  deferred count; `--passive` skips `origincheck` and runs `dnshistory`.

## Carried from built specs

Follow-ups and limits of the specs already built that bear on this one.

- **Claim sources (Spec 2).** A second claim source that reports the same record would overwrite
  the first one's `source` attribute. It does not arise here: historical addresses are their own
  kind, `historical_address`, not `dns_claim`.
- **Budget rules (Spec 6).** The first pending check of a run is always sent, a budget below 1
  counts as 1, and a check that fails still spends its share. The `Deferred to the next run`
  block shows a bare number beside `dnshistory`; the README names its unit (hostnames).
- **Quota.** `httpsrc.Get` already aborts a keyed stage on a 401, 403 or 429, which is the rule
  for the other keyed sources. `dnshistory` needs no quota code of its own.
- **Linode object storage (Spec 5, follow-up 3).** While editing the `cname:` entries of
  `providers.yaml`, add `{suffix: linodeobjects.com, provider: linode, service: Object Storage}`,
  so a host on Linode object storage is shared, not dedicated.
- **A finding that is no longer derived keeps only what its key holds (Specs 3 and 12).** The
  store keeps attributes only from current observations. The key `origin-exposure|<host>|<addr>`
  gives such a row its hostname and address; its other cells are blank, as in every risk file.
- **New fields go at the end.** `body_len` is appended to `WebServiceAttrs` after the three
  fields Spec 18 adds.
- **`Kind` is not comparable (Spec 3).** Compare `Name()`.
- **Console text (Spec 22).** If Spec 22 has merged, the `+` line goes through its log formatter
  and is asserted on stderr. If not, assert it on stdout.

## Out of scope

Origin discovery by scanning netblocks, favicon or certificate search engines; requests other than
GET `/`.
