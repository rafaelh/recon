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
