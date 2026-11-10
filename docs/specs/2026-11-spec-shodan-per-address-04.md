# Spec 4: passive ports and hostnames per address from Shodan

## Goal

With a Shodan key, a `--passive` run shows the open ports, banners and hostnames Shodan holds for
each dedicated in-scope address, up to a per-run limit, and an active run gains Shodan's view
alongside its own handshakes without Shodan's claims ever widening what recon connects to.

## Behaviours

1. The existing `shodan` netblock search also records the ports and banners it returns, so
   addresses it returned need no extra lookups. Existing engagements get those ports only after
   `--redo shodan`; the README says so. A new `shodan-host` stage, available under `--passive` and
   `not-configured (no key)` without `keys.shodan`, performs one host lookup per address that
   `ips.csv` marks port-eligible and that either is not inside an in-scope netblock or is inside
   one whose search stopped at its page cap and did not return the address. The summary says when
   a netblock search was truncated.
2. Lookups per run are capped by `shodan.max_hosts` (default 500), taken in address order. Deferred
   checks are not counted as failures, the stage shows `done`, and the summary always says how
   many addresses were deferred to the next run. Shodan data for an address is refreshed only by
   `--redo shodan-host`.
3. `open-ports.csv` gains `source` (`recon`, `shodan` or `recon;shodan`) and `shodan_last_seen`
   (empty on rows only recon saw). When both have a banner, recon's is shown. Shodan's banner is
   cut to its first line or 256 characters, whichever is shorter, and sanitised like recon's own.
   A TCP port Shodan reports outside the configured port list is shown as unconfirmed and recon
   never connects to it. UDP services Shodan reports are not recorded.
4. A hostname Shodan associates with the address is recorded as a hostname when it is under an
   in-scope root; any other becomes a candidate root in `candidates.csv`.
5. recon's own handshake result takes precedence over Shodan, whichever came first. A port
   recon finds closed (the connection is rejected) marks that address-and-port row not current; a
   port that does not answer within the connect timeout leaves it unconfirmed. A
   risky port reported only by Shodan is a finding in `risk-ports.csv` one severity step below the
   confirmed equivalent (medium becomes low) with a `confirmed` column of `no`. When the `ports`
   stage confirms it, the same row is updated to the full severity, `confirmed` becomes `yes`, and
   a new `+` line is printed at the raised severity.
6. The console summary has a line `N risky ports reported by Shodan, unconfirmed` whenever N is
   above zero, and the `--json` summary event carries N. The open-port count is split into
   confirmed (recon completed a handshake) and third-party reported (all others).
7. An address Shodan does not know (404) completes the check with no observations. Keyed-source
   abort rules are unchanged.
8. The README's passive-boundary section says Shodan is queried per dedicated in-scope address up
   to the cap, that host lookups are rate-limited rather than credited (to be confirmed against
   Shodan's current terms before the README is written), and that netblock search pages cost
   credits as today.
