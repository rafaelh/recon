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

# Design

**Status:** ready to build (wave 2). Every spec it depends on has merged, and the design was
re-checked against them on 2026-11-14. **Depends on:** Spec 6 (`run.Budgeted`, built as
`Budget(config.Settings) int` with `Check.Cost`), Spec 1 (`CleanName`, `ErrQuota`), Spec 3
(`Kind.Found`, for the reported-port line) and Spec 15 (candidate evidence, for the candidate
roots of behaviour 4). **Owns for Spec 14:** the `reported_port` kind, the `confirmed` notion,
`run.Noter`.

## Decisions

- **Shodan's ports are a kind of their own**, `reported_port` (key `ip:port`; `ip`, `port`,
  `banner`, `last_seen`), shown by the same port-eligibility rule as `open_port`. Recon's own
  handshakes stay in `open_port`. Nothing that decides contact reads `reported_port`: the probe's
  detection checks and the egress policy use `open_port` and the configured port list only.
- **`shodan` (netblock search)** also emits `reported_port` for each TCP match, and a
  `shodan_netblock` record (`truncated`) per search. The check key is unchanged, so existing
  engagements gain ports only with `--redo shodan`.
- **`shodan-host`** (`internal/stages/shodan/host.go`) yields, in address order, each
  port-eligible address that is outside every in-scope netblock, or inside one whose
  `shodan_netblock` is truncated and for which no `reported_port` from the `shodan` stage exists.
  It is `Budgeted` by `shodan.max_hosts` (default 500, minimum 1): `Budget` returns the setting,
  and each check is keyed by its address and has `Cost` 1. A 404 completes with nothing.
  TCP services become `reported_port`; UDP is dropped; hostnames under an in-scope root become
  `hostname` and `ip_hostname`, others become a `root` candidate (registrable domain).
- **Candidate evidence.** The check key is the address and carries no setting, so the default
  evidence (the stage name and the check key) is right and the stage needs no `Evidencer`.
  `shodan-host` joins the family table in `internal/candidates` as passive DNS, beside `shodan`
  and `shodan-dns`. A source the table does not list is a family of its own, so without the entry
  Shodan agreeing with Shodan would count as two families and raise a candidate's confidence.
- **Closed versus silent** (decided with the user: one extra handshake). The ports stage records
  the outcome only for ports Shodan reported, as `port_check` (`result`: `closed` or `silent`):
  - a port check that has not run yet carries `reported` in its input and records the outcome
    itself, so no extra handshake is made;
  - a port check that completed before the report existed is redone once under the key
    `<ip>:<port>|reported`, yielded only while there is no current `open_port` and no
    `port_check` for that address and port. This needs `View.Done(key)`, a read of the stage's
    completed set the runner already holds.
  The recheck is only for ports on the configured list at port-eligible addresses.
- **`open-ports.csv`** merges the kinds by key: `source` (`recon`, `shodan`, `recon;shodan`),
  `confirmed` (`yes` when recon completed a handshake), `shodan_last_seen`; recon's banner wins.
- **A rejected port is hidden by the showing rule, not by the file.** The store's `current` only
  means "has an observation", so the closed set (`port_check` with `closed`) goes into
  `inventory.Data` and `reported_port` is shown while its address is port-eligible and the port is
  not in that set. The counts, the findings, Spec 20 and Spec 21 then agree; `open-ports.csv`
  still lists the row, with `current` false.
- **Findings**: a risky port known only from `reported_port` (and not closed) is the same
  `ports|risky-port|<ip:port>` finding at one severity step lower with `confirmed: no`; when
  `open_port` appears the same key is re-derived at full severity. `deriveFindings` emits a
  `found` event when a current finding's severity rises, which is the new `+` line. (Findings keep
  the runner's own found-line code: `kinds` cannot import `findings`.)
- **Summary**: `open_port`'s category becomes `open ports (confirmed)`; the runner adds
  `open ports (third-party reported)` (reported, shown, not confirmed, not closed) and
  `unconfirmed_risky_ports`, printed as `N risky ports reported by Shodan, unconfirmed`. Stages may
  add summary lines through `run.Noter.Notes(View) []string`; `shodan` uses it for truncated
  searches. Deferred lookups need no code here: the runner's `Deferred to the next run` block
  shows the deferred cost beside `shodan-host`, which is a number of addresses, and the README
  names that unit.

## Changes

- `internal/kinds/reportedport.go` (`reported_port`, `shodan_netblock`, `port_check`).
- `internal/stages/shodan/shodan.go`, `host.go`. `internal/stages/ports/ports.go`: `reported`
  input, recheck key, `port_check`. `internal/run/stage.go`: `View.Done`, `Noter`.
- `internal/run/runner.go`: severity-raise event, summary counts and notes.
- `internal/output/ports.go` (moved from `output.go`). `internal/findings/findings.go`,
  `records.go` (`confirmed` column), `table.go`. `internal/config/config.go`: `shodan.max_hosts`.
- `internal/candidates/candidates.go`: `shodan-host` in the family table, as passive DNS.
- `README.md`: passive-boundary text, columns, the `--redo shodan` and `--redo shodan-host` notes,
  `shodan-host` in the passive DNS list of `sources` values, the unit of the deferred number.

## Tests

`internal/cli/shodan_host_test.go`:

- `--passive` with a key fills `open-ports.csv` and `risk-ports.csv` (low, `confirmed: no`); the
  cap defers the rest in address order and the summary says how many; a 404 completes.
- Addresses a complete netblock search returned are not looked up; those missed by a truncated
  search are, and the summary notes the truncation.
- **Canary tests:** a Shodan port outside the configured list is shown unconfirmed and never
  dialled; a Shodan port does not create a probe check.
- Passive then active: one handshake per port; open raises the finding with a new `+` line and
  `confirmed: yes`; a rejection marks the row not current; silence leaves it unconfirmed.
- Active then Shodan: exactly one extra handshake per reported port without an open record, then
  none on later runs.
- A closed Shodan-only port is absent from the counts and `risk-ports.csv`, and its
  `open-ports.csv` row is not current.
- Banner cut to one line or 256 characters and sanitised; UDP not recorded; out-of-root hostnames
  are candidate roots; the split open-port counts in console and `--json`.
- A candidate root that `shodan` and `shodan-host` both report, and nothing else, has one family
  and is `low`.

## To verify while building

Whether `shodan/host/<ip>` costs query credits under Shodan's current terms (behaviour 8); the
README sentence is written from that answer.

## Carried from built specs

Follow-ups and limits of the specs already built that bear on this one.

- **Budget rules (Spec 6).** The first pending check of a run is always sent, and a budget below
  1 counts as 1. A lookup that fails still spends its share of the budget, so a run with many
  failures looks up fewer than `shodan.max_hosts` addresses.
- **A 402 from Shodan is an ordinary failed check (Spec 2).** `httpsrc.Get` aborts a keyed stage
  on a 401, 403 or 429 only. Behaviour 7 keeps that for the netblock search. If the check under
  "To verify while building" finds that host lookups do cost credits, make a 402 from
  `shodan-host` wrap `run.ErrAbortStage`, so one spent balance does not fail every remaining
  address.
- **Truncation (Spec 2).** The `shodan` stage has no truncation warning today: it stops at its
  page constant, or once it has read `total` matches. Set `truncated` by that same test (the page
  cap was reached with fewer than `total` matches read), which is the rule Censys and `shodan-dns`
  use. Do not add another rule.
- **The check key does not carry the scope (Specs 2 and 3)**, as for `shodan-dns` and `dnsroot`.
  A hostname under a root the user promotes later was recorded only as that candidate root, so it
  becomes a hostname only after `--redo shodan-host`. Putting the scope in the key would repeat
  every lookup on every scope change. The README's `--redo shodan-host` note says so.
- **`Kind` is not comparable (Spec 3).** It holds `Found`. Compare `Name()`; never compare two
  `kinds.Named` values with `==` or use one as a map key.
- **Hostname cleaning (Spec 1).** `httpsrc.CleanName` strips `*.` before it validates. The
  `shodan` stage uses `input.NormaliseHost` today. Use `CleanName` in the new stage and leave the
  old call alone: the hostname helpers are merged in one change after Specs 4, 10, 13 and 17.
- **Console text (Spec 22).** If Spec 22 has merged, the severity-raise `+` line goes through its
  log formatter and is asserted on stderr. If not, assert it on stdout.

## Out of scope

Shodan vulnerability data; UDP; using Shodan ports to widen the port list.
