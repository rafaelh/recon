# Spec 4 of 6: recon (Go) — Open ports

## Goal

Find which common TCP services the target's own IPs expose, connecting only as any client would.
Depends on Specs 1 and 2. Not run in passive-only mode.

## Behaviours

1. Each IP eligible under Spec 2.9 receives a completed TCP handshake to each port in a configurable
   list (default: about the top 100 TCP ports), IPv4 and IPv6 alike.
2. Open ports are recorded with any banner the service sends unprompted. Closed or filtered ports are
   recorded as checked so they are not retried.
3. Open ports that speak HTTP(S) are passed to web service probing (Spec 3.1/3.2).

# Design

## Decisions

| # | Decision | Answer | Rationale |
|---|----------|--------|-----------|
| D1 | Stage | New `Target` stage `ports` in `internal/stages/ports`, registered in `cli.defaultStages()` after `crawl`. Passive mode, the ack (Spec 1 B14) and the netblock guard (Spec 1 B15) are handled by the existing gates. With an empty port list, `Configured` returns not-configured (`no ports`) | Placing it after the web stages means hostname probing on 80/443 doesn't wait for a sweep that can take hours. Any pass that runs checks is followed by another, so httpprobe still detects HTTP on the open ports in pass 2 (B3). This replaces Spec 3 D1's "after Spec 4's port stage" |
| D2 | Addresses (B1) | **Candidates:** every address of each in-scope IPv4 netblock (masked, all addresses, as `rdns` does), plus every `ip` record's address (IPv4 or IPv6) that is not inside an in-scope IPv4 netblock.<br>**Filter:** the new `inventory.(*Inventory).PortEligible(a, sc)` = `sc.PortEligible(a, Shared(a), OwnerKnown(a, sc))`, exposed as `View.PortEligible(a)`. `IPRows` switches to it.<br>**Build once:** the eligible list is built once per `Checks()` call.<br>**Unknown owner:** such an address is not yielded, and `View.Warn` reports how many were skipped this way | Spec 2 D18 has one eligibility function, so the sweep, egress and ips.csv cannot disagree. Every hostname-resolved address has an `ip` record (resolve emits both in one check). Found IPv6 addresses inside in-scope netblocks arrive the same way (Spec 2 B7). An unknown-owner address is checked once its owner is known instead of being completed as refused. The warning separates a Cymru outage from "nothing open" |
| D3 | Check key | `netip.AddrPortFrom(a.Unmap(), p).String()` (IPv6 bracketed): one check per address and port in `Settings.Ports` | Spec 1 B6 and B9. Adding a port yields only the new checks. It is the same string as the `open_port` key (Spec 3 D3) |
| D4 | Order | Port-major: for each port, for each eligible address | Workers take checks in iterator order from an unbuffered channel, and the TCP limiter is per IP (5/s, burst 1). Address-major order would serialise every worker on one host |
| D5 | Run (B2) | `TargetTCP.Connect`. **`Open`:** one `open_port` observation with key = the check key and attrs `ip`, `port`, `banner` (D6). **`Closed` and `Filtered`:** no observation; the check completes. **`Refused`:** returned as an error (transient, counted, warned with `--verbose`), not completed. **Other errors:** transient | B2: the completed check is the "recorded as checked" state. `Refused` should be unreachable, because checks are pre-filtered by the same Scope and inventory the Policy is built from. Completing it would silently and permanently skip an address that later becomes eligible |
| D6 | Banner encoding | `strconv.Quote(string(b))` with the outer quotes trimmed, so it is reversible with `strconv.Unquote`. Egress read semantics are unchanged: one `Read` of up to 1024 bytes within `BannerWait` | Lossless for binary greetings such as MySQL's. Non-empty iff a byte arrived, so Spec 3 D3 keeps HTTP-probing only silent ports. Printable text stays readable |
| D7 | Key is authoritative | Attrs round-trip through JSON, so `port` comes back as float64. Readers take the IP and port from the key, through `View.OpenPorts()` or the same `netip.ParseAddrPort` | Avoids type assertions on attrs in output and Spec 5 |
| D8 | (user) Workers | New setting `port_concurrency`, flag `--port-concurrency`, default 100, validated > 0, shown in help. Optional interface `run.WorkerCounter { Workers(config.Settings) int }`, which `ports` implements. `runStage` uses it when present and `Settings.Concurrency` otherwise. The `--concurrency` help becomes "workers per stage (ports: --port-concurrency)" | A silent port costs the full 5 s connect timeout. At 10 workers a /24 takes about 3.5 h and a /20 about 57 h; at 100 workers about 21 min and about 6 h. The per-IP limiter still bounds each host (Spec 1 B21). It can't be `ports.concurrency` because `ports` is a YAML list key. Raising `--concurrency` for every stage would let slow HTTP hosts build up in-flight requests |
| D9 | (user) Visibility on read | `output.PortVisible(sc, inv, rec)`: an `open_port` is shown only while `inv.PortEligible(addr, sc)` holds for the address in its key. It is used by open-ports.csv rows and, through `output.Visible` for kinds registered with `PortKey` (`open_port`), by `runner.categoryOf` (with `snap.Inv` passed in) and the console found line, so summary totals equal CSV rows. Spec 5's risky-port findings get it by registering their kind with `PortKey`. `View.OpenPorts()` stays unfiltered | (user) A reassigned cloud IP's ports, or an address excluded later, are not reported as the target's (Spec 1 D16). httpprobe already chooses only in-scope names or IPs and egress refuses the rest, so filtering its input would be redundant and would break Spec 3's fixtures |
| D10 | (user) Default port list | Add 1521, 6379, 9200, 11211 and 27017 to the default `ports` list (105 ports, still "about the top 100"). `risky_ports` is unchanged | (user) Every default risky port is scanned by default, so Spec 5 B7 can fire for each of them. There is still one scan list (Spec 1 B12), shown in `--help`. A custom `--ports` is the user's choice |
| D11 | open-ports.csv | Columns `ip, port, banner, hostnames` (plus current, first_seen, last_seen). `ip` and `port` come from the key. `hostnames` are the same set as the ips.csv `hostnames` for that address. The file is registered in `output.Default()`. Rows are sorted by the writer as strings, like every other CSV | The name was reserved in Spec 1. `csvSafe` already neutralises formulas and control characters in every cell, so a banner such as `+OK` is written as `'+OK` |
| D12 | Unreachable errors in egress | `EPERM` is added to `localFailure`, which makes it transient. For `ENETUNREACH`, `EHOSTUNREACH` and `EACCES`, which a local route (none, `unreachable`, `prohibit`) and a remote router can both produce, egress does a route lookup to the same address with a UDP `connect()`, which sends no datagram. If that lookup fails with the same errno, the error is this machine's, so it is transient. Otherwise a remote router answered, and the result is `Filtered`. The dial-error classification becomes a pure function with the route lookup injected, and the HTTP dial uses the same lookup | A local firewall (netfilter OUTPUT, VPN kill switch) returns `EPERM`, and treating that as "filtered" would complete a whole sweep with nothing found. A machine with no IPv6 route would otherwise complete every IPv6 check as filtered and never retry it (B1, "IPv4 and IPv6 alike"). A remote net-unreachable answer also produces `ENETUNREACH`, and that must stay a completed check (B2). The UDP connect is a local routing-table query, not contact with the target (Spec 1 B12) |
| D13 | HTTP handoff (B3) | No new code. Spec 3 D3/D4/D5 already read `View.OpenPorts()`. A silent port gets one detection check (https, then http), and the vhosts follow | The `open_port` contract was fixed in Spec 3 D3 |
| D14 | Console | The existing found line, `open port: <addrport>`. `open_port` is already Printed and counted under `open ports` | Spec 1 B17 |

## Packages and changes

- `internal/stages/ports` (new): the `ports` stage, covering D1–D6. It imports no `net`; it uses `net/netip` only, as `rdns` does.
- `internal/egress/tcp.go`: D12. `EPERM` goes into `localFailure`; for `ENETUNREACH`, `EHOSTUNREACH` and `EACCES`, the route lookup (injected through `Options` for tests), shared with the HTTP dial; the classification becomes a pure function.
- `internal/inventory`: `PortEligible(a, sc)`; `IPRows` uses it.
- `internal/run`:
  - `View.PortEligible(a)`;
  - the optional `WorkerCounter` interface, used by `runStage`;
  - `categoryOf` gains the inventory and calls `output.Visible`, which applies `output.PortVisible` to `PortKey` kinds; so does the found line.
- `internal/output`: `PortVisible`, and `open-ports.csv` (D11) in `Default()`.
- `internal/config`:
  - `port_concurrency` and `--port-concurrency` (default 100, > 0, in help);
  - the five ports added to `top100` (D10), with the doc comment updated;
  - the `--concurrency` help text.
- `internal/cli/cli.go`: `ports.New()` appended after `web.NewCrawl()`.
- Existing tests that assert the default port list, the help text or `TestDefaultRegistry`'s file list are updated.

## Test plan

Integration tests go through `cli.Execute` with:
- loopback TCP listeners mapped by `egress.Options.DialMap`;
- short connect and banner timeouts;
- the loopback fake DNS;
- the existing owner fixtures.

Request counters on the listeners assert what was and wasn't contacted.

| B | Tests |
|---|-------|
| 1 | **Address set:** the addresses checked are exactly the non-excluded addresses of an in-scope /30, plus the `port_eligible=true` rows of ips.csv. The fixture includes a hostname-resolved IP, a shared IP, an unknown-owner IP (skipped, with a warning, then checked on a later run once its owner is known), an excluded CIDR and a wildcard-only name's IP. IPv6 is covered via `::1/128`.<br>**Ports and order:** every port in the list is checked, in port-major order.<br>**Re-runs:** adding a port creates only the new checks.<br>**Workers:** `--port-concurrency` bounds in-flight connects, while another stage is still bounded by `--concurrency`.<br>**Gates:** `--passive` shows `not-configured (passive-only)`. An empty port list shows `not-configured (no ports)`.<br>**Defaults:** the default list contains every default risky port |
| 2 | **Banners:** a port that sends a banner is recorded with it escaped and reversible (CRLF, binary, invalid UTF-8). A silent port is recorded with an empty banner.<br>**Completed checks:** closed and filtered ports complete with no record and get zero connects on the next run.<br>**Redo:** `--redo ports` marks a port that has since closed as not-current.<br>**Refused:** a `Refused` result is a failed check, retried next run.<br>**Error classification (egress unit test):** `EPERM` → error; `ENETUNREACH`, `EHOSTUNREACH` or `EACCES` with a route lookup failing the same way → error; the same errors with a successful route lookup → `Filtered` |
| 3 | A real loopback HTTP server on a non-standard listed port produces a `web_service` end to end, which closes Spec 3's verification caveat 1. A port that sends a banner gets zero HTTP requests |
| Visibility | After an exclusion covering an address is added on a re-run, its open port is gone from open-ports.csv and from the summary count. `View.OpenPorts()` still returns it |
| Plumbing | open-ports.csv is sorted (string order), CSV-safe (`+OK` → `'+OK`), has dates, and its row count equals the summary's `open ports`. The boundary test still passes |

## Spec amendments made

- **B1 (default list):** the default is the nmap top 100 plus the five default risky ports outside it (105 ports).
- **B3 (timing):** open ports are passed to web probing in the pass after they are found, not the same pass.
- **Spec 3 D1:** `ports` runs after `crawl`, not before `httpprobe`.

## Out of scope for Spec 4

- Risky-port findings (Spec 5 B7, which must use `output.PortVisible`), UDP, and service or version fingerprinting beyond the unprompted banner.
- A configurable connect timeout.
- Known limitations:
  - **Banners:** only the first `Read` is kept, so a multi-segment banner (for example a multi-line FTP `220-`) is truncated.
  - **Memory:** the runner holds every check key, so memory grows with very large approved sweeps (about 6.5M keys for a /16).
  - **Removed ports:** an `open_port` on a port later removed from `--ports` stays current. Its httpprobe detection check is refused and completed (Spec 3 D7), so after the port is added back, `--redo httpprobe` is needed.
  - **Redo during an owner outage:** `--redo ports` during an owner-lookup outage doesn't yield unknown-owner addresses, so their ports are marked not-current. They come back on a later run, because the redo deleted their completions.
  - **Local broadcast:** a TCP connect to the broadcast address of a directly attached subnet fails with `ENETUNREACH`, and the route lookup decides it as `Filtered`.
  - **Route lookup end to end:** the ENETUNREACH decision is tested on the pure classifier with an injected lookup, and the default UDP lookup only against loopback. No test makes the kernel return ENETUNREACH through `Connect`, and none asserts that the lookup sends no datagram.
  - **Repeated warning:** the "owner is unknown" warning is issued each time `Checks` is called, so once per pass, not once per run.

# Implementation (Develop)

**How.** New stage `internal/stages/ports` (Target, imports no `net`) registered last in `cli.defaultStages()`.
- `Checks` builds the eligible list once (D2) and yields port-major (D4) with the key from D3.
- `Run` maps `Open` to an `open_port` observation with a quoted-and-trimmed banner (D6). `Closed` and `Filtered` complete with nothing found. `Refused` and errors are transient (D5).
- `Workers` returns `Settings.PortConcurrency`. `run.WorkerCounter` is read by `runStage` (D8).
- `inventory.PortEligible` is now the single decision behind `IPRows`, `View.PortEligible` and `output.PortVisible` (D2, D9).
- `categoryOf` and the found line take the inventory and apply `output.Visible` (`PortVisible` for the `PortKey` kind `open_port`), so summary counts equal CSV rows.
- `open-ports.csv` is registered last in `output.Default()` (D11).
- `egress/tcp.go`: `classifyDial` is a pure function, with `EPERM` added to `localFailure` and `Options.RouteLookup` (default a UDP `connect()`) deciding `ENETUNREACH`, `EHOSTUNREACH` and `EACCES` for TCP and HTTP dials (D12).
- `config`: five ports added to the default list (105), `port_concurrency` / `--port-concurrency` (default 100, > 0), and the `--concurrency` help text (D8, D10).

**Tests.**

| B | Test(s) |
|---|---------|
| 1 | `TestPortsB1_AddressSet` (netblock, exclusion, shared, wildcard-only, IPv6, ips.csv agreement, canary listeners); `_UnknownOwnerSkippedThenChecked`; `_IPv6`; `_PortMajorOrder`; `_AddedPortChecksOnlyTheNewPort`; `_WorkerBounds`; `_Gates`; config `TestDefaultPortsCoverRiskyPorts`, `TestPortConcurrency`, `TestPortConcurrencyHelp`; `TestPortsD1_RegisteredAfterCrawl`, `TestPortsD8_Help`, `TestPortsD8_WorkerCounter`; inventory `TestPortEligibleMatchesIPRows` |
| 2 | `TestPortsB2_Banners`, `_CompletedChecksAreNotRetried`, `_RedoMarksClosedPortNotCurrent`, `_RefusedIsAFailedCheckRetried`; egress `TestClassifyDial`, `TestClassifyDialLooksUpTheSameAddress`, `TestUDPRouteLoopback` |
| 3 | `TestPortsB3_HTTPOnANonStandardPortIsProbed` (real loopback HTTP server through `httpprobe`; a banner port gets only the port check) |
| Visibility | `TestPortsD9_ExclusionHidesAnOpenPortButNotTheView`; output `TestPortVisible` |
| Plumbing | `TestPortsPlumbing_OpenPortsCSV`, `TestPortsD14_FoundLine`; output `TestDefaultRegistry`. The import-boundary test covers the new package unchanged. |

Mutation checks (address-major order, unfiltered count, silent `Refused`, unknown-owner not held back, `Workers` ignored) each fail at least one test.

**Deviations.**
- Added `View.OwnerKnown` (not in the design) so the stage can count unknown-owner skips separately from exclusions and shared addresses.
- `newWorld` (and so `newWeb`) now drops the real `ports` stage from the default registry. Otherwise ~60 existing tests would sweep 105 ports on every eligible address, and only unlisted ports escape `fill()`'s `DialMap`. The Spec 4 tests use `newPorts`, which puts it back after `crawl`.
- `egresstest.DNS` gained `ClearRcode`, to make an owner lookup fail on one run and succeed on the next.
- `TestStageStatesAndFound` expected `open ports: 1` and a found line for an address that is not eligible. It now expects 0 and no found line, which is D9.
- IPv6 is covered twice: `TestPortsB1_IPv6` uses `::1/128` and a real `[::1]` listener (skipped where the machine has no IPv6 loopback), and `TestPortsB1_AddressSet` uses a found address in an in-scope `2001:db8:1::/64`, mapped to IPv4 loopback.

# Verification

**Result: the goal and all three behaviours are met.** `go build`, `go vet` and `go test ./...` pass. Every test listed under Implementation runs, and none is skipped on this machine (the IPv6 loopback test included).

- **B1:** met. The sweep takes every address of the in-scope IPv4 netblocks plus the found `ip` records outside them, and filters them with the single `inventory.PortEligible` decision. The same decision drives `IPRows`, `View.PortEligible` and `output.PortVisible`. Egress's `Policy` is built from the same scope and inventory, so egress, ips.csv and the sweep agree. IPv4 and IPv6 are handled alike. Checks go out port by port. The key is the unmapped `AddrPort`. The default list has 105 ports and includes every default risky port. `--port-concurrency` (default 100, > 0) applies only to `ports`, through `WorkerCounter`.
- **B2:** met. An open port becomes an `open_port` with a reversible quoted banner. A closed or filtered port completes with no record and is `done-previously` on the next run. `Refused` and local failures are transient. The `EPERM` and `ENETUNREACH` (with route lookup) classification matches D12.
- **B3:** met through the existing httpprobe path. An HTTP server on the non-standard port 8080 becomes a `web_service`. A port that sends a banner receives no HTTP bytes. As the spec amendment says, the handoff happens in the next pass.
- **Visibility and plumbing:** open-ports.csv and the summary count both filter through `PortVisible`. `View.OpenPorts()` stays unfiltered.

**Changed during verification:** I fixed the garbled `localFailure` doc comment in `internal/egress/tcp.go`, which had a duplicated clause. I made no code or behaviour changes.

**Caveats** (already in Known limitations, not defects): no test makes the kernel return `ENETUNREACH` through `Connect`. The "no connects on re-run" check for closed and filtered ports is shown by the stage state `done-previously`, not by a per-listener counter.
