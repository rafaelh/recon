# Spec 1 of 6: recon (Go) — CLI, engagement and run model

## Goal

Before or during an engagement, an analyst runs `recon` against the target's domains, organisation
names or netblocks and, using only third-party sources and the kind of contact any member of the
public could make, gets a record of the target's hosts, IPs, web services, URLs and open ports, plus
a severity-ranked list of obvious exposures, shown in the console and recorded in TXT/CSV files.

This spec covers the command-line experience, the engagement workspace, scope, resume behaviour and
the passive boundary that every later spec relies on. The CLI is built with cobra, viper and
lipgloss. The port is built in this repository; Specs 2–5 add discovery stages and Spec 6 removes
the Python version.

## Definitions

- **In-scope root:** a root domain given as an input, or a candidate later promoted by passing it as
  an input.
- **In-scope netblock:** a CIDR given as an input, or a netblock of an ASN given as an input.
- **In-scope hostname:** a hostname that equals or is under an in-scope root.
- **In-scope IP:** an IP inside an in-scope netblock. IPs that in-scope hostnames resolve to are
  recorded with their owner but do not by themselves bring new hostnames into scope.
- **Candidate:** a root domain, hostname or netblock discovered during a run that is not in scope.
  Candidates are recorded but never contacted.
- **Check:** one unit of work — a target plus what was checked (e.g. host+port, service+path,
  root+source).
- **Target-owned system:** any system at an in-scope hostname or IP.

## Behaviours

### Inputs and engagement

1. `recon` accepts root domains as arguments, a file of domains, organisation names, ASNs/CIDRs, and
   an exclusion list of hostnames, wildcards and CIDRs.
2. Each run writes to one engagement directory, named by flag or derived from the first input
   (sanitised to a safe directory name; `--help` states that naming is order-sensitive).
3. An engagement remembers its scope and its exclusions. Additional inputs or exclusions on a re-run
   are added; running with only the engagement name resumes with the stored scope and exclusions;
   nothing is removed by omission.
4. If the engagement directory exists but is not a `recon` engagement (e.g. output from the Python
   version), the run refuses to start and names the directory.
5. Settings (API keys, port list, risky-port list, sensitive-path list, wordlist, concurrency, rate
   limits, crawl limits, output dir) come from a config file, environment variables or flags; flags
   override env, env overrides file. API keys come from the config file or environment only, never
   flags. `--help` shows the default value of every setting and the
   config file's default location.

### Resume and re-runs

6. A re-run performs only checks with no recorded result, including new checks introduced by config
   changes (e.g. a port added to the list).
7. After an interruption (Ctrl-C or crash), no check whose result was recorded is repeated, checks in
   flight are redone, and no output file is left with a truncated line or row. A lock left by a
   crashed or killed run does not prevent the next run.
8. A check that fails transiently (timeout, rate-limited, source unavailable) is not recorded as
   done. It is not retried again in the same run, is retried on every subsequent run, and is counted
   as failed in stage status and the summary. A closed or filtered port is a completed check, not a
   failure.
9. Each record has a natural key (e.g. name+type+value for DNS, URL for web services, IP+port for
   ports). Re-observing a record updates its attributes and last-seen date and keeps its first-seen
   date. Every CSV includes first-seen and last-seen dates.
10. `--redo <stage>` re-performs every check of one stage, applying behaviour 9. Records that stage no
    longer observes are kept but marked not-current; the summary counts only current records. The
    accepted stage names are listed in `--help`.
11. Any new in-scope hostname or IP found by any stage (certificate SANs, reverse DNS, crawled or
    archived URLs, redirects, permutations) goes through every applicable stage in the same run. A
    run ends when no stage has unchecked items other than transient failures already tried this run.
    Out-of-scope names found this way are recorded as candidates.

### Passive boundary and safety

12. Requests to target-owned systems are limited to: DNS lookups; completed TCP handshakes to the
    configured port list, reading only what the service sends unprompted; HTTP(S) GET/HEAD to
    in-scope, non-excluded hosts, their same-host crawled links and the configured sensitive-path
    list. The tool never sends credentials, submits forms, uses other HTTP methods, places payloads
    in parameters or headers, requests paths beyond those listed, or attempts zone transfers. UDP is
    out of scope.
13. By default all stages run. A passive-only flag restricts the run to third-party sources: CT logs,
    web archives, public DNS resolvers (including permutation resolution), RDAP/WHOIS, BGP data,
    keyed APIs, and cloud storage provider endpoints. HTTP probing, crawling, port checks, sensitive
    paths and HTTP-based takeover fingerprinting are shown as not-configured; takeover checks use DNS
    evidence only.
14. Before any stage that contacts target-owned systems, the run requires an explicit acknowledgement
    that the operator is authorised. It is asked once per engagement (including when scope grows
    later) and remembered. With a terminal it can be given by prompt or flag; with no terminal (or in
    JSON mode) there is no prompt and only the flag counts. Without it, those stages are shown as
    not-configured.
15. If in-scope IPv4 netblocks (including those expanded from ASN inputs) exceed a configurable
    address count, the run stops before contacting any address in them, shows the total, and
    proceeds only with an explicit override flag; the override is remembered with the engagement.
16. A hostname is excluded if it matches the exclusion list or any address it resolves to is inside an
    excluded CIDR. Excluded names may be resolved via public resolvers, but nothing at their addresses
    is contacted by any stage, except that on addresses recognised as shared provider infrastructure
    (Spec 2.8) only the excluded hostname itself is never requested. Excluded items are recorded as
    excluded.

### Console and output

17. During a run the console shows each stage's state — running, done-previously, not-configured
    (with the reason: no key, passive-only, no authorisation), failed (only if none of its checks
    could run), or done (with a failed-check count) — plus counts, and prints each new host, web
    service, open port and risk finding as found. URLs are counted, not printed.
18. At the end a styled summary shows totals per category (current records only), failed-check
    counts, and lists every high- and medium-severity risk finding individually.
19. A JSON mode emits one JSON event per line on stdout with no styling; styling is also off
    automatically when stdout is not a terminal.
20. The engagement directory contains a separate output for each of: scope, candidates, excluded,
    subdomains, resolutions, unresolved names, wildcard-excluded names, IPs with owner,
    provider-labelled hosts, web services, URLs, open ports, email posture per root, unattributed
    storage, and each risk category. Plain lists are `.txt`, records with attributes are `.csv`;
    rows are sorted so diffs between runs are stable.
21. Concurrency and per-host request rate have conservative defaults and are configurable.

### Validation and errors

22. Invalid inputs (malformed domain, public suffix such as `co.uk`, bad CIDR/ASN, malformed
    exclusion entry, invalid config value, unknown `--redo` stage) are rejected before any network
    activity with a message naming the bad value.
23. The process exits 0 on completion and non-zero on fatal errors. A second simultaneous run against
    the same engagement refuses to start.
24. API keys never appear in console output, JSON output, or files in the engagement directory.

## Out of scope

- A quantified run-time target.
- An exit code signalling that high-severity findings exist.

# Design

## Decisions

| # | Decision | Answer | Rationale |
|---|----------|--------|-----------|
| D1 | Repo layout | `go.mod` at repo root, module `github.com/rafaelh/recon`, `cmd/recon/main.go`, packages under `internal/` | Idiomatic. No collision with Python `pkg/recon`, which Spec 6 removes. |
| D2 | CLI shape | One cobra root command, `recon [domain...] [flags]`, with no subcommands | The spec describes a single command. Resume is `recon -e <name>` with no inputs. |
| D3 | State store | SQLite via `modernc.org/sqlite` (pure Go) at `<engagement>/.recon/state.db`, WAL mode, `synchronous=NORMAL` | (user) Transactions give crash safety (B7) and UNIQUE keys give upserts (B9). Without cgo, Spec 6 still gets a single binary. |
| D4 | Record model | Generic `records` and `observations` tables. Later specs declare kinds, natural keys and columns without migrations | (user) Specs 2–5 add kinds cheaply, and first-seen, last-seen and current logic is written once. |
| D5 | Run model | Repeated passes. Stages run one after another in a fixed registry order, each with a worker pool over its pending checks. Passes repeat until a pass executes zero checks | (user) Deterministic and testable. Maps directly to B11's termination rule and B17's states. |
| D6 | Console | lipgloss-styled line log. `--json` emits the same events unstyled | (user) Works in scrollback: one event stream, two renderers. |
| D7 | ASN expansion | Spec 1 ships one real stage, `asn`, which uses RIPEstat `announced-prefixes` (keyless) | (user) The scope definition and B15 work end-to-end in Spec 1. |
| D8 | API keys | Config file or `RECON_KEYS_<SOURCE>` env only. B5 amended | (user) Keeps keys out of shell history and `ps`. |
| D9 | Shared-infra exclusion | On addresses labelled as shared provider infrastructure, exclusion is by name. Elsewhere it is by address. B16 amended | (user) The literal reading would block every in-scope host behind a CDN edge that an excluded name shares. |
| D10 | Config file | YAML at `$XDG_CONFIG_HOME/recon/config.yaml` (default `~/.config/recon/config.yaml`), overridable with `--config`. Env prefix `RECON_`. Unknown keys are rejected (`UnmarshalExact`) | Viper's best-supported format. Sensitive paths with signatures read well in YAML. Strict keys catch typos (B22). |
| D11 | Engagement marker and lock | Order of operations: `mkdir -p <dir>`, then if `<dir>/.recon/` is absent and `<dir>` is non-empty, refuse and name the dir (B4). Then `mkdir .recon`, take `flock(LOCK_EX\|LOCK_NB)` on `.recon/lock`, and open or initialise `state.db`, setting `PRAGMA application_id`. A `.recon/` that has a lock but no valid DB is adopted | The kernel releases a flock on crash or kill -9 (B7). A second live run refuses (B23). A crash during creation can't brick the dir. macOS and Linux only (Spec 6). |
| D12 | Output files | Rendered from the store to `.recon/tmp/<name>` and `rename`d into the engagement dir after every pass and on exit, including interrupt. `.recon/tmp` is swept at startup | Rows are always sorted (B20). No truncated file is ever visible, and no partial temp file sits beside the outputs (B7). |
| D13 | Passive boundary | All network I/O goes through `internal/egress`, which returns its own types (no `net/http` types leak). A test fails if any first-party non-test package outside `internal/egress` directly imports `net`, `net/http`, `crypto/tls`, `syscall`, `os/exec` or `github.com/miekg/dns` | A single choke point is the only way to make B12 verifiable. |
| D14 | Check outcomes | Egress classifies negative results (closed or filtered port, no HTTP service, NXDOMAIN or NODATA, policy refusal) as **results**. Stages record these as completed checks. A Go `error` from a stage means a transient failure: not recorded, not retried this run, retried next run, counted | B8. The stage can tell the cases apart without importing `net`. |
| D15 | Currency and redo | Per-check provenance in `observations`. A record is current iff it has at least one observation. Attributes live on observations | A redo un-currents only records that no stage still observes. One stage can't overwrite another's attributes. Interrupted redo resumes correctly. |
| D16 | Scope classification | Computed from stored inputs plus the store when Scope is built, never stored on records | Promoting a candidate (passing it as an input) re-classifies existing names immediately. |
| D17 | Exit codes | 0 for completion, including with failed checks or not-configured stages. 1 for a fatal runtime error, a held lock, or a non-recon dir. 2 for invalid input or config (always before network). 3 when the netblock limit is exceeded without approval. 130 when interrupted (SIGINT, SIGTERM or SIGHUP) | B23. Code 2 is reserved for validation failures, so it guarantees nothing was contacted. |
| D18 | Defaults | See the table below | Conservative (B21). `output_dir` `.` matches the Python tool. |
| D19 | Scale target | Default limits: 4,096 IPv4 addresses × 100 ports ≈ 410k checks per engagement. `Checks()` is an iterator, and the writer batches commits | Keeps memory flat and avoids one fsync per closed port. |

### Settings and defaults

| Key | Flag | Default |
|---|---|---|
| `keys.<source>` | (none, file or env only) | unset |
| `ports` | `--ports` | top-100 TCP list (help shows it with ranges compressed) |
| `risky_ports` | `--risky-ports` | 21,23,445,1433,1521,3306,3389,5432,5900,6379,9200,11211,27017 |
| `sensitive_paths` | `--sensitive-paths` (YAML file path) | `built-in (N entries)`; the embedded list is empty until Spec 5 |
| `wordlist` | `--wordlist` (file path) | `built-in (N entries)`; the embedded list is empty until Spec 2 |
| `concurrency` | `--concurrency` | 10 workers per stage |
| `rate.per_host` | `--rate-per-host` | 5/s per dialled target IP (HTTP requests and TCP connects), burst 1 |
| `rate.per_source` | `--rate-per-source` | 1/s per third-party source |
| `rate.dns` | `--rate-dns` | 50 queries/s in total across public resolvers |
| `crawl.max_depth` | `--crawl-depth` | 2 |
| `crawl.max_pages` | `--crawl-pages` | 100 |
| `output_dir` | `--output-dir` | `.` |
| `netblock_limit` | `--netblock-limit` | 4096 IPv4 addresses |

Env vars are `RECON_<UPPER_SNAKE>`, with `.` replaced by `_`. Validation names the offending key and value. Examples:
- a port outside 1–65535;
- a concurrency or rate ≤ 0;
- an unreadable file;
- an unknown key.

## Packages

- `cmd/recon`: `main` calls `cli.Execute(ctx, os.Args[1:], cli.DefaultDeps())` and exits with the returned code.
- `internal/cli` covers:
  - **Command setup:** the cobra root command (`SilenceUsage`, `SilenceErrors`) with flags bound to viper.
  - **Validation:** inputs and config are validated before any network client is built (B22).
  - **Help:** the help text for B2, B5 and B10.
  - **Ack:** the authorisation prompt (B14).
  - **Exit codes:** errors map to codes (D17).
  - **Signals:** SIGINT, SIGTERM and SIGHUP cancel the run context; a second signal exits immediately.

  `Deps` carries the stage list, `egress.Options`, stdin/stdout/stderr, `isTerminal` funcs and a clock, so tests run in-process with fakes.
- `internal/config`: the `Settings` struct with defaults, viper loading (file < env < flag), validation, and built-in lists via `embed`. `Secret` is a string type whose `String`, `GoString`, `Format` and `MarshalJSON` return `****`.
- `internal/input`: parses and validates inputs.
  - **Domains:** lowercased, IDNA to punycode, label syntax checked. Public suffixes (`golang.org/x/net/publicsuffix`) and IP literals are rejected.
  - **Orgs:** must be non-empty after trimming.
  - **ASNs:** `AS123` or `123`, in the range 1..4294967295.
  - **CIDRs:** `netip.ParsePrefix`, then `Masked()`.
  - **Exclusions:**
    - `host.example.com` matches that exact name;
    - `*.dev.example.com` matches names strictly below `dev.example.com`, not `dev.example.com` itself;
    - a CIDR excludes addresses inside it.

  It also derives the engagement name and validates `-e`.
- `internal/scope`: `Scope`, built from the inputs, the `asn` stage's current observations, and resolutions from the store. Its functions are pure:
  - `ClassifyHost(host) → InScope | Candidate | Excluded(reason)`
  - `InScopeIP(addr)`
  - `ExcludedAddr(addr) → (bool, reason)`, which covers excluded CIDRs and addresses of excluded hostnames
  - `IPv4AddressCount()`, which accounts for overlapping netblocks
- `internal/engagement`: opening and creating the dir, the marker, and the lock (D11). Merges new inputs and exclusions into `inputs` as a union (B3). Holds the ack and the netblock approval in `meta`.
- `internal/store`: SQLite, migrations via `PRAGMA user_version`, and a single writer goroutine that commits completions in batches (up to 200 or 100 ms per transaction). Redaction happens here (see Secrets).
- `internal/run`: the `Stage` contract, the runner, gating, the netblock guard, redo, the per-run failed set, and `Policy` construction.
- `internal/egress`: `Resolver`, `TargetHTTP`, `TargetTCP`, `ThirdPartyHTTP`, rate limiters, and policy enforcement.
- `internal/report`: event types, the console renderer (lipgloss), the JSON renderer, the summary, and sanitisation.
- `internal/output`: the output file registry and atomic TXT/CSV rendering.
- `internal/stages/asn`: the `asn` stage.

## Store schema

```
meta(key TEXT PK, value TEXT)          -- ack_at, netblock_approved (address count), redo:<stage>, created_at
inputs(kind TEXT, value TEXT, added_at TEXT, PK(kind,value))         -- root|org|asn|cidr|exclude
checks(stage TEXT, key TEXT, completed_at TEXT, PK(stage,key))
records(kind TEXT, key TEXT, first_seen TEXT, last_seen TEXT, current INT, PK(kind,key))
observations(kind TEXT, key TEXT, stage TEXT, check_key TEXT, attrs TEXT /*JSON*/, seen TEXT,
             PK(kind,key,stage,check_key))
failures(stage TEXT, key TEXT, error TEXT, at TEXT, PK(stage,key))   -- last failure, redacted; deleted on success
```

Dates are UTC `YYYY-MM-DD` from the injected clock. Completing check C of stage S with observations O happens in one transaction (batched with others):
1. Upsert each record: insert it with `first_seen = last_seen = today`, or set `last_seen = today` and keep `first_seen`.
2. Upsert the observation rows `(kind, key, S, C)` with their attrs and `seen = today`.
3. Delete the observation rows for `(S, C)` that are not in O.
4. Set `current = EXISTS(observation)` on every record touched in step 1 or step 3.
5. Insert or replace the `checks` row, and delete any `failures` row for `(S, C)`.

A record's rendered attrs merge its current observations, with later stages in registry order winning per field. A CSV column can instead be declared `per-stage` (for example `found_by`, which is the sorted, joined list of observing stages).

### Redo (B10)

`--redo S` runs one transaction at the start of the run. It deletes every `checks` row for S and sets `meta['redo:S']`. The run then proceeds normally, and re-performed checks replace their own observations.

The marker is cleared when stage S ends a pass with no pending checks other than ones that failed this run. At that point, the run first deletes S's observations whose `check_key` is no longer produced by `S.Checks()`; these are orphaned checks, such as an IP that is no longer in scope.

A failed check keeps its old observations, so its records stay current. An interrupted redo leaves the marker and the unchecked checks in place, so the next run finishes the redo (B7).

Clarification of B10: a record goes not-current only when no stage still observes it. A subdomain found by both CT and an archive source stays current if a redo of the CT stage drops it.

## Stage contract (`internal/run`)

```go
type Contact int // ThirdParty | Target

type Stage interface {
    Name() string                                      // listed in --help, accepted by --redo
    Contact() Contact
    Sources() []string                                 // third-party host patterns, e.g. "stat.ripe.net", "*.s3.amazonaws.com"
    Configured(Env) (ok bool, reason string)           // e.g. "no key"
    Checks(ctx context.Context, v View) iter.Seq2[Check, error]
    Run(ctx context.Context, c Check, e egress.Clients) ([]Observation, error)
}
type Check struct { Key string; Input any }
type Observation struct { Kind, Key string; Attrs map[string]any }

var ErrAbortStage = errors.New("abort stage") // wrap: fail this and all remaining checks of the stage for this run without sending them
```

Contract rules, which are documented on the interface:
- **`Check.Key`** must encode every input and setting that changes the work done (for example `203.0.113.5:8080`, or `https://a.example.com|depth=2|pages=100`). Changing such a setting then creates new checks (B6).
- **Contact** is single-valued. Mixed behaviour is split into separate stages; for example, Spec 5 splits takeover into `takeover-dns` (ThirdParty) and `takeover-http` (Target). `egress.Clients` only carries Target clients to stages whose `Contact()` is Target.
- **Discovered entities** are observations of kind `hostname`, `root` or `netblock`. `scope` classifies them as in scope, candidate or excluded when Scope is built. Each stage gets B11's candidate recording and B16's excluded recording without implementing it.
- **Record kinds** are registered in the kind registry with these properties:
  - natural key;
  - `Printed` (B17: printed as a line when first seen in an engagement): host, web service, open port, finding;
  - `Counted` (URLs);
  - summary category (B18);
  - output file.
- **Findings** are records of kind `finding`, with attrs `category`, `severity` (high, medium or low), `target` and `detail`.
- **`View`** gives read access to the store and the current `Scope`. Typical queries are in-scope hostnames, guard-approved IPs, and records of kind K.

## Runner algorithm

1. **Prepare.** Validate inputs and config with no network access. Open the engagement (D11), merge inputs, apply `--redo`, and sweep `.recon/tmp`.
2. **Ack (B14).** If `--authorised` (alias `--authorized`) is given, store the ack, whether or not `--passive` is set. Otherwise, if the ack is not stored, some stage is Target, the run isn't `--passive`, stdin is a TTY, and `--json` is off, prompt on stderr with `Confirm you are authorised to test this engagement's scope [y/N]`; store the ack on `y`. The ack is never asked again for this engagement, even when scope grows.
3. **Build Scope and apply the guard (B15).** Scope is built at the start of each pass and again after any stage that emitted `netblock` observations. At every build, if `IPv4AddressCount() > max(netblock_limit, meta.netblock_approved)`:
   - with `--allow-large-netblocks`, store `netblock_approved = count` and continue;
   - otherwise print the total, render the outputs, and exit 3.

   No stage after `asn` runs on unapproved netblocks, so third-party per-address sweeps are gated too.
4. **Passes.** For each stage in registry order:
   - **Gate:** a Target stage under `--passive` is not-configured ("passive-only"). A Target stage without an ack is not-configured ("no authorisation"). A stage whose `Configured` returns false is not-configured with that reason.
   - **Pending:** the checks from `Checks()`, minus checks completed in the store, minus checks that failed this run.
   - **Execute:** run the pending checks on a worker pool of `concurrency` workers. Results go to the writer. Errors go to the in-memory failed set, the `failures` table (redacted) and the counters, plus a `warning` event when `--verbose` is on. `ErrAbortStage` fails the stage's remaining pending checks without running them.
   - **Redo sweep:** apply it when the stage's redo marker is set and it has nothing pending.

   After each pass, render the outputs. Stop when a pass executes zero checks (B11).
5. **Finish.** Render the outputs, emit the summary, and exit 0.

### Stage states (B17)

States are evaluated per stage and printed only when they change:

| State | Condition |
|---|---|
| `running` | the stage has pending work |
| `done-previously` | the first pass had no pending checks and the store has ≥1 completed check |
| `not-configured (reason)` | a gate applied |
| `failed` | ≥1 check was attempted this run and all of them failed |
| `done (n checks, m failed)` | none of the above; this includes a stage that has never had a check (`done (0 checks)`) |

### Interrupt

The context is cancelled and workers abandon in-flight checks, which are not committed. The writer commits the completions already queued and flushes. The outputs are rendered, and the process exits 130. A second signal exits immediately; the outputs are still intact because of the rename (D12).

## Egress (`internal/egress`)

The runner builds a `Policy` at every Scope build. It contains the Scope, the ack, the passive flag, the port list, the sensitive-path list, the resolutions of in-scope and excluded hostnames, and the shared-provider label lookup. In Spec 1 that lookup always returns false; Spec 2.8 fills it. Egress consults the `Policy` and never imports the store.

### `Resolver`

- **Transport:** `github.com/miekg/dns` against the fixed public resolver set (1.1.1.1, 8.8.8.8, 9.9.9.9), limited by `rate.dns`. It never reads `/etc/hosts`.
- **API:** `Query(ctx, name, qtype) → (DNSResult{RCode, Answers, CNAMEChain}, error)`. NXDOMAIN, NODATA and SERVFAIL-after-retries are results. A timeout is an `error`.
- **Restrictions:** no AXFR or IXFR API exists.

### `TargetHTTP`

- **Requests:** `Get` and `Head` take a typed request, not a URL:
  - `Root(host, scheme, port)`
  - `SensitivePath(service, index)`, indexed into the configured list
  - `Link(resp, href)`, which can only be built from a fetched `Response` and is checked to be on the same host
  - `Redirect(resp)`

  Archived URLs can't be requested because there is no constructor for them.
- **Request shape:** no cookie jar, no auth, no userinfo, a fixed User-Agent, and no caller headers. Redirects are not followed automatically; stages decide.
- **Policy checks**, on every dial:
  - the ack is present and the run is not passive;
  - the scheme is http or https;
  - the host is in scope and not excluded by name;
  - the port is 80, 443 or in the port list;
  - the address is chosen from vetted resolutions: no address in an excluded CIDR, and no address of an excluded hostname unless the address is labelled shared (D9).

  The connection dials the vetted IP.
- **Result:** `(HTTPResult, error)`. `HTTPResult` is one of:
  - `Response{Status, Header map[string][]string, Body (capped at 1 MiB), Location, PeerCerts, CertVerifyErr}`
  - `NoService{Refused|Timeout|TLSFailed}`
  - `Refused{PolicyReason}`

  TLS verification is skipped for the connection, but the chain is verified separately so that `CertVerifyErr` records an expired or self-signed certificate (Specs 3.3 and 5.8).

### `TargetTCP`

- **API:** `Connect(ctx, addr, port) → (TCPResult, error)`, where `TCPResult` is `Open{Banner []byte}`, `Closed`, `Filtered` or `Refused{PolicyReason}`.
- **Banner:** the banner is read unprompted for up to 3 s. Egress closes the connection itself, so no connection ever reaches a stage and nothing can be written.
- **Policy checks:**
  - the ack is present and the run is not passive;
  - the port is in the port list;
  - the address is an in-scope IP, or an address of an in-scope hostname that is not labelled shared;
  - the address is not excluded (excluded CIDR, or an address of an excluded hostname).

### `ThirdPartyHTTP`

- **Requests:** GET or POST to URLs whose host matches the calling stage's `Sources()`. Anything else is refused. The client also refuses any host that is in scope, a candidate, or excluded.
- **Keys:** attached by the client from `Secret`s.
- **Rate limit:** one limiter per stage source, so all `*.s3.amazonaws.com` traffic shares a single limiter.
- **Body:** capped at 10 MiB.
- **Errors:** scrubbed of key values.

### Policy refusals and rate limits

A `Refused` result is a completed check. The guard also emits an `excluded` observation for an address that triggered an exclusion at dial time, which records it as excluded (B16).

Target limiters are keyed by the dialled IP (`rate.per_host`).

### Test hooks

`egress.Options` can replace:
- the resolver address, with a fake DNS server on loopback;
- per-source base URLs;
- the target dial address map.

Policy logic is unchanged in tests.

## Secrets (B24)

- `config.Secret` never formats its value.
- One `Redactor`, built from the configured key values, is applied at both sinks: the store writer (observation attrs, keys, `failures.error`) and the event emitter (all strings). Every output file is rendered from the store, so it is redacted too.

## Output files (`internal/output`)

A registry entry is `File{Name, Format(txt|csv), Kind or query, Columns}`.
- **TXT** lists current records only, one value per line.
- **CSV** lists all records with the columns `<key cols>,<attr cols>,current,first_seen,last_seen` (B9, B10).
- **Sorting:** rows are sorted by natural key bytes.
- **CSV safety:** written with `encoding/csv`. A cell starting with `=`, `+`, `-`, `@`, tab or CR is prefixed with `'`.
- **Control characters:** removed from every cell.

Spec 1 registers:
- `scope.csv`: type (root, org, asn, cidr, netblock), value, source (`input` or `AS<n>`), first_seen, last_seen.
- `candidates.csv`: type (root, hostname, netblock), value, found_by, current, first_seen, last_seen.
- `excluded.csv`: value, reason (the matched entry, or the CIDR or excluded host plus the address), current, first_seen, last_seen.

Reserved for the owning specs:
- `subdomains.txt`
- `resolutions.csv`
- `unresolved.txt`
- `wildcard-excluded.txt`
- `ips.csv`
- `provider-hosts.csv`
- `web-services.csv`
- `urls.csv`
- `open-ports.csv`
- `email-posture.csv`
- `storage-unattributed.csv`
- `risk-<category>.csv`

## Events and console (`internal/report`)

Every event has `type` and an RFC 3339 `time`. The event types are:
- `run_start`: engagement, scope counts, passive, ack
- `stage`: name, state, reason, checks, failed
- `found`: category, value, severity?
- `count`: category, n
- `warning`
- `error`: fatal message, exit code
- `summary`
- `run_end`: exit code

**Console:**
- Each event renders as one lipgloss-styled line on stdout. Prompts and fatal errors go to stderr.
- Styling is disabled when stdout is not a TTY.
- Control and escape characters are stripped from every value before rendering, so target-supplied banners and titles can't inject terminal escapes.

**JSON** (`--json`): one `json.Marshal`'d object per line on stdout. There are no prompts, no styling, no usage text and no other stdout output. Fatal errors are emitted as `error` events (B19).

**Summary** (B18) shows:
- totals of current records per category;
- failed-check counts per stage;
- every current high- and medium-severity finding, listed individually.

## CLI

- **Inputs:** positional domains, `-d/--domains-file`, `--org`, `--asn`, `--cidr`, `-x/--exclude` and `--exclude-file`. All flags are repeatable, and files have one entry per line, with `#` comments allowed.
- **Run control:** `-e/--engagement`, `--passive`, `--authorised` (alias `--authorized`), `--allow-large-netblocks`, `--redo <stage>`, `--json`, `--verbose` and `--config`.
- **Settings flags:** see the Settings and defaults table.
- **Engagement name (B2):** taken from the first positional domain, else the first line of the domains file, else the first `--org`, else the first `--asn`, else the first `--cidr`. It is lowercased, `/` becomes `_`, characters outside `[a-z0-9._-]` become `-`, runs are collapsed, and the result is trimmed. The name must match `^[a-z0-9][a-z0-9._-]*$`. `-e` is validated against the same pattern.
- **Help:** every flag shows its default. A footer gives:
  - the default config path and the env prefix, including `RECON_KEYS_<SOURCE>`;
  - the stage names accepted by `--redo`;
  - the engagement-name precedence above, with a note that it depends on the order of inputs.

## `asn` stage

- **Contact:** `ThirdParty`. `Sources()` is `stat.ripe.net`.
- **Checks:** one per input ASN, with key `AS<n>`.
- **Request:** `GET https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS<n>&sourceapp=recon`.
- **Errors:** a body `status` other than `ok` is treated as an error (transient).
- **Observations:** a `netblock` for each v4 and v6 prefix, with attr `asn`.
- **Scope:** a netblock is in scope when it is a current observation of the `asn` stage under a check for an input ASN. This never depends on a mutable attr.

## Dependencies

- `github.com/spf13/cobra`
- `github.com/spf13/viper`
- `github.com/charmbracelet/lipgloss`
- `modernc.org/sqlite`
- `github.com/miekg/dns`
- `golang.org/x/net` (`publicsuffix` and `idna`)
- `golang.org/x/time/rate`
- `golang.org/x/term`
- `golang.org/x/sys/unix`

Tests use the standard `testing` package only.

## Test plan

**Test harness:**
- **Integration tests** drive `cli.Execute` in-process with:
  - fake stages;
  - a loopback fake DNS server;
  - `httptest` servers;
  - loopback TCP listeners;
  - an injected clock;
  - a temp output dir.
- **Subprocess tests** re-execute the test binary as `recon` with fake stages, using a `TestMain` switch on an env var.
- **Deterministic crash points** use an env-var fault hook. It pauses at a named point: `render-mid-file`, `in-check-tx`, `after-commit` or `in-flight`. The test then sends kill -9 or SIGINT at that moment.

| B | Tests |
|---|-------|
| 1 | cli: each input form is stored in `inputs`; exclusions are read from the flag and the file; comments and blank lines in files are ignored |
| 2 | input: name precedence and sanitisation table; `-e ../x` is rejected. cli: the engagement dir is created under `output_dir`; help states the name precedence |
| 3 | cli: a second run adds roots and exclusions; `-e name` alone resumes with the stored scope; omitted inputs are kept; a promoted candidate moves from candidates.csv to scope |
| 4 | cli: a non-empty dir without `.recon` is refused with exit 1 and a message naming the dir; an empty dir is adopted; a `.recon/` with a lock but no DB (crash during creation) is adopted |
| 5 | config: precedence file < env < flag for a scalar and a list; help shows every default and the config path; no `--key*` flag exists; `RECON_KEYS_X` is read |
| 6 | run: a second run executes zero checks of a fake stage; adding a port gives exactly the new checks; changing a key-encoded setting (fake crawl depth) gives new checks |
| 7 | subprocess, at each crash point: (a) kill -9 at `render-mid-file`: every output file parses with no partial row, and the next run sweeps `.recon/tmp` and isn't blocked by the lock; (b) kill -9 at `in-check-tx` and at `in-flight`: those checks are redone next run; (c) kill -9 at `after-commit`: committed checks are not repeated; (d) SIGINT and SIGTERM: exit 130 with the same guarantees |
| 8 | egress: against a closed loopback port → `Closed`; a blackholed address with a short timeout → `Filtered`; fake DNS NXDOMAIN, NODATA and SERVFAIL → results, DNS timeout → `error`. run: a fake stage error on check X → X not in `checks`, attempted once per run across passes, counted in stage and summary, row in `failures`, retried next run; `ErrAbortStage` fails the remaining checks without running them |
| 9 | store: re-observation updates attrs and `last_seen` and keeps `first_seen` (clock advanced); two stages observing one record keep both stages' attrs, and redoing one leaves the other's attrs; every CSV has first_seen and last_seen |
| 10 | run: `--redo S` re-runs every check of S; a record no longer observed becomes current=false; a record still observed by another stage stays current; an orphaned check's observation is swept; a redo interrupted at `after-commit` finishes on the next plain run; the summary counts current records only; an unknown stage gives exit 2; help lists the stage names |
| 11 | run: fake stage A emits an in-scope hostname and fake stage B checks it in the same run; a later stage B emits a name that earlier stage A must check (needs a second pass); an out-of-scope name appears in candidates.csv and is never given to B; the run terminates |
| 12 | egress: there is no API for methods other than GET/HEAD, custom headers, userinfo or raw target URLs; `Link` to another host is refused; an out-of-scope host is refused; a redirect is not auto-followed; a port not in the list is refused; no connection type reaches stages; `ThirdPartyHTTP` refuses a host outside `Sources()` and an in-scope, candidate or excluded host. A boundary test over `go list -json ./...` checks direct imports per D13 |
| 13 | run: under `--passive`, Target stages are not-configured ("passive-only") and ThirdParty stages run; a Target fake dialer counts zero |
| 14 | cli: a TTY prompt answered y stores the ack; n leaves Target stages not-configured ("no authorisation"); `--json` or a non-TTY stdin gives no prompt and only the flag counts; the ack isn't asked again after a root is added; `--authorised --passive` stores the ack |
| 15 | run: the `asn` stage (httptest RIPEstat) yields more than the limit → exit 3, the total is printed, and zero dials or rDNS queries follow; `--allow-large-netblocks` proceeds and is remembered; growing scope beyond the approved count stops the run again |
| 16 | scope: table of exact names, `*.x` wildcards (not matching the apex) and CIDRs; a host excluded because it resolves into an excluded CIDR; the address of an excluded host is refused for TCP and HTTP on non-shared addresses; with a fake shared label, another in-scope host on the same address is allowed by HTTP; excluded items appear in excluded.csv with a reason |
| 17 | run and report: the state computed for each condition (done-previously, failed versus done with failures, not-configured with each reason, zero checks); one line per state change; found lines for printed kinds; URLs only counted |
| 18 | report: the summary has current-record totals, failed counts, and each current high or medium finding |
| 19 | cli: with `--json`, every stdout line is valid JSON with no ANSI, including for a validation error; non-TTY stdout gives no ANSI |
| 20 | output: TXT versus CSV per the registry; files are sorted; temp-file-then-rename (temp file in `.recon/tmp`); a CSV formula cell is prefixed; control characters are stripped |
| 21 | config: defaults asserted; run: max concurrent fake checks ≤ `concurrency`; egress: per-IP limiter spacing and vhosts sharing an IP share a limiter |
| 22 | input and config: each invalid form gives exit 2 naming the value, and the fake DNS, HTTP and TCP endpoints receive nothing. The invalid forms are: malformed domain, `co.uk`, bad CIDR, bad ASN, bad exclusion, bad config value, unknown config key, unknown `--redo` stage |
| 23 | cli: exit 0 on completion; a second run while the test holds the lock refuses with exit 1; exit 1 on a store error |
| 24 | cli: a sentinel key from env and one from file, used by a fake keyed stage that puts the key into an attr, a request URL and an error string, never appears in stdout, stderr, JSON, `--verbose` warnings, any output file, or `.recon/state.db*` |

## Spec amendments made

- **B5:** API keys come from the config file or env only.
- **B16:** on shared provider infrastructure, exclusion is by name only (D9).
- **B10 (clarification, not a text change):** a record goes not-current only when no stage still observes it.

## Out of scope for Spec 1

- Discovery stages other than `asn` (Specs 2–5).
- The record kinds and output files reserved for later specs.
- Populating the shared-provider label lookup (Spec 2.8).
- Populating the built-in wordlist (Spec 2) and the sensitive-path list (Spec 5).
- A configurable resolver list.
- Windows support.
- A debug log file. `--verbose` and the `failures` table cover diagnostics.
- Remembering `--passive` per engagement. It is a per-run flag, and the stored ack guards Target stages.

# Implementation (Develop)

Built as designed (D1–D19): module `github.com/rafaelh/recon`, `cmd/recon`, packages under `internal/`
(`config`, `input`, `scope`, `engagement`, `store`, `run`, `egress`, `report`, `output`, `kinds`,
`fault`, `testkit`, `cli`, `stages/asn`). Tests were written first and failed to build; the
implementation then made them pass, including under `-race`.

**How each behaviour is tested**

| B | Where it is pinned |
|---|---|
| 1, 2 | `input` (parse, name table, `-e` validation); `cli` `TestInputsStored`, `TestEngagementDirNaming`, `TestHelp` |
| 3 | `engagement` `TestMergeInputs`; `cli` `TestRerunAddsAndResumes`, `TestPromotedCandidate` |
| 4 | `engagement` and `cli` non-engagement, empty and half-created directories |
| 5 | `config` precedence, keys, no key flag; `cli` `TestHelp` |
| 6 | `cli` `TestResumeOnlyNewChecks`, `TestKeyEncodedSettingCreatesNewChecks` |
| 7 | `cli` subprocess tests with `RECON_FAULT` crash points: render-mid-file, in-check-tx, in-flight, after-commit, a redo interrupted at after-commit, and SIGINT/SIGTERM/SIGHUP (exit 130) |
| 8 | `egress` DNS and TCP outcomes; `cli` `TestTransientFailure`, `TestErrAbortStage` |
| 9, 10 | `store` re-observation, two-stage attrs, redo and orphan sweep; `cli` `TestRedo*` |
| 11 | `cli` `TestDiscoveryLoop` (forward and second-pass discovery, candidates, termination) |
| 12 | `egress` API-shape reflection, policy refusals, link/redirect, third-party sources; import-boundary test over `go list -json` |
| 13, 14 | `cli` `TestPassive`, `TestAck*` |
| 15 | `cli` `TestNetblockGuard`, `TestNetblockInputGuard`; `scope` overlap count |
| 16 | `scope` table; `egress` TCP/HTTP exclusion and shared-label tests; `cli` `TestExcludedCSV` |
| 17, 18 | `cli` `TestStageStatesAndFound`; `report` console and summary |
| 19 | `cli` `TestJSONMode`, `TestNonTTYNoANSI`; `report` renderers |
| 20 | `output` TXT/CSV, sorting, CSV safety, atomic render and sweep |
| 21 | `config` defaults; `cli` `TestConcurrencyBound`; `egress` per-IP limiter and shared vhost limiter |
| 22 | `input`, `config`; `cli` `TestInvalidInputsTouchNothing` (UDP/HTTP/TCP canaries stay at zero) |
| 23, 24 | `engagement` lock; `cli` `TestExitCodes`; `TestSecretsNeverLeak` scans stdout, stderr, every file and `state.db*` |

**Deviations from the plan**

- Engagement name from an ASN input uses the canonical `AS<n>` form lowercased (`as64500`), not the
  raw text, so `123` and `AS123` name the same engagement.
- A bare IP is accepted as an exclusion (stored as `/32` or `/128`).
- `egress.Policy` gained a `Candidates` set so `ThirdPartyHTTP` can refuse candidate hosts. `ThirdPartyRequest`
  gained `KeySource`/`KeyHeader`/`KeyParam` so the client attaches keys.
- `egress.Options` gained timeouts (DNS, connect, banner, HTTP) so tests run quickly.
- The `guard` pseudo-stage records `excluded` observations made at dial time, so they appear in
  `excluded.csv`. It leaves a `checks` row per address under stage `guard`.
- The console prints nothing for `run_end`. In `--json` mode `--help` is written to stderr so stdout stays JSON.
- `internal/testkit` (a fake `Stage`) is a non-test package so the `cli` tests and the subprocess child can share it.
- The blackholed-address `Filtered` test is skipped where the local network answers instead of timing out; a
  deterministic dial-failure case always runs.
- The `kinds` registry holds Spec 1 record kinds (`hostname`, `root`, `netblock`, `excluded`, `resolution`,
  `web_service`, `open_port`, `finding`, `url`). Later specs register theirs there.

# Out of Scope (additions found while implementing)

- No scale test: the ~410k-check target (D19) is untested.
- The ack prompt is tested with injected TTY functions, not a real pty.
- The sensitive-paths YAML format (strings or `{path: ...}`) is provisional until Spec 5.
- The `Policy` and `View` read the whole record set per stage and pass; fine at Spec 1 volumes, may need
  indexing for later specs.
- Root domains, orgs and in-scope IPs are not yet expanded into hostnames (Specs 2-4).
- IPv6 netblocks are in scope but not counted by the B15 guard.
- Stage state `done-previously` is only decided on the first pass.
- Windows is unsupported (flock, signals).

# Verification

**Result: the goal and behaviours 1–24 are met for Spec 1's scope.** Spec 1 ships one real stage
(`asn`) and the scope, candidates and excluded outputs. The other outputs in B20 and the discovery
of hosts, services and ports are reserved for Specs 2–5, as the Design states.

How this was checked:
- I read every package against each behaviour.
- `go build`, `go vet` and `go test -race ./...` all pass.
- I ran the built binary for smoke tests:
  - invalid domain, `co.uk`, bad CIDR, bad ASN, bad wildcard, bad config value, unknown `--redo` stage and `-e ../x` all exit 2 and name the bad value;
  - a non-recon directory is refused with exit 1 and named;
  - with `--json`, a validation error is reported as JSON lines only;
  - a passive run exits 0, writes sorted CSVs with `first_seen` and `last_seen`, and resumes with `-e`;
  - an oversized `--cidr` exits 3 and shows the address total;
  - `--allow-large-netblocks` proceeds and is remembered;
  - `--help` shows every default, the config path, the env prefix, `RECON_KEYS_<SOURCE>`, the naming precedence and the redo stages.

**Fixed**
- **B8/B11: a run could loop forever.** When a stage's `Checks()` yielded an error, every pass
  counted it as an executed check, so the "stop when a pass executes zero checks" rule never
  triggered. It is now counted once per stage per run, like any other failed check, and still shows
  in the stage's failed count. `TestEnumerationErrorTerminates` covers it, and `testkit.Stage`
  gained `ChecksErr` to support the test.

**Minor observations (not changed)**
- The `failures` row for `(enumeration)` is never cleared, because no check with that key ever
  completes.
- The early JSON-mode check in `cli.Execute` only recognises `--json` and `--json=true`. With
  `--json=1`, a flag-parse error is printed as console text instead of JSON. Successful runs are
  unaffected.
- `TargetHTTP` refuses IP-literal hosts because they classify as candidates. Spec 3 must decide
  how web services on in-scope IPs are requested.
- `TargetTCP` refuses every address of an excluded hostname, including shared ones. When Spec 2.8
  populates the shared-provider lookup, check this against B16's "only the excluded hostname
  itself" wording.
