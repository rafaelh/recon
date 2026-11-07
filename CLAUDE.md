# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

recon is a passive-first reconnaissance CLI for authorised engagements: a single static Go binary
for macOS and Linux (Windows is not supported). `README.md` is the user-facing behaviour contract
(flags, output files, exit codes, the passive boundary). `CONTEXT.md` defines the domain
vocabulary. Use its terms (engagement, scope input, stage, check, observation, record, record
kind, shown, evidence, finding) and avoid the synonyms it lists.

## Commands

```sh
make build                      # ./recon (CGO_ENABLED=0, -trimpath)
make test                       # go vet for all 4 GOOS/GOARCH targets, then go test -race ./...
make dist                       # dist/recon-{darwin,linux}-{amd64,arm64}
go test ./internal/cli/ -run 'TestPorts_' -count=1   # one package, tests matching a regex
golangci-lint run ./...         # config in .golangci.yml (v2, std-error-handling exclusions)
```

- Don't export `CGO_ENABLED=0` globally: `-race` needs cgo on Linux.
- `go.mod` pins a recent toolchain. With `GOTOOLCHAIN=local` and an older Go, builds fail.
- The `.claude/hooks/go-check.sh` PostToolUse hook runs gofmt, `go vet` and golangci-lint
  (new issues only) on each edited `.go` file. Exit 2 means it found something to fix.
- When running the binary by hand, use an `--output-dir` outside the repo. `output_dir` defaults
  to `.`, and `/output/` is gitignored.

## Hard invariants (enforced by tests)

- **Only `internal/egress` does network I/O.** `internal/egress/boundary_test.go` checks the
  non-test files of every package, for all four targets, and fails if any of them imports `net`,
  `net/http`, `crypto/tls`, `syscall` or `github.com/miekg/dns`. Uses of `golang.org/x/sys/unix`
  are limited to an allowlist: signals in `internal/cli`, flock in `internal/engagement`. No
  first-party package may import `os/exec`. Stages get `egress.Clients` and egress's own result
  types, never `net/*` types. Test files may use `net` (fake servers);
  `internal/egress/egresstest` is the fake DNS server.
- **Passive boundary.** Target-owned systems may only receive DNS lookups, TCP handshakes (read the
  unprompted banner, send nothing) and HTTP GET/HEAD to in-scope hosts. Egress enforces this
  through a `Policy` the runner rebuilds whenever the scope changes. Candidates and excluded
  hosts/addresses are never contacted.
- The cross-target `go vet` in `make test` exists so that an untagged platform-specific call can't
  break one OS/arch unnoticed. If you change the target list, keep `TARGETS` in the `Makefile` in
  step with the list in `boundary_test.go`.

## Architecture

Flow: `cmd/recon` → `internal/cli` (cobra/viper flags, validation, authorisation prompt,
signals, exit codes) → `internal/run.Runner` → stages → `internal/store` (SQLite via
`modernc.org/sqlite`, under `<engagement>/.recon/`) → `internal/output` (CSV/TXT files) and
`internal/report` (console or `--json` event lines).

**Stages** (`internal/run/stage.go`) implement `Name/Contact/Sources/Configured/Checks/Run`.
- `Contact` is either `ThirdParty` or `Target`, never both. A stage that would do both is split
  into two stages. Only `Target` stages get HTTP/TCP target clients. They are skipped under
  `--passive`, and also until the user confirms authorisation.
- A `Check.Key` must encode every input and setting that changes the work (for example a wordlist
  hash or crawl depth), so that changing a setting creates new checks instead of reusing stale
  ones. Check results are persisted. A re-run executes only checks that haven't completed, so
  resume works and failed checks are retried.
- `Run` reports negative results (NXDOMAIN, closed port) as completed checks with zero or more
  observations. A returned error means a transient failure: the check is retried on later runs.
  Wrap `run.ErrAbortStage` to abort the stage's remaining checks for this run.
- Optional interfaces: `WorkerCounter` (a custom pool size, used by ports), `CandidateExempt`, and
  `Retiring` (completed checks the stage no longer yields are retired, so their evidence stops
  being current).
- Stages read state only through `run.View`, which offers scope, inventory and cached current
  records. Web stages must use `ProbeHostnames()` (wildcard-aware), not `InScopeHostnames()`.
- The registry order is `defaultStages()` in `internal/cli/cli.go`, and that order matters (see
  its comment). The runner repeats passes over all stages until no new work appears. After any
  stage does work it flushes the store, rebuilds the scope (which also updates the egress Policy)
  and re-derives findings.

**Record kinds** (`internal/kinds/table.go`) are typed handles. Stages write with
`kinds.X.Obs(key, attrs)`, and readers decode with `kinds.X.Attrs(rec)`. The store merges the
attributes that several stages observed for one record, field by field. `omitempty` and pointer
fields carry meaning (see the comment at the top of `table.go`). A kind's showing rules
(counted, printed, written, used for findings) live with it, and visibility is decided at read
time from the current scope.

**Derived on read, never stored by stages.** `scope` (classifies hosts and addresses as
in-scope, candidate or excluded), `inventory` (wildcards, provider hosts, port eligibility) and
`findings` are pure functions of the current records, scope, settings and date. Risk stages
(`internal/stages/risk`) store only *evidence* kinds. `internal/findings` derives findings from
the evidence that is shown. A finding that is no longer derived stays on record but is marked not
current. Records keep `first_seen`/`last_seen`/`current` and are never deleted.

**Pure knowledge packages** with no I/O: `cloudstorage` (bucket naming, S3/GCS/Azure),
`provider` (shared infrastructure from CNAME suffixes, address ranges and ASNs; data in the
embedded `providers.yaml`), `dnsname`, `sanitize` (strips terminal-acting characters from
target-supplied text), `input`. The built-in wordlist and sensitive-path list are embedded in
`internal/config/builtin/`.

**Config** (`internal/config`): precedence is file < `RECON_*` env < flags, and unknown keys are
rejected. API keys come only from `keys.<source>` or `RECON_KEYS_<SOURCE>`. They are
`config.Secret` values and get redacted from all output, so never add a key flag or log a key.

**Output** files are written to `.recon/tmp` and then renamed into place. A file is written only
when it has rows, and is removed once it has none.

## Testing

- Most behaviour tests live in `internal/cli/*_test.go`. They drive `cli.Execute` in-process
  through the `harness` in `harness_test.go`, with fake stages from `internal/testkit` or real
  stages pointed at loopback fakes. `egress.Options.SourceBaseURLs`, `ResolverAddrs` and
  `DialMap` redirect traffic without changing policy logic. The harness has UDP/HTTP/TCP
  "canaries" that detect any unexpected request. The clock is fixed at 2026-11-01 UTC.
- `crash_test.go` re-executes the test binary as a child process (`RECON_TEST_CHILD=1`) and uses
  `internal/fault` crash points (`RECON_FAULT=<point>`, such as `in-check-tx`, `after-commit` or
  `render-mid-file`) to kill the process at known moments and verify resume and atomic output.

## Conventions

- Australian English in docs, comments and messages ("authorised", "behaviour", "sanitise").
  `--authorized` is accepted only as a flag alias.
- Specs live in `docs/specs/` (the `.claude/skills/spec-*` workflow). Code, comments, test names
  and file names must never cite spec numbers or spec IDs; describe the behaviour instead.
- Commit messages use conventional prefixes (`feat:`, `fix:`, `refactor:`, `chore:`, `docs:`,
  `style:`).
- `docs/todo.md` lists known deferred work, such as store statement batching, HTTP connection
  reuse, and how findings are announced.
