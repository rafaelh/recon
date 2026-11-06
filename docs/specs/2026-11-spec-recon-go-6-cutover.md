# Spec 6 of 6: recon (Go) — Cutover

## Goal

Make the Go `recon` the only implementation in this repository, installable as a single binary, and
remove the Python version. Depends on Specs 1–5 being complete.

## Behaviours

1. The Go `recon` builds into a single binary for macOS and Linux (amd64 and arm64) with no runtime
   dependency on external recon tools.
2. The repository contains no Python code, Python packaging, Python version pins, Python-specific
   ignore entries, helper notes referencing the old tools, or scripts that install the external tools
   the old version used.
3. The README documents installation, configuration (including where API keys go), usage, the passive
   boundary, passive-only mode, the authorisation acknowledgement, and the meaning of each output.
4. Output directories from the Python version are not resumable (Spec 1.4).
5. XSS/SQLi testing and the separate single-site command are retired.

# Design

## Decisions

| # | Decision | Answer | Rationale |
|---|----------|--------|-----------|
| D1 | Distribution | (user) `go install github.com/rafaelh/recon/cmd/recon@latest`, plus a `Makefile`. No CI, no GoReleaser, no published release binaries | The simplest route to B1. The module path already matches the public repo |
| D2 | Version | (user) Add a `--version` flag. The string is `debug.ReadBuildInfo().Main.Version`, or `devel` when that is `(devel)` or there is no build info. It is passed in through a new `Deps.Version` field: `DefaultDeps` sets it, and `Execute` defaults an empty value to `devel`, as it does for `Kinds`, `Files` and `Clock`. `cmd.SetVersionTemplate("recon {{.Version}}\n")`. The `version` flag is defined explicitly, so cobra adds no `-v` shorthand that could be confused with `--verbose` | Since Go 1.24, builds from a checkout and `go install @latest` both record a VCS pseudo-version such as `v0.0.0-20261106032157-7e34c1b8d74f`, with `+dirty` when there are local changes. No ldflags or hand-made revision formatting is needed. Cobra skips `--version` when `Version` is empty, so the default is required: without it, test harnesses that build `cli.Deps{}` would start a run |
| D3 | README drift | (user) The README is hand-written, with no drift test. It points to `recon --help` for anything already generated there (settings and their defaults, the severity table, `--redo` stage names) instead of copying it | No test means the README should hold as few copies of generated facts as possible |
| D4 | Pinning B1 | `make test` runs a cross-build with `CGO_ENABLED=0 GOOS=<os> GOARCH=<arch> go vet ./...` for each of the four targets after `go test -race ./...`. No Go test for this | `go vet` type-checks per target, so it catches the realistic regression: untagged `golang.org/x/sys/unix` calls in `internal/cli` and `internal/engagement` that break on one OS. A `go list` test was rejected: with `CGO_ENABLED=0`, `CgoFiles` is always empty and `go list` doesn't type-check, so it could never fail |
| D5 | First-party `os/exec` | Tighten `internal/egress/boundary_test.go` so `os/exec` is forbidden in every first-party non-test package, including `internal/egress` | Pins that recon's own code doesn't import `os/exec`. Dependencies may still exec: `colorprofile` runs `tmux info` inside tmux to detect colour, which is not a recon tool |
| D6 | Removals | `git rm` pkg/, pyproject.toml, uv.lock, .python-version, install.py, install_scripts/ and notes.txt. Then `rm -rf` the leftover untracked/ignored `pkg/` (`__pycache__`) and `.venv/` | B2. Removing pkg/recon/reconsite.py and enumerateflaws.py retires the single-site command and XSS/SQLi (B5). The Go code has no equivalent |
| D7 | `.gitignore` | Keep `.vscode`. Replace the Python section with `/recon` and `/dist/` | B2. Only the outputs the Makefile produces are ignored |
| D8 | B4 | No code change. Already covered by `TestNonEngagementDirRefused` (internal/cli/behaviour_test.go), which uses a Python-shaped dir, and by `TestRefusesNonEngagement` (internal/engagement). The Python tool always wrote `<target>/tool_output/` and `<target>/*.txt`, so its dirs are never empty | Already met (Spec 1 D11) |
| D9 | Historical specs | Files under `docs/specs/` keep their references to the Python version | They are design records, not helper notes. B2 targets tooling, packaging and notes |
| D10 | `--version` in JSON mode | With `--json`, the version line goes to stderr (cobra output is already sent to stderr in JSON mode) | Keeps Spec 1 B19's rule that every stdout line is JSON |
| D11 | Keyed source names | The README lists the four keyed sources by name (`securitytrails`, `shodan`, `virustotal`, `whoisxml`), with an example key for each in the config example | The user needs the names to set keys. Generating the list in `--help` would need a new stage interface, which isn't worth it for four stable names |

## Makefile

`CGO_ENABLED=0` is set only inside the `build` and `dist` recipes, never exported globally. On Linux, `-race` needs cgo.

| Target | Does |
|---|---|
| `build` | `CGO_ENABLED=0 go build -trimpath -o recon ./cmd/recon` |
| `dist` | For each of darwin/amd64, darwin/arm64, linux/amd64 and linux/arm64: `CGO_ENABLED=0 GOOS=… GOARCH=… go build -trimpath -ldflags "-s -w" -o dist/recon-<os>-<arch> ./cmd/recon` |
| `test` | `go vet ./...`, `go test -race ./...`, then the four-target `CGO_ENABLED=0 GOOS=… GOARCH=… go vet ./...` (D4) |
| `clean` | `rm -rf recon dist` |

`.PHONY` covers all of these.

## README

Replace README.md entirely. Sections:

1. **What it is.** Passive-first reconnaissance for an authorised engagement. A single Go binary for macOS and Linux with no external tools.
2. **Install.** `go install github.com/rafaelh/recon/cmd/recon@latest`: Go 1.21+ is enough because `GOTOOLCHAIN=auto` fetches the go.mod toolchain. Mention `CGO_ENABLED=0` for a fully static Linux binary. From a clone, `make build` or `make dist`. Windows is unsupported.
3. **Quick start.** Run from a working directory outside the repo, or pass `--output-dir`, because `output_dir` defaults to `.`. Cover:
   - a domain run;
   - `--passive`;
   - `--authorised`;
   - resuming with `-e`.
4. **Inputs and engagements.**
   - **Input forms:** domains, `-d`, `--org`, `--asn`, `--cidr`, `-x` and `--exclude-file`.
   - **Engagement name:** derived from the inputs, and the derivation is order-sensitive.
   - **Re-runs:** add to the stored scope and exclusions; nothing is removed by omission.
   - **Resume:** a re-run performs only unchecked checks, and failed checks are retried on later runs.
   - **`--redo <stage>`:** stage names are in `--help`.
5. **Configuration.**
   - **Config file:** `$XDG_CONFIG_HOME/recon/config.yaml`, defaulting to `~/.config/recon/config.yaml`, overridable with `--config`. Unknown keys are rejected.
   - **Precedence:** flags override `RECON_*` env, which overrides the file. Env names are `RECON_<UPPER_SNAKE>`, with `.` replaced by `_`.
   - **API keys:** only in `keys.<source>` in the file or `RECON_KEYS_<SOURCE>` in env, never in flags. Keys never appear in output.
   - **Keyed sources (D11):** list them. A stage whose key is missing is shown as not-configured.
   - **Example `config.yaml`:** a short example.
   - **Settings:** "all settings and their defaults: `recon --help`".
6. **Passive boundary.** Exactly what target-owned systems may receive (Spec 1 B12): DNS; TCP handshakes to the port list, reading only what the service sends unprompted; GET/HEAD to in-scope hosts, same-host crawled links and the sensitive-path list. What is never sent, and that candidates and excluded hosts are never contacted.
7. **Passive-only mode.** What `--passive` restricts to (third-party sources only), and which stages show as not-configured. It applies per run.
8. **Authorisation acknowledgement.** It is required before any stage that contacts target-owned systems. On a TTY it can be given by prompt or flag; with `--json` or no TTY, only `--authorised` counts. It is remembered per engagement. Without it, those stages are not-configured.
9. **Large netblocks.** The `netblock_limit` stop, `--allow-large-netblocks`, and that the approval is remembered.
10. **Console and JSON.** The stage states, the found lines, the summary, `--json` (one event per line), and `--verbose`.
11. **Output files.** A table with one row per file in `output.Default()` (scope.csv … risk-certificates.csv), each with a one-line meaning.
    - Files are sorted, and every CSV has `first_seen`/`last_seen`. Not-current records are kept.
    - `.recon/` holds the state DB and the lock: don't edit it.
    - "Finding severities: `recon --help`."
12. **Exit codes.** 0, 1, 2, 3 and 130, with their meanings (Spec 1 D17).
13. **Migrating from the Python version.**
    - Old output dirs are refused (exit 1, the dir is named) and never resumed. Fix: use a different `-e` name or move the old dir.
    - The `reconsite` command and XSS/SQLi testing are retired.
    - The external tools and `install.py` are no longer needed.

## Code changes

- `internal/cli/cli.go`: add the `Deps.Version` field, set it in `DefaultDeps` from `versionString(debug.ReadBuildInfo())`, default it in `Execute`, and add an explicit `--version` flag and version template (D2).
- `internal/cli/version.go` (new): `versionString(info *debug.BuildInfo, ok bool) string`.
- `internal/egress/boundary_test.go`: `os/exec` is forbidden in `internal/egress` too (D5).
- `Makefile` (new), `.gitignore`, `README.md`, and the removals listed in D6.

## Test plan

| B | Tests |
|---|-------|
| 1 | `make test`: four-target `CGO_ENABLED=0 go vet ./...` passes (D4). Boundary test: no first-party package imports `os/exec` (D5). cli: `--version` exits 0, prints `recon <Deps.Version>\n` to stdout, creates no engagement dir and contacts nothing; with `--json`, stdout is empty and the line is on stderr; zero-value `Deps` prints `recon devel`. version: `versionString` returns a pseudo-version as-is, and `""` for `(devel)` or no build info, so `Execute` is the only place that substitutes `devel` |
| 2 | Verification (not a Go test): `git ls-files` has no `*.py`, `pyproject.toml`, `uv.lock`, `.python-version`, `install.py`, `install_scripts/` or `notes.txt`; `git status --porcelain --ignored` shows no `pkg/`, `.venv/` or `__pycache__`; `.gitignore` has no Python entries |
| 3 | Verification: the README has each section listed above, and every file in `output.Default()` appears in its outputs table |
| 4 | Existing tests (D8) |
| 5 | Verification: no `reconsite` or XSS/SQLi code remains (`git grep -i -w -E 'reconsite\|dalfox\|dsss\|xss\|sqli'` matches only `docs/specs/`; `-w` avoids matching `sqlite`) |

Verification also runs `make dist`, which must produce four binaries. `go version -m dist/*` must show `CGO_ENABLED=0` for each. Check that `file` reports the Linux binaries as statically linked; darwin binaries always link libSystem dynamically, which is expected.

## Out of scope

- CI, published release binaries, GoReleaser, code signing or notarisation, a Homebrew tap.
- Windows.
- A README drift test, and generating the keyed-source list in `--help`.
- Forbidding `golang.org/x/sys/unix` outside `internal/cli` and `internal/engagement`.
- Any change to scan behaviour.
- The two macOS-only TLS error-text test failures described under Implementation (Develop). They
  predate this spec.
- `make test` aborts before the cross-target vet when the race tests fail, so a failing test
  hides a cross-target type error until the test is fixed.

# Implementation (Develop)

**Code.** `internal/cli/version.go` adds `versionString`. `cli.go` gains `Deps.Version`, set by
`DefaultDeps` and defaulted to `devel` in `Execute`, plus `Version` on the root command, an explicit
long-only `--version` flag and the `recon {{.Version}}` template (D2, D10). `Makefile` has `build`,
`dist`, `test` and `clean` (D4). `.gitignore` is reduced to `.vscode`, `/recon` and `/dist/` (D7).
`README.md` is replaced with the thirteen sections in the design (D3, D11). The Python version is
removed with `git rm` plus `rm -rf` of the leftover `pkg/` and `.venv/` (D6).

**Tests by behaviour.**

| B | How it was tested |
|---|---|
| 1 | `TestVersionString` (internal; pseudo-version, tag, `(devel)`, empty, no build info). `TestVersionFlag` (stdout `recon <version>\n`, exit 0, nothing created, no network contact), `TestVersionFlagZeroDeps` (`recon devel`), `TestVersionFlagJSON` (stdout empty, line on stderr), `TestNoVersionShorthand` (`-v` is rejected). `TestPassiveBoundaryImports` now forbids `os/exec` in `internal/egress` too, and failed when `os/exec` was imported there temporarily. Cross-target `CGO_ENABLED=0 go vet ./...` passed for all four targets. `make dist` built four binaries, `go version -m` showed `CGO_ENABLED=0` on each, and `file` reports both Linux binaries as statically linked |
| 2 | Verified: `git ls-files` has no Python or tooling files, `pkg/` and `.venv/` are gone, and `.gitignore` has no Python entries |
| 3 | Verified: every section is present, and every file in `output.Default()` is in the outputs table (checked by script) |
| 4 | Existing tests (D8), unchanged |
| 5 | Verified with the `git grep` in the test plan, with the exception below |

**Deviations.**
- The B5 `git grep` also matches `README.md`, whose migration section names `reconsite`, `dalfox`
  and the other retired tools. The design requires that section, so the README is a second place
  the grep matches, and no code matches.
- `make test` stops at its `go test -race ./...` step because of the two failures below, so the
  cross-target vet loop was run separately with the same commands.
- The boundary test change was a pin, so it passed before and after. A temporary `os/exec` import
  was used to show that it can fail.

**Pre-existing failures.** `TestWebB3_AllAttributes` and
`TestWebB3_ExpiredAndSelfSignedCertificatesAreRecorded` (`internal/cli`) fail on the unmodified
commit 7e34c1b on macOS. The `tls_error` text from the system certificate verifier differs from what
they expect. They are unrelated to this spec and were not changed.

# Verification

All five behaviours and the goal are met. No code was changed during verification.

| B | Result |
|---|---|
| 1 | Met. `go vet ./...` and the four-target `CGO_ENABLED=0 go vet ./...` pass. `make dist` builds four binaries. `go version -m` shows `CGO_ENABLED=0` for each, and `file` reports both Linux binaries as statically linked. `TestPassiveBoundaryImports` passes, so no first-party package imports `os/exec`. All `--version` tests pass. `./recon --version` prints `recon v0.0.0-20261106032157-7e34c1b8d74f+dirty`. With `--json`, nothing from `--version` or `--help` goes to stdout |
| 2 | Met. `git ls-files` lists none of the removed Python or tooling files. `pkg/`, `.venv/` and `__pycache__` are gone from disk. `.gitignore` contains only `.vscode`, `/recon` and `/dist/` |
| 3 | Met. The README has all thirteen designed sections, and all 20 files from `output.Default()` are in its outputs table. Its claims were checked against the code: the env names (`RECON_RATE_PER_HOST`, `RECON_CRAWL_MAX_DEPTH`), the keyed source names, which stages contact the target (`httpprobe`, `crawl`, `sensitive-paths`, `ports`, `takeover`), the `passive-only` and `no authorisation` reasons, the stage states, and the trailing `current`/`first_seen`/`last_seen` CSV columns. All are accurate |
| 4 | Met. `TestNonEngagementDirRefused` passes |
| 5 | Met. The B5 `git grep` matches only `docs/specs/` and the README's migration section, which the design requires (the deviation recorded under Develop). No code matches |

`go test -race ./...` passes except for the two `TestWebB3_*` macOS TLS error-text failures, which predate this spec and are out of scope. Because of them, `make test` stops before its cross-target vet step, so that step was run separately with the same commands.
