# Exit codes

The exit code tells the caller which kind of outcome happened, so it can choose between using the
result, fixing its arguments and treating the run as failed, all without parsing any output. Whether
a failure is worth retrying is not in the exit code: that is the error's `transient` key
([Output](0003-output.md)).

## Always present

| Code  | Meaning      | When to use | Error codes |
|-------|--------------|-------------|-------------|
| `0`   | Success      | Data returned or operation completed, including a search or list that matched nothing (`data: []`) | none |
| `1`   | System error | The arguments were fine and something else went wrong: network failure, timeout, rate limit, vendor 5xx, credentials rejected, unexpected failure | `NETWORK_ERROR`, `TIMEOUT`, `RATE_LIMITED`, `UPSTREAM_ERROR`, `AUTH_FAILED`, `UNEXPECTED_ERROR` |
| `2`   | Usage error  | Bad flag, invalid value, missing flag or credential, a path that doesn't exist: anything caught before work starts | `INVALID_INPUT` |
| `3`   | Not found    | A lookup by ID or name found no such record | `NOT_FOUND` |
| `130` | Interrupted  | SIGINT cancelled the run | `INTERRUPTED` |
| `143` | Terminated   | SIGTERM cancelled the run | `INTERRUPTED` |

`130` and `143` are 128 plus the signal number, which is what a shell reports for a process killed
by that signal.

## Conditional (add only when meaningfully distinct from `1` or `2`)

| Code | Meaning           | When to use | Error codes |
|------|-------------------|-------------|-------------|
| `4`  | Permission denied | Credentials are valid but aren't allowed to do this. Distinct from `1` because nothing is broken: the caller should report the problem or ask for access. | `PERMISSION_DENIED` |
| `5`  | Conflict          | A record with the same unique key exists and differs from the request, or a precondition (such as an etag) failed. Distinct from `2` because the input was valid; the way forward is "fetch, merge, retry", not "fix the arguments". An identical existing record is not a conflict; see [Idempotency](0006-idempotency.md). | `CONFLICT` |
| `6`  | Verdict not met   | The run succeeded and its answer is unfavourable. Only when the caller asked for it with `--fail-on-verdict`. | `VERDICT_FAILED` |
| `7`  | Partial result    | Only part of what was asked for came back: the targets of one call ended differently ([Batch input](0009-batch-input.md)), or a walk stopped before its end ([Pagination](0007-pagination.md)). stdout carries what there is. Never report a partial result as `0`. | `PARTIAL` |

Don't reach for `4` to `7` by reflex; most tools only use `0` to `3`. A tool may add a more specific
error code within a row when callers would act differently on it, but the exit code stays the row's.

**Why `2` is the usage error:** POSIX utilities, shell builtins and getopt-style parsers exit `2` on
misuse, so callers expect it. Not every argument parser follows that, and most runtimes exit `1` on
any failure nobody caught, so the convention holds only where the tool imposes it. See "Building
it" below.

**Why `3` is for lookups only:** a caller that asked for a specific record needs to tell "it doesn't
exist" from "something went wrong" without parsing output, and exit `3` is that signal. A search that
matches nothing is different: like a verdict (below), it is a complete, successful answer. It exits
`0` with `data: []`, so scripts that stop on any failure and pipelines into `jq` keep working.

**A verdict is data, not an exit code.** Exit codes say whether the *tool* ran, never whether the
*answer* was favourable. A host with forty open CVEs is a successful run: exit `0` with the verdict
in `data` as an `ok` boolean, the counts and the failing list. Exiting non-zero for an unfavourable
answer leaves callers unable to separate "the gate failed" from "the tool crashed", and teaches an
agent to ignore that tool's non-zero exits altogether. CI wants the opposite, so it opts in with
`--fail-on-verdict`. Only the caller knows it is acting as a gate, so only the caller can say so.

## Every exit explains itself

A caller that sees only the tool's output must be able to act correctly without knowing what `3`
means. So every non-zero exit writes one error to stderr saying what happened and what to do next
(format in [Output](0003-output.md)):

```
$ cve CVE-2099-0001 --json          # exit 3, stdout empty
{"error":"CVE-2099-0001 is not in the NVD","code":"NOT_FOUND","hint":"check the ID; NVD lists only published CVEs","input":{"ids":["CVE-2099-0001"]},"transient":false}
```

Exit `0` explains itself too when the result isn't the obvious one, such as a dry-run, a truncated
list or a create that changed nothing, through `meta.dry_run`, `meta.truncated` and
`meta.created: false`.

Don't document exit codes in an agent's skill file or wrapper prompt. That costs tokens every time
it is loaded, whether or not the tool is called, and goes stale the moment the tool gains a code.
The one place they're listed is a single line at the end of `--help`, as a man page's EXIT STATUS
section would, which costs nothing until asked for. If a caller needs more than that to know what
to do next, the error message isn't saying enough: fix the message.

## Building it

**One place chooses the exit code and writes the error.** Call it `main`. Every verb goes through
it, which is what keeps the codes and the error format the same across the tool.

Commands never exit and never print an error. They report failure by returning or raising one error
type that carries everything `main` needs: exit code, error code, message, hint, input and
transient. When other code has wrapped that error in its own, `main` finds it by walking the chain
of causes.

- **The process exits in exactly one place**: the last line of the entry point, with the code `main`
  returned, after stdout and stderr have been flushed. A hard exit from anywhere else can skip
  clean-up code, bypass the error format, and cut off output still waiting to be written to a pipe.
- **Catch everything.** An uncaught exception, a panic or a failure in a background task ends the
  process with the runtime's own stack dump and the runtime's own exit code. Neither is right: the
  dump isn't the error format, and the code may collide with one in the tables above (a Go panic
  exits `2`, a Rust panic `101`). `main` catches whatever a command can throw, reports
  `UNEXPECTED_ERROR` and exits `1`. The stack trace goes to stderr only under `--debug`.
- **Wait for everything you start.** A task nobody waits for can fail after `main` has stopped
  listening. Every task a tool starts is waited for before the command returns.
- **Take over the argument parser's errors.** Left alone, a parser prints its own message and exits
  with its own code, which is `1` in some and `2` in others. Configure it to hand the error back
  without printing or exiting. `main` reports a parse error as `INVALID_INPUT` with exit `2`, and
  treats a request for help or the version as exit `0`. An error that reaches `main` without an exit
  code is treated as `1`, so every kind of error the parser can raise needs mapping; see
  [Input validation](0005-input-validation.md).
- **Handle signals.** On SIGINT or SIGTERM, cancel the invocation
  ([Never hang](0004-never-hang.md)), let the command return, then exit 128 plus the signal number.
  Whatever the runtime does with an interrupt by default, whether that is killing the process with
  no output or raising an exception that prints a stack trace, replace it with this.

## What to avoid

- **Exiting from inside a command or a library.** It is the usual cause of two verbs in one tool
  disagreeing about what an exit code means.
- **A non-zero exit for an empty result or an unfavourable verdict.** Both are answers.
- **Exit `0` when some targets failed.** That is `7`.
- **Exit `1` for a mistake the caller made.** `1` says the arguments were fine. A caller told that
  retries or reports, when what it needed to do was fix a flag.
- **A stack trace on stderr without `--debug`.** An agent reads all of it and learns nothing it can
  act on.
- **Trusting the parser's exit code** because it happens to be `2` today. Map it deliberately, so the
  tool decides the code, not the library.
