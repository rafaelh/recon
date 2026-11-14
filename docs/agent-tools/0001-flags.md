# Command-line flags

These are the flags every tool converges on. A tool declares a flag only when it has the capability
the flag describes, and no capability is spelled two ways. A caller that has learned one tool can
then guess the next one correctly.

## Every tool

| Flag          | Short | Meaning |
|---------------|-------|---------|
| `--json`      | `-J`  | Emit one compact `{data, meta}` object on stdout instead of the human rendering. Implies `--quiet`. See [Output](0003-output.md). |
| `--quiet`     | `-q`  | Suppress informational and progress output on stderr. Warnings and errors are still written. |
| `--debug`     |       | Write diagnostics to stderr: requests made, retries, and the stack trace of an unexpected failure. Never changes stdout. |
| `--timeout D` |       | Deadline for the whole invocation, as a duration: a number and a unit (`ms`, `s`, `m`, `h`), and units combine (`30s`, `2m`, `1m30s`). Default `60s`. Only for tools that make network calls. See [Never hang](0004-never-hang.md). |
| `--version`   |       | Print the tool's version and exit `0`. The same version goes in the `User-Agent` of every request. It has one source, fixed when the tool is built or released, so the two can't disagree. |

Machine output is a mode, not a format, so `--json` is its only switch. There is no
`--format json`.

**Secrets come from the environment, never from flags.** A credential is read from a named variable
(`NVD_API_KEY`). A flag value lands in shell history, in the process list, and in the transcript of
any agent that runs the tool. A verb that needs a secret that isn't set exits `2` naming the
variable.

**The environment is the one the caller gave.** A tool must not load a `.env` file from the working
directory. A tool started in a directory that holds one would pick up a credential its caller never
set, and an agent couldn't see why. Some runtimes and libraries load these files on their own, before
any of your code runs. Find out whether yours does, and turn it off.

## Help and usage errors

- `--help` prints to stdout and exits `0`. It leads with examples, because a caller copies an example
  faster than it assembles one from a flag list. The examples pass `--json`, which is how an agent
  learns to ask for it. It lists the valid values of every flag that takes a fixed set and, where
  the verb takes `--fields`, the field names. It ends with one line listing the exit codes the tool
  uses (see [Exit codes](0002-exit-codes.md)).
- **The root `--help` is the whole reference.** In a tool with subcommands it shows every verb with
  its flags and one example, so one call teaches the whole tool. Otherwise an agent spends a turn on
  `tool --help` and another on `tool verb --help` before doing any work. Most argument parsers print
  only a list of subcommands at the root, so this usually means writing the root help yourself.
  `tool verb --help` still works but is never needed.
- A usage error prints one error and a hint, never the help text. Full help after every mistake costs
  an agent hundreds of tokens and buries the one line that matters.
- A bare invocation of a command that needs arguments is a usage error like any other: exit `2`, one
  error on stderr saying what is missing, and a hint naming `tool --help`. It doesn't print the help
  itself.

## When the verb returns multiple records

| Flag             | Meaning |
|------------------|---------|
| `--limit N`      | Return at most N records. Every list verb has a default cap, shown in `--help`. |
| `--all`          | Remove the cap and walk every page. |
| `--cursor TOKEN` | Resume from the `meta.next_cursor` of a previous response. |

These are the only paging flags; [Pagination](0007-pagination.md) says why, and how they combine.

## When the record is wide

| Flag             | Meaning |
|------------------|---------|
| `--fields a,b,c` | Return only the named fields, plus `id`; `--fields all` returns every field. See [Field selection](0008-field-selection.md). |

## When the verb changes something

| Flag        | Meaning |
|-------------|---------|
| `--dry-run` | Work out the target and show what would change, without writing anything. The reads needed to build the preview are expected: you can't report "removes 3 of 5 members" without fetching the 5. Available on every verb that changes something. Wins over `--confirm`. |
| `--confirm` | Required by destructive or irreversible verbs: delete, overwrite, bulk change. Without it they exit `2` naming the flag and suggesting `--dry-run`. Changes that only add, or that can be undone, don't take it. |
| `--force`   | Override a refusal the tool raised itself, such as a failed precondition or a local file that would be overwritten. Never stands in for `--confirm`: a guarded verb that refuses needs both. |

`--confirm` gates only what can't be undone. A gate on every change trains callers to always pass
it, at which point it guards nothing. A missing `--confirm` is an error, not a silent dry-run: a
dry-run exits `0` having changed nothing, and a caller that doesn't inspect `meta.dry_run` would
believe it had succeeded. There is no `--yes`; `--confirm` is the gate a prompt would otherwise have
been.

## When the verb searches or filters

| Flag           | Meaning |
|----------------|---------|
| `--query TEXT` | Free-text search over whatever the vendor searches. For finding the thing; `--filter` is for narrowing once you know the field. |
| `--filter ...` | Narrow the result set by field. Where the vendor has its own query language (FQL, CQL, JQL), pass the expression through untouched and name the language in `--help`. A tool with no native language takes repeatable `key=value` pairs, all of which must match. Don't invent a third language in between. |

## When the verb gives a verdict

| Flag                | Meaning |
|---------------------|---------|
| `--fail-on-verdict` | Exit `6` instead of `0` when the tool's own answer is unfavourable: a gate below threshold, findings above a level. For CI. Off by default; see [Exit codes](0002-exit-codes.md). |

## Deliberately two calls

These rules aim for one call per question: batch lookups, names in place of IDs, `--fields all`,
self-contained cursors, and errors that report every problem at once. Three flows take two calls by
design, because the second call is where the caller decides something. Don't collapse them.

- **`--dry-run`, then `--confirm`.** The preview is the safety check.
- **The default cap, then `--all`.** `meta.total` in the first response says whether the second call
  is needed.
- **List, then fetch.** Summary records keep the list cheap, and batch lookups keep the fetch to one
  call instead of one per record.

## What to avoid

- **A second spelling of anything**: `--format json`, `--output json`, `--yes`, `--page`. Each one is
  a guess an agent has to get right per tool.
- **Shortened flag names.** Some parsers accept any unambiguous prefix (`--lim` for `--limit`) unless
  told not to. That gives every flag several spellings, and adding a flag later can break one a
  caller had come to rely on. Turn it off.
- **The parser's own error handling.** Its message, its usage text and its exit code all bypass the
  tool's error format. [Exit codes](0002-exit-codes.md) says how to take it over.
- **A flag or config file that carries a secret**, including a "convenience" flag for testing.
- **Behaviour that depends on whether a terminal is attached.** Colour is the only exception
  ([Output](0003-output.md)). The flags decide what a caller gets, not what its output happens to be
  connected to.
