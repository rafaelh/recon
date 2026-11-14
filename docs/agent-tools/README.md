# Agent tools

A language-neutral design for command-line tools that AI agents call as often as people do. Each
document says what one part of a tool is for, the rules that follow from that, and what to avoid.
None of them assumes a language. Build them with whatever your language and its libraries offer,
whether that is Python, Rust, Go, TypeScript or something else.

Where a document names a language or library, it is an example of a trap, not an instruction to use
it.

## Why agents change the design

An agent uses a tool differently from a person at a terminal, and each difference drives a rule.

- **Every call costs a turn.** The agent starts a process, reads the result and reasons again before
  it can do anything else. So one call should answer one question: look up many IDs at once, accept a
  name where an ID is expected, report every mistake in one error.
- **Every byte of output costs context.** The agent reads all of it, every time. So output is
  compact, lists are capped, and wide records are trimmed to the fields that matter.
- **It sees only stdout, stderr and the exit code.** It can't skim, scroll back or notice that
  something looks off. So each stream has one job, the exit code says which kind of outcome
  happened, and every error says what to do next.
- **It can't answer a prompt, and may never close stdin.** A tool that waits for either waits
  forever. So nothing prompts, and every run has a deadline.
- **It retries.** After a timeout it can't tell whether the first attempt landed. So repeating a call
  is always safe.

A person still gets a readable default: tables, colour on a terminal, plain-text errors. The two
modes return the same records, so what a person sees predicts what an agent gets.

## The documents

| #  | Document | What it settles |
|----|----------|-----------------|
| 1  | [Flags](0001-flags.md) | The flags every tool shares, help text, and where secrets come from |
| 2  | [Exit codes](0002-exit-codes.md) | Which exit code means what, and who is allowed to choose one |
| 3  | [Output](0003-output.md) | stdout and stderr, the `{data, meta}` envelope, record shape, the error format |
| 4  | [Never hang](0004-never-hang.md) | No prompts, one deadline, pacing, retries, signals |
| 5  | [Input validation](0005-input-validation.md) | Check everything before the first call, and accept names as well as IDs |
| 6  | [Idempotency](0006-idempotency.md) | What a repeated create, update or delete returns |
| 7  | [Pagination](0007-pagination.md) | The default cap, `--all`, and self-contained cursors |
| 8  | [Field selection](0008-field-selection.md) | Summary records, full records and `--fields` |
| 9  | [Batch input](0009-batch-input.md) | Many targets in one call, and partial results |
| 10 | [Concurrency](0010-concurrency.md) | A fixed number of requests at a time, and output that never depends on arrival order |

Each rule is stated in one document and linked from the others, so a change is made in one place.
The layout and colours of the log lines a tool writes to stderr are in
[Log colours](../log-colors.md).

These documents cover how a tool behaves. How a repository of tools is laid out, and what code they
share, is each project's own decision.

## Terms

| Term | Meaning |
|------|---------|
| Tool | One command-line program. |
| Verb | One subcommand of a tool: `list`, `get`, `create`. A small tool may be a single verb. |
| Caller | Whoever ran the tool: an agent, a script or a person. |
| Invocation | One run of the tool, from start to exit. |
| Vendor | The remote system a tool talks to, such as an API or a database. |
| Client | The code that talks to one vendor. |
| Record | One item in the tool's output, in a shape the tool owns. |
| Envelope | The `{data, meta}` object that wraps every `--json` result. |
| Lookup | A verb that fetches specific records by ID or name. |
| List | A verb that returns whatever matches, a page at a time. |
| Cursor | The token a list verb returns so the next call can carry on where it stopped. |
| Verdict | The tool's own pass or fail judgement about what it found, as opposed to whether it ran. |

## Using these with a new language

Most of the work in a new language is finding out what its libraries do by default, because several
rules exist to override a default:

- **The argument parser.** What does it print and which exit code does it use on a bad flag? Does it
  print help after an error? Does it accept shortened flag names?
- **The JSON encoder.** Does it add whitespace, drop empty values, escape characters or reorder keys?
- **The HTTP client.** Does it have a timeout if you set none? Does it reuse connections? Can a
  request in flight be cancelled?
- **The runtime.** What happens on an uncaught failure, on Ctrl-C, on a hard exit with output still
  buffered? Does anything load a `.env` file for you?

Each document has a "What to avoid" section that names the traps to look for.

## Proving it

Every rule here is something a caller can observe, so one test can check them all. Run the whole
tool the way a caller would, against a local HTTP server standing in for the vendor, and check:

- The exit code for a bad flag, an invalid value, a record that isn't found and a vendor failure.
- stdout is empty on every exit except `0`, `6` and `7`.
- Under `--json`, stderr is empty on exit `0` and holds one line of JSON with all five keys on every
  other exit.
- A successful result is one compact envelope.
- A call with several targets, where the stand-in answers the first ID last and counts the requests
  it has in flight: `data` follows argument order, and the count never passes the concurrency limit.
- The same call with one target the stand-in rejects: exit `7`, the other records in `data`, and the
  rejected target in `meta.errors` with its `input`.

For that test to be possible, the tool takes three things as inputs instead of reaching for them:
its output streams, the vendor's base URL, and the way it reads environment variables.
