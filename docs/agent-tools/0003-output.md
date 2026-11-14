# Output

A tool has two output modes: human (the default) and `--json`. Both return the same records, with
the same limits and the same fields, so what a caller sees without `--json` predicts what it gets
with it.

## Streams

- **stdout carries the result and nothing else.** It holds a payload only when there is one: exit
  `0`, `6` and `7`. On every other exit, stdout is empty.
- **stderr carries everything else**: the error on a non-zero exit and, in human mode only,
  warnings and informational and progress lines (`-q` silences all but the warnings). Those lines
  are laid out as in [Log colours](../log-colors.md). Under `--json`, stderr is empty on success
  (`--debug` aside), so an agent capturing both streams pays only for the result.

**Never write an error to stdout.** A caller parses stdout as the result, and a stray message there
breaks the parse.

**Write only through the output streams the command was handed.** The entry point passes stdout and
stderr down as values, and nothing below it reaches for the process's global streams or a
print-to-console function. A test can then capture exactly what a run wrote, and a stray debugging
print can't end up in a result.

## Human mode

Colour a stream only when that stream is a terminal, `NO_COLOR` is unset (or empty) and `TERM` is
not `dumb`. Nothing overrides that: not `FORCE_COLOR`, not a CI variable. This is the one behaviour
that follows the terminal: it changes how output looks, never what it contains, and keeps escape
codes out of pipes and files. An agent harness that runs tools inside a pseudo-terminal should set
`NO_COLOR`.

Decide once per stream, at the top of the tool, from the stream it was given and the environment it
was given, and pass each decision down as a plain yes or no. stdout and stderr are decided
separately, so `tool 2> run.log` on a terminal writes a plain log beside a coloured table. Many
colour libraries decide for themselves by inspecting the process's real stdout and variables such
as `FORCE_COLOR`. A library that does that can't be pointed at the stream a test passes in, and
would override this rule, so use one that can be told.

Output is lines, each written once: no spinner, no progress bar that redraws, no cursor movement. A
harness's pseudo-terminal would hand every frame to the agent.

**Whatever `meta` says, human mode says too.** Anything in `meta` that changes how the result should
be read gets one plain line: on stdout after the records for a truncated list (with the command that
gets the rest; see [Pagination](0007-pagination.md)), a dry run, and a create, update or delete that
changed nothing; on stderr for a warning. A caller reading the table must not come away believing
something the envelope would have corrected.

## `--json`

One JSON object on stdout, with the `{data, meta}` envelope below.

- **Compact, not indented.** No whitespace between tokens at all. Indentation and newlines add
  tokens to every call and give an agent nothing; a person who wants them pipes to `jq`.
- **`data` is never a bare array at the root.** `meta` always accompanies it.
- **UTF-8, written as it is.** A URL with a query string or a name with an accent comes through
  unescaped.

## What goes inside the records

1. **The tool's own record type, never the vendor's response.** Convert vendor types into a type the
   tool owns. Vendor responses are nested and wordy, which costs tokens, and passing them through
   makes every vendor schema change a breaking change for callers. Keep the conversion in one
   place, so a vendor change is absorbed there and the tool's output stays the same.
2. **Flat over nested.** `{"user_id": "u_1", "user_name": "Sara"}` can be read in one step;
   `{"user": {"id": "u_1", "name": "Sara"}}` makes the caller reason about depth. Nest only when the
   data really is a hierarchy (order line items, a file tree).
3. **IDs are usable as given, and come with a name.** An ID appears in exactly the form the tool's
   verbs accept, so the caller passes it back unchanged. A field holding another record's ID is
   paired with that record's display name (`owner_id` and `owner_name`), because an ID alone forces
   a lookup to answer the obvious next question. Take the name from the vendor response where it's
   there; otherwise resolve references in one batched call, never one call per record.
4. **The same units and types everywhere.** Timestamps are RFC 3339 in UTC, at one precision.
   Durations are seconds and sizes are bytes, with the unit in the key (`age_seconds`,
   `size_bytes`). Numbers are JSON numbers, not strings. Where the language allows it, give
   timestamps, seconds and bytes their own types, each made by one function, so the compiler or type
   checker enforces the rule and review doesn't have to.
5. **Every key, every time.** Every field the call selected appears in every record: `null` when
   empty, `[]` for an empty list. The caller can then tell "this record has no CVSS score" from
   "this call didn't ask for CVSS" ([Field selection](0008-field-selection.md) decides which fields
   a call selects). The same holds for `meta`: its keys are fixed per verb, so a key a verb emits once
   it emits every time.
6. **Keys are snake_case, in a fixed order.** Declare each key once, alongside the record type,
   whatever the language's own naming style. The same record then encodes to the same bytes on
   every run, which is what makes output testable and comparable.

## Know your JSON encoder

Every encoder has defaults that break one of the rules above without any warning. Check each of
these in yours, and keep records to strings, numbers, booleans, `null`, lists and plain keyed
objects so there is less to check.

| Value | What an encoder may do | What the tool must emit |
|-------|------------------------|-------------------------|
| Whitespace | Indent by default, or put a space after every `,` and `:` | None |
| An empty value (null, none, nil, undefined, an unset optional) | Drop the key, by default or through an "omit if empty" option | The key, with `null` |
| An empty list | Encode a list that was never initialised as `null` | `[]` |
| A number that isn't finite (not-a-number, infinity) | Emit a bare `NaN` (not valid JSON), turn it into `null`, or fail | Decide before encoding. A score from a division by zero must not read as "no score" by accident |
| A date or time | Use its own format, the local time zone, or a precision that varies | RFC 3339 in UTC, through the one timestamp function |
| A map, set or object | Emit `{}`, emit its internal fields, or order its keys differently on each run | Plain records with fixed keys |
| An integer above 2^53 | Emit it correctly, after which the caller's parser rounds it | A string. In practice these are IDs, which are strings already |
| `<`, `>`, `&` and non-ASCII characters | Replace them with `\u` escape sequences, which cost more tokens and are harder to read | The characters themselves |

## Envelope shapes

Shown indented for readability; the tool emits them compact.

### List

```json
{
  "data": [
    {"id": "rec_123", "name": "Example", "status": "active"},
    {"id": "rec_124", "name": "Another", "status": "inactive"}
  ],
  "meta": {"count": 2, "total": 47, "truncated": true, "next_cursor": "eyJwYWdlIjogMn0="}
}
```

- `meta.count`: records in this response.
- `meta.total`: records matching across all pages; `null` when the vendor doesn't report it.
- `meta.truncated`: `true` whenever this response holds fewer records than matched.
- `meta.next_cursor`: token for the next page; `null` on the last. See
  [Pagination](0007-pagination.md).

Lookups by ID also return a list, even for one ID, with `meta.errors` in place of the paging keys.
See [Batch input](0009-batch-input.md).

### Single record

For verbs that act on exactly one target: create, update, a one-of-a-kind record such as `status`.

```json
{"data": {"id": "rec_123", "name": "Example", "status": "active"}, "meta": {"count": 1}}
```

### Change

`data` is the record as it now stands, so the caller needs no follow-up fetch. What the call did
goes in `meta`, never in the record: `created`, `updated` or `deleted` for the verb, and `dry_run` on
every verb that changes something. A delete returns only `{"id": ...}`, since there is no record
left to show.

```json
{"data": {"id": "rec_123", "name": "New Thing", "status": "active"},
 "meta": {"count": 1, "created": true, "dry_run": false}}
```

A verb that changes several targets returns a list in `data`, and its `created`, `updated` or
`deleted` key is the list of IDs the call changed instead of a boolean: `[]` when it changed none. A
record in `data` whose ID isn't in that list was already as requested.

Under `--dry-run`, `data` is the record as it would stand, in the same shape; fields the vendor
would assign, such as `id`, are `null`. A caller parses a dry-run with the same code that parses the
real thing, and `meta.dry_run` tells them apart:

```json
{"data": {"id": null, "name": "New Thing", "status": "active"},
 "meta": {"count": 1, "created": true, "dry_run": true}}
```

### Warnings

A success that comes with something the caller should know, such as a field the vendor has
deprecated or a source that answered with stale data, says so in `meta.warnings`, a list of strings.
A verb that can warn emits the key every time, `[]` when there is nothing to say. Under `--json` a
warning never goes to stderr.

## Errors on stderr

On any non-zero exit, the tool writes one error to stderr. Under `--json` it is one line of JSON,
always with all five keys:

```json
{"error": "No record matches id 'rec_99'", "code": "NOT_FOUND", "hint": "run 'tool list --limit 20' to see valid ids", "input": {"id": "rec_99"}, "transient": false}
```

- `error`: what went wrong, in plain English. When validation finds several problems, it lists them
  all.
- `code`: the error code, from the table in [Exit codes](0002-exit-codes.md).
- `hint`: what to try next. A complete command the caller can run where there is one, otherwise the
  exact flag to change; `null` if there's nothing useful to add.
- `input`: the failing argument or arguments, exactly as passed, so the caller sees what it sent
  without working it out from its history; `null` if no input was at fault.
- `transient`: `true` when retrying after a wait could succeed (timeout, 503, rate limit), `false`
  for permanent errors. The caller uses it to choose between retrying and reporting. A `PARTIAL`
  error is transient when any failure it summarises is.

In human mode the same error is plain text, with the code after the message:

```
error: No record matches id 'rec_99' (NOT_FOUND)
hint: run 'tool list --limit 20' to see valid ids
```

A transient error adds a third line, `retry: may succeed after a wait`. On exit `7` from a batch, one
more `error:` line follows for each target that failed. Neither mode sends the error through the log
formatter: it has no timestamp and no level.

**The mode must be known even when flag parsing fails.** Before handing the arguments to the parser,
`main` scans them for `--json` and `-J` itself, so `tool --bogus --json` still gets a JSON error.

## Compatibility

Once a tool is distributed, its `--json` output, error codes and exit codes are its API. Adding a
field, a `meta` key or an error code is compatible. Renaming or removing any of them, changing a
field's type or unit, or changing which exit code an outcome gets is a breaking change and needs a
major version. Human output carries no such promise.

## What to avoid

- **Anything on stdout that isn't the result**: a progress line, a warning, a "done", a deprecation
  notice from a library.
- **Different records in the two modes.** A human table that shows a column `--json` lacks, or the
  reverse, makes one mode useless as a guide to the other.
- **Passing the vendor's response through**, whole or trimmed.
- **A key that comes and goes.** Check for "omit if empty" settings on every field.
- **Numbers as strings, and units in values** (`"5 MB"`, `"3h"`). Put the unit in the key.
- **Several JSON objects or lines on stdout.** One invocation, one object.
- **A colour library that makes its own decision.**
- **Printing from a library or helper.** Only the command writes the result, once, at the end.
