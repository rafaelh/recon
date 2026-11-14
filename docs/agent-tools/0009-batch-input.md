# Batch input

Verbs that look records up by ID take many IDs in one call, so a question about ten records costs
one turn instead of ten.

## Rules

- **Lookup verbs take one or more IDs or names as positional arguments:**
  `cve CVE-2021-44228 CVE-2024-3094`. Names are handled as in
  [Input validation](0005-input-validation.md).
- **A lone `-` reads the targets from stdin**, one per line with blank lines ignored, for a list too
  long for a command line. The tool reads to the end of input before it starts any work.
- **One bad target doesn't sink the rest.** A malformed ID, a name that can't be found or a name
  that matches several records becomes an entry in `meta.errors`, and the other targets are still
  fetched, so the caller gets its valid results in the same turn. The format of every ID is still
  checked before the first request.
- **They always return a list envelope, even for one ID.** The output shape never depends on how
  many arguments were passed.
- **`data` keeps argument order**, without the targets that failed, and a target passed twice is
  fetched and returned once. So a record's position in `data` is not its position on the command
  line: match a record to its argument by `id`, and a failure by the `input` of its `meta.errors`
  entry.
- **Requests overlap**, following [Concurrency](0010-concurrency.md): a fixed number at a time, paced
  to the vendor's rate limit, and within the invocation's deadline.

## Partial results

Failures for individual targets go in `meta.errors`, which is always present. Each entry has the
five keys of the error format in [Output](0003-output.md), with the target exactly as it was passed
in `input`. The `hint` is where an ambiguous name lists its candidates, so the caller doesn't need a
second call to choose one.

```json
{
  "data": [{"id": "CVE-2021-44228", "severity": "critical"}],
  "meta": {"count": 1, "errors": [
    {"error": "not in the NVD", "code": "NOT_FOUND", "hint": null, "input": "CVE-2099-0001", "transient": false}
  ]}
}
```

| Outcome                                   | Exit | stdout |
|-------------------------------------------|------|--------|
| Every target succeeded                    | `0`  | The envelope, with `meta.errors: []` |
| Some succeeded                            | `7`  | The envelope, with `data` and `meta.errors` |
| None succeeded, all with one error code   | That code's exit: `3` when all are `NOT_FOUND` | Empty. The one error on stderr covers every target, and its `input` lists them |
| None succeeded, with different error codes | `7` | The envelope, with `data: []`, so each target keeps its own entry in `meta.errors` |

On exit `7` the error on stderr is `PARTIAL`: it counts what succeeded and what didn't, and its hint
says which targets are worth retrying.

Verbs that change several targets follow the same model: `data` holds what was applied and
`meta.errors` what wasn't, so the caller retries only the remainder. There is one difference. The
checks and name lookups that [Input validation](0005-input-validation.md) puts before the first
write cover every target, and a failure there fails the whole call with nothing written.

## What to avoid

- **A verb that takes exactly one ID** when the vendor can serve many. It turns one question into a
  loop of tool calls.
- **Failing the whole call for one bad target** on a read.
- **A bare record for one ID and a list for several.** The caller's parsing code would have to know
  how many arguments it passed.
- **Results in the order responses arrived.** The same call would print differently from run to run.
- **Exit `0` with errors in `meta.errors`.** A caller that checks only the exit code would miss them.
- **Leaving `meta.errors` out when there are none.** It is `[]`, every time.
- **A `meta.errors` entry with no `input`.** The caller can't tell which argument it belongs to.
