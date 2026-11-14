# Never hang

The worst thing one of these tools can do is wait forever and say nothing. It is worse than
crashing: the caller can't tell whether to wait longer or kill the process, and an agent whose tool
call is killed by its own timeout gets no output to reason about at all.

## Never wait for input

- **No verb prompts, even on a terminal.** Permission arrives as `--confirm`, and a verb missing a
  required flag exits `2` naming it. Most human-facing CLIs prompt when attached to a terminal, but
  some agent harnesses run commands inside a pseudo-terminal, so a terminal doesn't mean a person is
  there. That rules out every way of asking: the language's built-in "read a line" function,
  password prompts and prompt libraries.
- **Stdin is read only when an argument is `-`** ([Batch input](0009-batch-input.md) gives the
  format). An agent's stdin may be an open pipe that never closes, and a tool that reads it without
  being asked blocks forever. Don't touch stdin otherwise, not even to check whether it has data.
- **Nothing else that waits on a person**: no pager, no editor, no opening a browser.
- If a tool grows an interactive mode, it is a separate subcommand, and everything it can do is also
  available from a flag-driven verb.

## Time budget

The deadline comes from `--timeout` and travels with every call. Pacing, retry and backoff all
happen inside it, in the code that talks to the vendor.

- **One deadline for the whole invocation.** `--timeout` (default `60s`) sets it. `main` builds one
  **invocation context** and every call that can wait receives it. The context carries two things: a
  way to cancel, which fires when the deadline passes or a signal arrives, and the deadline itself
  as a point in time. Being told *that* a run was cancelled is not enough: the code making a request
  needs to know *when* it will be, so it can refuse a wait that would overrun. Some languages carry
  both in one standard value; in others you pass the pair together. Measure the deadline on a clock
  that only moves forward, not the wall clock, which can jump.
- **The default sits under the caller's own timeout.** Agent harnesses kill a tool call after a fixed
  time (Claude Code's is two minutes). At `60s` the tool reports its own timeout (exit `1`,
  `TIMEOUT`, `transient: true`) before the caller kills it with no explanation.
- **Every request carries the context.** No network call without it, in the tool or in a library it
  uses. Many HTTP libraries have no timeout at all unless one is set, and that default is how a tool
  hangs.
  Below `main`, a new timeout or cancellation only ever narrows the invocation's: it is derived from
  it, and fires no later. One that stands alone makes a request that neither the deadline nor a
  signal can stop.
- **Reuse connections.** Build one HTTP client for the run and send every request through it, so
  connections to the vendor stay open and are reused. Don't switch that off, and don't make a new
  client per request.
- **Stay under the vendor's rate limit.** Where the vendor publishes one, pace requests on the
  tool's side to match it, using the limit that applies with or without a credential: NVD allows 5
  requests per rolling 30 seconds without an API key and 50 with one. Retrying a "too many requests"
  response is the fallback, not the plan; a batch that trips the limit spends its deadline waiting.
- **Pace with a sliding window that matches the vendor's.** Record when each of the last N requests
  started; a request may start once the oldest of them has left the window. Where the next free slot
  falls after the deadline, fail at once as `RATE_LIMITED` with the wait in the hint, instead of
  waiting to time out.
- **Retry transient failures inside the tool, within the deadline.** Reads retry network errors,
  429 and 502/503/504 up to twice, with exponential backoff and jitter, honouring the vendor's
  `Retry-After` header. If the wait would overrun the deadline, fail at once with `transient: true`
  and the wait in the hint. Each retry absorbed here saves the agent a round trip. A write is
  retried only when the failure proves the vendor never applied it: a 429, or a connection that was
  never made. After anything else the outcome is unknown, and the retry is the caller's.
- **Every wait can be cancelled.** Backoff and pacing waits end early when the context is cancelled.
  A plain sleep keeps waiting after the run has been cancelled, so never use one.
- **Signals cancel the invocation.** SIGINT and SIGTERM cancel requests in flight, and the tool
  exits `130` or `143` (see [Exit codes](0002-exit-codes.md)).

## What to avoid

- **A request with no timeout**, including the one made by a vendor SDK or a helper that builds its
  own HTTP client.
- **A timeout per request in place of a deadline for the run.** Ten requests at 30 seconds each is a
  five-minute tool. Per-request limits are fine only when derived from the invocation's deadline.
- **A sleep that can't be interrupted**, in backoff, pacing or polling.
- **A token bucket or a fixed-window counter for pacing.** A bucket that holds N and refills at N per
  window lets through up to 2N−1 requests in a rolling window. A fixed window lets through 2N across
  its edge. Both trip the vendor's limit. A bucket that holds 1 is safe, but makes even a small
  batch wait a full interval per request.
- **Waiting out a delay that can't fit.** If the retry or the next pacing slot lands after the
  deadline, say so now.
- **Reading stdin "just in case".**
- **Retrying a write** because the response was lost. The caller retries it, and
  [Idempotency](0006-idempotency.md) makes that safe.
- **Blocking work that ignores cancellation**, such as a synchronous call inside an otherwise
  cancellable task. Find out what your runtime can't interrupt and keep it short.
