# Concurrency

These tools spend almost all their time waiting on the network, so overlapping independent requests
is the biggest time saving available. Use it wherever requests don't depend on each other. The rules
below keep it from costing stability or correctness: the same input produces the same output, in
whatever order the responses happen to arrive.

Three things go wrong with overlapping work in every language: starting an unlimited number of
requests, a failure that stops the tool waiting while requests are still running, and results that
land in arrival order. Each rule below exists for one of those.

Languages that run tasks truly in parallel add a fourth: two tasks changing the same data at once.
See "Shared state" below.

## Where it applies

Fanning out is the command's job, never the client's. A client method is one call to the vendor, and
the command decides what runs alongside what.

Run together:

- The targets of a batch verb (see [Batch input](0009-batch-input.md)).
- Independent calls that build one result: several endpoints for one record, looking up several
  names ([Input validation](0005-input-validation.md)) or the names behind references
  ([Output](0003-output.md)).
- The remaining pages of a walk that pages by offset, once the first page has reported the total.
  Fetch only the pages needed to reach `--limit`.

Keep one after another:

- Walks that page by cursor: each page needs the token from the one before.
- A call that needs another call's result. Each target's chain still runs alongside the other
  targets' chains.
- Writes to the same record, or writes the vendor applies in order.
- Work that doesn't wait on anything. Decoding a response or rendering a table gains nothing from
  being made a task.

## Stability

- **A fixed number at a time, never one task per item.** Starting a request for every ID at once is
  the shortest code in most languages, and it sends a hundred requests for a hundred IDs. Run a
  fixed pool of workers over the input instead, as in the batch pattern below: 4 per vendor unless
  the vendor documents otherwise. A construct that admits the same fixed number at a time is
  equivalent. The number is not a flag; the tool knows its vendor better than the caller does.
- **One rate limiter per vendor, shared by every task.** The concurrency limit caps how many
  requests are in flight; the limiter ([Never hang](0004-never-hang.md)) caps how fast they start.
  Raising concurrency never raises the request rate. The limiter belongs to the client, so there is
  exactly one client per vendor in the process: build it once and pass it to every task.
- **Size the connection pool to the concurrency limit.** Every task shares the run's one HTTP client
  ([Never hang](0004-never-hang.md)). A pool that keeps fewer idle connections per host than the
  tool has in flight (Go's default keeps 2) opens a new connection, with a new TLS handshake, for
  most requests.
- **Every task runs under the invocation context** ([Never hang](0004-never-hang.md)), so the
  deadline and signals stop all of them, mid-wait included.
- **Every task catches its own failures** and records them as that item's error. The catch wraps the
  whole body of the task, so a failure raised before the first request is caught as surely as one
  raised by it. A task that lets a failure escape hands it to whatever is waiting on the group, and
  what happens next depends on the language (see below), never in a way a batch wants.
- **Only the command writes output.** Tasks return results; the command encodes and prints them once
  all are in. A task that printed its own record would print in arrival order. `--debug` logging is
  the exception: write each line with a single call, so lines from different tasks may interleave
  but never run into each other mid-line.

## Correctness

- **Results by position, not by arrival.** Make the result list the same length as the input before
  starting, and have each task write only its own element. No appending from tasks, no map filled as
  responses come in, nothing that collects in order of completion. Once every task has finished, the
  command walks the slots in order and sends each to `data` or to `meta.errors`
  ([Batch input](0009-batch-input.md)). Output is then identical from run to run, which is what
  makes it testable and comparable.
- **A failed item is data, not a reason to cancel.** In a batch, a task records its error in its own
  slot and moves on, so one failure never stops the others.
- **Know what "wait for all" does when one task fails.** Some stop waiting and return the error
  while the other tasks keep running with nobody watching; the tool may then print and exit with
  requests still in flight. Others cancel every remaining task. A batch wants neither, which is why
  no batch task ever lets a failure escape. For work that really is all-or-nothing, cancel the rest
  on purpose: give the group its own cancellation, derived from the invocation's, and trigger it on
  the first failure.
- **Stop starting writes; don't abandon sent ones.** When a batch of writes stops early, stop handing
  out items, but don't cancel the shared context: that cuts off every request already sent. Only the
  deadline or a signal cuts one off, and a write cut off that way has an unknown outcome. Its
  `meta.errors` entry says so, instead of reporting it as not applied.
  [Idempotency](0006-idempotency.md) makes the retry safe.
- **Tests prove it.** [Proving it](README.md#proving-it) describes the stand-in vendor that answers
  out of order and counts the requests it has in flight.

## Shared state

Where every task runs on one thread, as in JavaScript or a single-threaded async loop, two tasks
never touch the same data at the same instant. Where tasks run in parallel (threads, goroutines, a
multi-threaded async runtime), also:

- **Handing out the next item is safe to do from several workers at once**: a queue or channel, a
  lock, or an atomic counter.
- **Each task writes only its own slot** in the results, and nothing reads the results until every
  task has finished. That is what makes position-based results safe without a lock.
- **Anything else shared is built for sharing**: the client, its rate limiter, the debug logger.
- **Run the race detector in tests** where the language has one.

## The batch pattern

In outline, for any language:

```
results = a list with one empty slot per id        # in input order
next    = 0                                        # index of the next id to hand out

worker:
    repeat:
        i = next; next = next + 1                  # as one step that can't be interrupted
        stop if i is past the end of ids
        try:
            results[i] = record from client.get(context, ids[i])   # waits on the shared limiter
        on any failure:
            results[i] = that failure              # a failed target is data; don't stop the others

start min(concurrency, number of ids) workers
wait for all of them
walk results in order: records into data, failures into meta.errors
encode and print the envelope
```

## What to avoid

- **One task per item with no limit**, however short the code is.
- **A concurrency flag.** Callers will raise it, and the vendor will answer with rate-limit errors.
- **A limiter or client per task.** Each would pace itself, and together they would exceed the limit.
- **Collecting results as they finish**, then sorting to tidy up. Sorting hides the problem only
  when there is a key to sort by.
- **Printing from a task.**
- **Letting one failure cancel a batch of reads**, or cancelling writes already sent.
- **Fan-out inside a client.** A worker pool in a client means the tool's decisions have leaked into
  it.
- **Making work concurrent that doesn't wait on anything.** It adds ways to go wrong and saves no
  time.
