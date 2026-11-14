# Pagination

List verbs take three paging flags: `--limit N`, `--all` and `--cursor TOKEN`. Everything else about
paging is the tool's problem, not the caller's.

## Default cap

Every list verb caps its result at a default, 25 unless the verb has a reason to differ, shown in
`--help`. An agent's context is the scarce resource, and an uncapped list verb can put thousands of
records into a context that needed five. `--limit` changes the cap and `--all` removes it; passing
both exits `2`.

**A cap must announce itself.** Whenever a response holds fewer records than the query matched,
whether because of the default cap, `--limit` or a ceiling the vendor imposes, `meta.truncated` is
`true`, `meta.total` says how many matched if known, and human mode prints a footer with the
complete command that gets the rest. Twenty rows of four hundred, looking exactly like a complete
answer, is the failure a default cap creates.

## Internal paging

The tool asks the vendor for its largest page size, or just what it still needs to reach the limit
if that's smaller, so each invocation makes as few round trips as possible. Page size is not a flag:
it affects speed and never changes the result.

## `meta.next_cursor` is the only way to resume

Every list verb emits `meta.next_cursor` and accepts it back as `--cursor`, whatever the vendor
does. Vendors that page by cursor and vendors that page by offset look the same from outside.

There is no `--page` or `--offset`, because a caller can't work out where a response stopped: the
limit and the page size are different numbers, and a verb that filters after paging returns fewer
records than it walked. The cursor is the one way to resume. Keep going while `meta.next_cursor` is
not `null`, even through an empty page: a verb that filters after paging can return a page with no
matches while later pages still hold some.

**A cursor is self-contained.** The token carries the query that produced it, meaning every flag
that shapes the result except `--limit` and `--all`, together with the vendor's own token, or the
next offset where the vendor has none. `tool list --cursor X` resumes on its own. Rebuilding the
original flags by hand is where callers go wrong, and a wrong rebuild silently returns the wrong
page. `--limit` or `--all` may accompany `--cursor` and may change between pages, so
`tool list --cursor X --all` fetches everything after the first page without fetching that page
again. Any other flag passed alongside `--cursor` that differs from what the token carries exits `2`.

**A cursor is opaque to its caller, not to the tool that made it.** The token is the tool's own:
compact JSON, encoded as URL-safe base64 so it survives a shell unquoted. The tool decodes it and
checks every field before making any call. A token that won't decode, JSON of the wrong shape or a
negative offset exits `2`. Decoding into a loosely typed value and trusting it is not a check.

The vendor's token rides inside untouched. Never decode or validate that part: it is the vendor's
state, and a tool that parses it is one vendor change away from breaking.

## When a walk can't finish

A walk over several pages can fail partway: the deadline passes, or a page fails after its retries.
The pages already fetched are not thrown away. The tool prints them with `meta.truncated: true` and
a `meta.next_cursor` that resumes after the last record returned, and exits `7`. The error on stderr
says why it stopped, and its hint is the complete command that carries on. Where pages were fetched
side by side ([Concurrency](0010-concurrency.md)), return the unbroken run from the start and drop
anything after the first gap.

A failure before any page has arrived is an ordinary error, with stdout empty.

## What to avoid

- **A list with no cap**, or a cap that isn't in `--help`.
- **A truncated result that looks complete**, in either mode.
- **`--page`, `--offset` or `--page-size`**, even where the vendor offers them.
- **A cursor that needs the original flags repeated.**
- **Stopping at the first empty page.** Only a `null` cursor means the end.
- **Fetching more than the limit needs**, then throwing the extra away.
- **Throwing away the pages already fetched** because a later one failed. The caller would pay for
  the whole walk again.
- **Trusting a cursor because the tool made it.** A caller may have cut it short, edited it or
  passed one from another verb.
