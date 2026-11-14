# Input validation

Check everything that can be checked locally before the first network call or write. A mistake then
costs the caller one fast exit `2` with nothing changed, instead of a half-finished run or a vendor
error it has to decode.

## Order

1. Parse flags. The parser rejects unknown flags, and `main` makes that exit `2`
   ([Exit codes](0002-exit-codes.md)).
2. Check each value: fixed sets of values, ranges, ID formats, durations.
3. Check combinations: flags that can't be used together, flags that require another.
4. Check credentials and paths: a required environment variable that isn't set, a path that doesn't
   exist.
5. Turn names into IDs (see below). This is the first step that reads from the vendor.
6. **Then, and only then,** start the operation.

**Report every problem at once.** Steps 2 to 4 collect every failure instead of stopping at the
first, and exit `2` with all of them: `error` lists each problem and `input` echoes each failing
value. A caller with three mistakes fixes them in one retry, not three. Flag parsing in step 1 may
stop at the first unknown flag; that is how most parsers behave and it isn't worth working around.
Batch reads go further and fetch the valid targets anyway; see [Batch input](0009-batch-input.md).

**Do the checks in your own code.** Argument parsers offer built-in checks: a fixed set of choices,
required flags, conflicting flags, typed values. Each one stops at the first failure and reports it
in the parser's own words, so the caller sees one problem at a time. Checks written in the command
run together and are reported together. Where a parser check is used anyway, its error must still
be turned into `INVALID_INPUT` with exit `2`.

## Names as well as IDs

Wherever a verb takes the ID of something a caller knows by name (a project, a user, a team), it
also takes the name, slug or email and looks the ID up itself. Otherwise "add Sara to project Foo"
costs two lookup calls before the real one.

- Input that matches the ID format is an ID; anything else is a name. That works only when the ID
  format is distinctive (`CVE-2021-44228`, `rec_123`). Where IDs are bare numbers, or a name could
  look like an ID, take names through an explicit flag (`--name`) instead of guessing.
- One match: use it. The output carries the ID that was found, so the caller can pass that next
  time.
- Several matches: exit `2`, with the candidates and their IDs in the hint.
- No match: exit `3`, with the closest names in the hint where the vendor makes them cheap to find.

A verb that changes something looks up every name before its first write.

## Make the error the fix

- **Name the valid set.** An unknown value for a flag with a fixed set lists the valid values in the
  hint; an unknown field lists the valid fields. The caller fixes it in one try instead of reading
  `--help` first.
- **Accept variants that leave no doubt.** Tidy up letter case and surrounding whitespace where the
  format makes the meaning certain (`cve-2021-44228` becomes `CVE-2021-44228`). Reject anything that
  would need a guess.
- **Echo the failing value** in the error's `input`.

## What to avoid

- **Stopping at the first problem** when the rest could have been found in the same pass.
- **Letting the vendor do the validation.** A value the tool could have rejected comes back as a
  vendor error after a round trip, in the vendor's words, as exit `1`.
- **Starting work before every check has passed**, above all a write followed by a failed lookup of
  a later name.
- **Guessing.** Picking the first of several matches, or "correcting" input that could mean two
  things, turns a clear error into a wrong result.
- **An error that says a value is invalid without saying what would be valid.**
