# Field selection

Wide records cost tokens on every call, whether or not the caller needs the fields.

## Defaults

- **List verbs return a summary; lookups return the full record.** A list record carries the handful
  of fields needed to pick one: id, name, status, a date. The natural flow of list, choose, fetch
  then pays for full detail only on the records chosen.
- **`--fields a,b,c` overrides the default in either direction**, in both output modes. Add it once a
  record is wide enough that callers routinely pay for fields they didn't ask for.
- **`--fields all` returns every field.** A caller that knows it needs full records gets them from
  the list call, instead of listing and then fetching.
- **`id` is always included**, requested or not; the caller needs it for the follow-up call.
- **Field names are the JSON keys.** `--help` lists them, and an unknown name exits `2` with the valid
  names in the hint.

## Building it

Apply the selection as close to the data source as possible:

1. **Best:** pass it to the vendor (a `fields` parameter, a GraphQL selection, SQL columns), so the
   unwanted fields are never fetched.
2. **Acceptable:** pick the fields out of the record before encoding.

Either way, keep **one field table per record type**: a fixed table from each JSON key to the way
that field is read from the record. The same table does the selection, supplies the names for
`--help`, and checks the names a caller passes. With one table, the three can't disagree.

Where the type system allows it, make "a valid field name" a type derived from the table, so a typo
in the code fails to compile.

## What to avoid

- **Encoding the full record, decoding it into a generic map and deleting keys.** It does the work
  twice, loses the record's types and key order, and puts the field names in a second place.
- **A hand-written list of field names in the help text**, separate from the table. It will drift.
- **Different field names in the two output modes.** A human column heading may be prettier, but
  `--fields` takes the JSON key in both.
- **Dropping `id`** because the caller didn't list it.
- **Ignoring an unknown field name.** A silent typo returns records missing the field the caller
  wanted, and it will read that as "no value".
