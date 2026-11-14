# Idempotency

A caller that retries after a timeout can't know whether the first attempt landed. So repeating a
call is always safe, and its result says what happened.

| Operation                                          | Behaviour |
|----------------------------------------------------|-----------|
| Create; an identical record already exists         | Return the existing record with `meta.created: false`, exit `0` |
| Create; a record with the same unique key differs  | Exit `5` (`CONFLICT`), with a hint naming the verb that fetches the existing record |
| Update; nothing changes                            | Return the current record with `meta.updated: false`, exit `0` |
| Delete; the record is already gone                 | Return `{"id": ...}` with `meta.deleted: false`, exit `0` |

**Deleting something already gone is exit `0`, not `3`.** The caller's goal, the record not
existing, is met. A retry after a delete that succeeded but whose response was lost must not look
like a failure. Two things follow:

- A delete with a mistyped ID also exits `0`, with `meta.deleted: false`. A caller that needs to know
  the record existed checks that key.
- Retry by ID, not by name. Once the record is gone its name can no longer be looked up, so a
  retried delete-by-name exits `3`. The first call's output carries the ID.

## What to avoid

- **Passing the vendor's "already exists" or "not found" straight through** as an error on a create
  or delete. Work out whether the caller's goal is already met first.
- **A second record from a retried create.** Where the vendor has no unique key to check against,
  look for an existing match before creating, or use the vendor's own idempotency key if it has one.
- **Treating "same key, different content" as success.** That is a conflict; quietly returning the
  existing record hides the fact that the caller's change was not applied.
- **Hiding what happened.** `meta.created`, `meta.updated` and `meta.deleted` are always present on
  their verbs, and always truthful.
