# Spec 9: third parties from SPF, DMARC and MX, and MTA-STS posture

## Goal

The user sees which outside services an organisation authorises to send its mail, receive its mail
reports or host its mailboxes, in the one third-party inventory, and whether each mail-receiving
root publishes an MTA-STS policy.

## Behaviours

1. For each in-scope input root, every domain the SPF walk follows (`include:` and `redirect=`,
   as far as the email check already goes) plus every domain named by `a:`, `mx:` or `exists:` at
   any level is a row in `third-parties.csv` with mechanism `spf`, the root, and the depth (the
   root's own record is depth 1). Arguments containing macros are skipped. A domain equal to or
   under an in-scope root, or sharing the registrable domain of the root it was found on, is not a
   third party. An include with no SPF record is still listed. A SERVFAIL on any include fails the
   root's email check as today, so that run records no third parties for the root.
2. Each DMARC `rua=` and `ruf=` URI (comma-separated, size suffix such as `!10m` removed,
   non-`mailto:` URIs ignored) contributes its mailbox domain with mechanism `dmarc`. The row
   belongs to the root whose policy it is, including when the policy came from the organisational
   domain.
3. Each MX host whose registrable domain is not in scope is a row with mechanism `mx`, using the
   host's registrable domain.
4. Each in-scope hostname whose CNAME chain ends at a provider entry of class SaaS is a row with
   mechanism `cname`. Wildcard-dropped and excluded names are not listed. `provider-hosts.csv` is
   unchanged.
5. One row per root, mechanism and domain. A `provider` column shows the provider name when the
   domain is on a built-in list of mail and SaaS providers named in the README (for example
   `_spf.google.com` shows Google); the domain is never replaced.
6. Third-party domains are not added to `candidates.csv`.
7. Rows follow the standard `current`, `first_seen`, `last_seen` columns. After `--redo email`
   (or `--redo dnsroot`, `--redo resolve` for the mechanisms those stages feed), a third party no
   longer referenced is marked not current.
8. A `+` line is printed per new third party as for other finds, and the summary shows
   `N third parties`. The stage runs under `--passive`.
9. For each in-scope input root with at least one non-null MX record, the email stage also reads
   the TXT records at `_mta-sts.<root>`. `email-posture.csv` gains an `mta_sts` column: `present`
   when exactly one TXT record there begins `v=STSv1`, `absent` otherwise, and empty for roots
   without MX. A subdomain root's value does not fall back to the organisational domain. A
   timeout or SERVFAIL on that lookup fails the root's email check, as for SPF and DMARC. Absence
   is the low finding `mta-sts-missing` in `risk-email.csv`, and the README row for that file
   mentions MTA-STS. The policy file over HTTPS is never fetched. The added lookup is part of the
   email check, so existing engagements re-run their email checks once.

# Design

**Status:** ready to build (wave 2). **Depends on:** Spec 3 (the `third_party` kind, its showing
rule, `third-parties.csv`, `provider.DomainOwner`) and Spec 15 (the runner's derived-records
hook); re-check both names once they have merged.

## Decisions

- **SPF, DMARC and MX third parties are observations of the email check.** `spfEval` already
  walks the record; it additionally collects `{domain, depth}` for each `include:` and
  `redirect=` it follows and each `a:`, `mx:` and `exists:` argument, skipping macros. DMARC
  `rua` and `ruf` are parsed from the record the check already holds. The check emits
  `third_party` observations beside `email_posture`, so a failed check records none (behaviour 1)
  and `--redo email` retires stale ones (the stage is already `Retiring`).
- **What counts as a third party is decided on read**, not in the stage: the stage drops only a
  domain sharing the registrable domain of the root it was found on; Spec 3's `OutsideAttr` rule
  hides any domain that is, or later becomes, in scope.
- **The domain is kept as written** for `spf` and `dmarc` rows (`_spf.google.com`), and is the
  registrable domain for `mx` rows. `provider` comes from `provider.DomainOwner`, whose
  `domains:` list this spec extends with mail and SaaS providers.
- **`cname` rows are derived, then stored**, so they are printed, counted and dated like the
  others: a `thirdparty-cname` deriver on the runner's hook (its input signature is the `hostname`,
  `resolution` and `wildcard` kinds and the inputs, not `third_party`, which stages also write) emits one `third_party` record per
  root and provider suffix for each in-scope, non-wildcard-only hostname whose CNAME chain ends at
  a SaaS-class entry. A row whose hostname stops pointing there loses its observation and goes not
  current, which is what `--redo resolve` produces. `provider-hosts.csv` is not touched.
- **MTA-STS is part of the email check**: when the root has a non-null MX, one TXT lookup at
  `_mta-sts.<root>`; `mta_sts` is `present` for exactly one `v=STSv1` record, else `absent`; a
  timeout or SERVFAIL fails the check. The check key gains a `|mta-sts` token so existing
  engagements run it once; the old checks are retired.
- **Finding**: `mta-sts-missing` (low) in the `email` category when `mta_sts` is `absent`.

## Changes

- `internal/stages/risk/email.go`: SPF collection, DMARC URIs, MX domains, MTA-STS, key token.
- `internal/kinds/table.go`: `MTASTS` at the end of `EmailPostureAttrs`.
- `internal/thirdparty/` (pure): the `cname` derivation. `internal/run/runner.go`: one deriver.
- `internal/provider/providers.yaml`: mail and SaaS `domains:` entries.
- `internal/output/evidence.go`: `mta_sts` column. `internal/findings/findings.go`, `table.go`.
- `README.md`: mechanisms, the provider list, `email-posture.csv` and `risk-email.csv` rows.

## Tests

`internal/cli/email_third_parties_test.go`, with `egresstest`:

- Includes two deep give depths 1 and 2; `a:`, `mx:`, `exists:` are listed; macros are skipped; an
  include with no SPF record is listed; a SERVFAIL on an include records nothing for the root.
- `rua`/`ruf`: several URIs, a `!10m` suffix, a non-`mailto:` URI, and a policy inherited from
  the organisational domain (the row belongs to the root).
- MX rows use the registrable domain; an in-scope MX host is not listed.
- A domain under another in-scope root is hidden, including when that root is added later.
- `cname` rows for SaaS chains only; wildcard-only and excluded names are not listed; the row goes
  not current after the CNAME changes and `--redo resolve`.
- One row per root, mechanism and domain; the `provider` column; nothing in `candidates.csv`;
  the `+` line and the `N third parties` count; the stage runs under `--passive`.
- MTA-STS: `present`, `absent`, empty without MX, no fallback for a subdomain root, SERVFAIL
  fails the check, the finding, and an existing engagement re-running its email checks once. The
  canaries see no HTTPS request for the policy file.

## Out of scope

Fetching the MTA-STS policy; TLS-RPT; resolving third-party domains.
