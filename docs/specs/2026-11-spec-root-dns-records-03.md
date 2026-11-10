# Spec 3: root DNS records and the SaaS verification inventory

## Goal

For each in-scope root domain, recon records the name server, start-of-authority, TXT and CAA
records, so later pivots can use them, and from the TXT records tells the user which SaaS
platforms the organisation has verified domain ownership with.

## Behaviours

1. A `dnsroot` stage, available under `--passive`, performs one check per input root that is in
   scope and per record type (NS, SOA, TXT, CAA), through the same public resolvers as `resolve`,
   so a type that keeps failing does not block the others. Zone transfers are never attempted.
2. Each answer is a row in `resolutions.csv` with its type and value. A CAA value is written as
   `<flags> <tag> "<value>"`. An SOA value is the primary name server and the administrative
   mailbox written as an email address, with an escaped dot in the local part preserved
   (`john\.doe.example.com` becomes `john.doe@example.com`).
3. NS and SOA target names that are in scope are recorded as hostnames and are then resolved,
   probed and port-checked like any other hostname. NS targets outside scope are recorded in
   `third-parties.csv` with mechanism `ns`, the provider name when known and the domain otherwise,
   and are not candidates.
4. A root TXT record matching one of a fixed, case-insensitive prefix list is one row in
   `third-parties.csv` per platform and root, with mechanism `txt-verification` and the platform
   name. The list covers at least Google (`google-site-verification=`), Microsoft 365 (`MS=`),
   Atlassian, DocuSign, Facebook, Apple, Stripe, Adobe, HubSpot, Zoom, Dropbox, Salesforce, Have
   I Been Pwned and Cisco Webex, and is named in the README. The token appears in
   `resolutions.csv` (it is public DNS) but not in `third-parties.csv`.
5. A TXT record matching no pattern still appears in `resolutions.csv`; nothing else is inferred
   from it.
6. `third-parties.csv` is written only when it has rows and ends with the standard `current`,
   `first_seen` and `last_seen` columns. After `--redo dnsroot`, a record no longer present is
   marked not current.
7. NODATA and NXDOMAIN complete a type's check with no rows. SERVFAIL or a timeout is a transient
   failure for that type's check only.
8. The console `+` line for a new third party reads `third-party <platform> via txt-verification
   on <root>`; the `--json` `found` event carries the platform, mechanism and root.
