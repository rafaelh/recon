# Spec 5 of 6: recon (Go) — Risk findings

## Goal

Turn what Specs 2–4 discover into a severity-ranked list of obvious exposures, without exploiting
anything. Depends on Specs 1–4.

## Behaviours

1. Every finding has a severity (high, medium or low). Each finding type has a documented default
   severity. Unattributed storage findings are never listed in the summary as high or medium.
2. **Takeover candidates:** DNS records pointing at cloud/SaaS resources that look unclaimed according
   to known fingerprints are flagged. In passive-only mode only DNS evidence is used.
3. **Cloud storage, attributed:** buckets/containers referenced by in-scope DNS records or discovered
   URLs are reported as attributed, recording whether they exist, are public, and are listable. For
   listable ones, an object count and the first few key names are recorded, never object contents.
4. **Cloud storage, unattributed:** names guessed from company and domain names (capped per root,
   configurable) are checked on AWS, Azure and GCP and reported separately as unattributed, never as
   attributed findings. Storage checks run in passive-only mode.
5. **Exposed sensitive paths:** each path in a configurable list is requested once per live web
   service per run, and not again on later runs unless the earlier request failed transiently or the
   stage is redone. This applies to company hosts behind CDNs, on shared hosting and on
   company-specific PaaS hostnames, but not to hostnames served by third-party SaaS platforms.
   Responses matching the path's expected signature are flagged, recording URL, status, size and the
   matched signature; response bodies are not stored.
6. **Email posture:** MX, SPF, DMARC and common DKIM selectors are read for each in-scope root.
   Flagged: SPF missing, `+all`/`?all`, or more than 10 DNS lookups; DMARC missing or `p=none`; a root
   with no MX lacking a `v=spf1 -all` record. DKIM selectors found are recorded; not finding one is
   informational only.
7. **Risky open ports:** open ports on a configurable list (e.g. RDP, SMB, Telnet, database ports) are
   flagged.
8. **Certificate issues:** expired certificates, certificates expiring within a configurable number
   of days, and self-signed certificates are flagged.
