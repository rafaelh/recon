# Spec 15: ranked candidates

## Goal

The user can tell at a glance which candidates in `candidates.csv` are worth promoting to scope,
because each shows how many independent signals support it and a confidence level.

## Behaviours

1. `candidates.csv`'s `found_by` column is replaced by `sources` (the distinct stages or
   mechanisms that observed the candidate, `;`-joined, allowed values listed in the README),
   `evidence_count` (the number of distinct source-and-supporting-item pairs, where the supporting
   item is the address, root, name server or record that linked the candidate) and `confidence`
   (`low`, `medium`, `high`).
2. Sources are grouped into families: certificate transparency (crt.sh, Cert Spotter, Censys),
   web archive (Wayback, Common Crawl), passive DNS (OTX, VirusTotal, SecurityTrails, Shodan,
   Chaos, urlscan, Anubis, HackerTarget hostsearch), reverse IP, registrant (RDAP, reverse
   WHOIS), shared infrastructure (shared NS or MX) and web identifier. Confidence is `high` when a
   registrant-family match of the input organisation (by the word rule of Spec 8) is joined by any
   other family, or three or more families agree; `medium` with two families, or one of: a shared
   self-hosted name server or mail host, reverse IP on two or more addresses, or a registrant
   match alone; `low` otherwise. Without an `--org` input the registrant match rule does not
   apply. The README states these rules.
3. `candidates.csv` is sorted high first, then evidence count descending, then value. Rows that
   are not current sort last and show the confidence they last had.
4. The console summary lists up to 20 `high` candidates with the input that promotes each (a root
   or hostname as a positional domain, a netblock as `--cidr`, an autonomous system as `--asn`, an
   organisation as `--org`), then `and N more in candidates.csv`. `--verbose` also lists `medium`
   candidates. `--json` emits one `candidate` event per high candidate.
5. Confidence is recomputed on every run from current evidence. After `--redo` of the stage that
   found a candidate's support, a candidate no longer supported drops a level.
