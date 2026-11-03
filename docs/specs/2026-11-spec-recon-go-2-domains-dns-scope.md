# Spec 2 of 6: recon (Go) — Domains, DNS and scope

## Goal

Build the list of the target's hostnames and IPs from domains, organisation names and netblocks,
using third-party sources and DNS, and classify each by ownership so later stages contact only the
target's own infrastructure. Depends on Spec 1 (definitions of scope, candidates, checks and the
passive boundary).

## Behaviours

1. Subdomains of in-scope roots are gathered from keyless passive sources (e.g. CT logs, web
   archives). Keyed sources run when a key is configured and are shown as not-configured otherwise.
2. Permutations of subdomain labels found by sources, certificates, crawling or reverse DNS, plus a
   configurable wordlist, are resolved via public resolvers. This is on by default (including in
   passive-only mode) and can be disabled. Permutations are never generated from other
   permutations.
3. Discovered names are resolved (A/AAAA/CNAME). Names that don't resolve are recorded as unresolved.
   A resolution timeout is a transient failure (Spec 1.8), not a takeover signal.
4. Names that resolve only because of a wildcard record are identified and excluded from later
   stages, except that one representative name per wildcard is HTTP-probed.
5. Names whose CNAME points at a known cloud/SaaS provider are passed to takeover checks (Spec 5.1),
   whether or not the chain resolves.
6. Organisation-name pivots (CT certificate organisation; reverse WHOIS as a keyed source) record new
   root domains as candidates, and ASN lookups for the organisation record netblocks as candidates.
   Candidates are not enumerated.
7. User-supplied ASNs/CIDRs are in scope. Hostnames for in-scope IPs are found via reverse DNS and
   passive sources; those not under an in-scope root are recorded against the IP and as candidates.
   IPv4 netblocks are swept in full (subject to Spec 1.15); for IPv6 netblocks, only addresses found
   by other stages are checked.
8. Hosts and IPs recognised as shared provider infrastructure (AWS/Azure/GCP PaaS, CDNs, SaaS
   platforms, shared hosting) are labelled with provider and service.
9. An IP is eligible for port checks only if it is an in-scope IP, or an in-scope hostname resolves
   to it and it is not recognised as shared provider infrastructure. Other IPs are recorded with
   their owner (provider or ASN name) but never port-checked. IPv4 and IPv6 are treated alike.
