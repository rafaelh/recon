# Spec 16: shared name servers and mail hosts as a relatedness signal

## Goal

Root domains that share an organisation's own name servers or mail hosts are found and offered as
candidates, because self-hosted DNS and mail are strong signs of common ownership, without ever
resolving a candidate.

## Behaviours

1. A name server or mail host is **self-hosted** only if it is in scope, or its address is inside
   an in-scope netblock or is a port-eligible dedicated address. Name servers and mail hosts on
   known providers, or whose address is shared infrastructure or of unknown owner, are never a
   signal and nothing is fetched for them. `resolutions.csv` NS rows and `email-posture.csv` MX
   entries gain a `self_hosted` marker.
2. An `nsreverse` stage, keyed on `keys.securitytrails` and available under `--passive`, fetches
   the domains hosted on each self-hosted name server and the domains whose MX is each
   self-hosted mail host, and records each as a candidate root with source `shared-ns` or
   `shared-mx`. Candidate roots are never resolved; this lookup is the only discovery path.
3. If a server has more than `nsreverse.max_domains` domains (default 1,000), none are recorded,
   the server is treated as not self-hosted for this purpose, and a `--verbose` warning names it.
   Changing the setting re-fetches. Quota exhaustion stops the stage as for other keyed sources.
4. A candidate found this way is at least `medium` confidence (Spec 15). Excluded roots stay
   excluded.
5. Without the key, the stage is `not-configured (no key)` and only the `self_hosted` marker is
   produced.
