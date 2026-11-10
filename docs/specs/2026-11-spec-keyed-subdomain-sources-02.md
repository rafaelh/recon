# Spec 2: keyed subdomain sources that reuse existing keys

## Goal

Users who already hold a Shodan key get its subdomain data, and users with Censys or Chaos
subscriptions can plug them in, through the same keyed-source rules as today, without any
third-party DNS claim ever deciding what recon contacts.

## Behaviours

1. A `shodan-dns` stage uses `keys.shodan` to fetch each in-scope input root's subdomains and
   their A, AAAA, CNAME, MX and NS records. It is on whenever the key is set; the README states
   that each root costs one Shodan query credit per result page. Names under the root are
   recorded as hostnames (Spec 1 behaviour 3). In-scope CNAME, MX and NS targets are recorded as
   hostnames too.
2. DNS records known only from Shodan are shown in `resolutions.csv`, which gains a `source`
   column (`resolve`, `shodan`, or `resolve;shodan` when both saw the record). They never decide
   which addresses are contacted, port-checked or probed; they do not make a name resolved; they
   do not feed wildcard, provider, takeover or exclusion results. Only `resolve`'s own answers do
   those things. A name `resolve` finds NXDOMAIN but Shodan lists appears in both
   `unresolved.txt` and `resolutions.csv` (source `shodan`). A test with the harness canaries pins
   that a Shodan-only address is never contacted.
3. A `censys` stage uses `keys.censys` (a Censys personal access token) to search certificates
   whose names fall under each in-scope input root, recording the names under the root as
   hostnames (Spec 1 behaviour 3).
4. A `chaos` stage uses `keys.chaos` to fetch each in-scope input root's subdomain list; labels
   are joined to the root and normalised. A 404 or an empty list is an empty result.
5. Each stage is `not-configured (no key)` when its key is absent. A 401, 403 or 429 stops that
   stage for this run as for other keyed sources. No key, no part of a key and no encoding of a key
   appears in any output, event, file or warning.
6. Each stage follows result pages up to `<stage>.max_pages` (default 10). The cap is part of the
   check, so raising it repeats the checks; reaching it completes the check with a `--verbose`
   warning that the result was truncated. The existing sources' fixed page limits are unchanged.
7. The README's keyed-sources list adds `censys` and `chaos`; `--help` lists the stages.
