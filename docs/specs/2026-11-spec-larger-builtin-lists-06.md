# Spec 6: larger built-in word and sensitive-path lists

## Goal

The default permutation wordlist and sensitive-path list are large enough to be useful without the
user supplying their own, and neither a large list nor a large target can make a run's request
count explode.

## Behaviours

1. The built-in permutation wordlist has between 2,000 and 5,000 entries: lowercase, unique, valid
   DNS labels, ordered most common first (the per-seed cap takes words from the front), assembled
   from MIT-licensed SecLists lists with attribution in the file header and the README.
   `--wordlist` continues to replace it. Permutations keep their current `--passive` status; the
   README states the lookup volume per root.
2. The built-in sensitive-path list has at least 150 entries, each with a body signature or byte
   prefix and an explicit severity. A test checks that each entry matches a sample of the real file
   and does not match a generic 200 page or a soft 404. `--sensitive-paths` continues to replace
   it.
3. The first run after upgrading repeats every permutation check once, because the list changed.
   Sensitive-path checks are performed for the new entries only; every existing built-in entry is
   kept unchanged so its hits stay current.
4. `permutations.max_names` (default 200,000) caps the names generated per run. Roots are taken
   before seeds, each in name order, and a root's or seed's names are never split across runs:
   once the next one would pass the cap, it and the rest are deferred, though the first is always
   taken even if it alone exceeds the cap. Deferral is not a failure; the stage shows `done`, and
   the console summary and the `--json` summary event give the deferred count. `max_per_seed` is
   unchanged. Names under a zone already known to be a wildcard are not generated.
5. `sensitive_path_max_requests` (default 50,000; 0 is invalid and exits 2; the setting is not
   nested under the existing `sensitive_paths` file setting) caps sensitive-path requests per run.
   Requests are taken entry by entry in severity order, then by service, so every service gets its
   highest-severity paths first; the remainder is deferred to later runs. A hit from an earlier run
   stays current in a run that defers other requests. Deferral is not a failure; the stage shows
   `done`, and the console summary and the `--json` summary event give the deferred count. The
   README states the request count formula (services × entries) and the time it takes at the
   default rate.
