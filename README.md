# recon

Passive-first reconnaissance for an authorised engagement. Give it domains, organisations, ASNs or
netblocks and it records the hosts, IPs, web services, URLs and open ports it can find, plus a
severity-ranked list of obvious exposures (dangling CNAMEs, public cloud storage, weak email
policy, risky open ports, sensitive paths, expiring certificates). It is a single Go binary for
macOS and Linux, with no external tools to install.

## Install

```sh
go install github.com/rafaelh/recon/cmd/recon@latest
```

Go 1.21 or later is enough when `GOTOOLCHAIN=auto`, the upstream default: it fetches the toolchain
named in `go.mod`. Some Linux distributions' Go packages set `GOTOOLCHAIN=local`; check with
`go env GOTOOLCHAIN`, and if it says `local`, run `GOTOOLCHAIN=auto go install ...` instead. Set
`CGO_ENABLED=0` for a fully static Linux binary.

From a clone:

```sh
make build   # ./recon for this machine
make dist    # dist/recon-{darwin,linux}-{amd64,arm64}
make test    # vet, race tests, and a cross-target vet for all four platforms
```

`recon --version` prints the build's version (`devel` when there is none). Windows is not supported.

## Quick start

`output_dir` defaults to `.`, so run from a working directory outside this repository, or pass
`--output-dir`.

```sh
recon example.com                  # all stages; asks you to confirm authorisation on a terminal
recon example.com --passive        # third-party sources only; nothing at the target is contacted
recon example.com --authorised     # confirm authorisation up front (needed with --json or no terminal)
recon -e example-com               # re-run or resume an existing engagement by name
```

Results are written to `<output-dir>/<engagement>/` and summarised on the console.

## Inputs and engagements

- **Inputs:** positional domains, `-d <file>` (one root domain per line, `#` comments allowed),
  `--org <name>`, `--asn <AS123|123>`, `--cidr <netblock>`. The last three are repeatable. An ASN's
  announced netblocks become in scope.
- **Exclusions:** `-x <hostname|*.wildcard|CIDR>` (repeatable) and `--exclude-file <file>`. An
  excluded host, or any host that resolves into an excluded CIDR, is recorded as excluded and its
  addresses are never contacted.
- **Engagement name:** `-e <name>`, or derived from the first input: the first positional domain,
  else the first line of the domains file, else the first `--org`, `--asn` or `--cidr`. The
  derivation depends on the order of your inputs. Either way, the name is lowercased and sanitised.
- **Re-runs:** inputs and exclusions are added to those already stored for the engagement. Nothing
  is removed because you left it out of a later run.
- **Resume:** a re-run performs only the checks not yet done. Checks that failed (a transient
  error, not a negative result) are retried on later runs. An interrupted run resumes the same way.
- **`--redo <stage>`:** performs every check of one stage again. The stage names are listed in
  `recon --help`.
- **`--skip <stage>`:** turns a stage off (repeatable; the `skip` setting, or `RECON_SKIP` as a
  comma-separated list, does the same). A skipped stage is shown as `not-configured (skipped)`,
  whatever else would stop it, and does nothing: results it found earlier stay in the files. The flag
  replaces the setting for that run, and `--skip none` runs every stage. An unknown stage, a stage
  also given to `--redo`, and `resolve`, `wildcard`, `ipowner` and `providerranges` (other stages'
  safety depends on them) exit with code 2. When every stage that contacts the target is skipped,
  there is no authorisation prompt.

## Configuration

- **Config file:** `$XDG_CONFIG_HOME/recon/config.yaml`, which defaults to
  `~/.config/recon/config.yaml`. Use `--config <file>` to choose another. Unknown keys are
  rejected.
- **Precedence:** flags override `RECON_*` environment variables, which override the file. An
  environment variable is `RECON_<UPPER_SNAKE>` with `.` replaced by `_`, for example
  `RECON_RATE_PER_HOST` and `RECON_CRAWL_MAX_DEPTH`.
- **API keys:** set only as `keys.<source>` in the file or `RECON_KEYS_<SOURCE>` in the
  environment. There are no key flags, so keys never appear in shell history or process lists.
  Keys are redacted from all output and files.
- **Keyed sources:** `securitytrails`, `shodan`, `virustotal`, `whoisxml`, `censys` and `chaos`. A
  stage whose key is missing is shown as `not-configured`. `keys.shodan` also turns on `shodan-dns`,
  which lists each in-scope root's subdomains and their A, AAAA, CNAME, MX and NS records; it costs
  one Shodan query credit per result page, for each root. `keys.censys` is a Censys personal access
  token and searches certificates for names under each root. `keys.chaos` is a ProjectDiscovery
  Chaos key. A 401, 403 or 429 stops that stage for the run. Each of these three follows result pages
  up to `shodan_dns.max_pages`, `censys.max_pages` or `chaos.max_pages` (default 10; raising one
  repeats the stage's checks, and reaching one is reported with `--verbose`). Chaos answers with the
  whole list in one page, so its cap is not reached. `certspotter` takes an
  optional key: it runs without one, and sends `keys.certspotter` when it is set. The other sources
  need no key.
- **Settings:** all settings and their defaults are listed by `recon --help`.

Example `config.yaml` (a leading `~/` in `output_dir`, `wordlist` or `sensitive_paths` is your home
directory):

```yaml
output_dir: ~/engagements
concurrency: 10
keys:
  securitytrails: your-securitytrails-key
  shodan: your-shodan-key
  virustotal: your-virustotal-key
  whoisxml: your-whoisxml-key
```

```sh
RECON_KEYS_SHODAN=your-shodan-key recon example.com
```

## Passive boundary

recon limits what target-owned systems can receive. It sends only:

- **DNS lookups.** Zone transfers are never attempted.
- **TCP handshakes** to the configured port list. It reads only what the service sends
  unprompted and sends nothing.
- **HTTP(S) GET and HEAD requests** to in-scope, non-excluded hosts, to same-host links found
  while crawling, to each service's `/robots.txt` and `/sitemap.xml` and the same-host URLs they
  list (robots.txt is read, not obeyed), and to the paths on the sensitive-path list.

It never sends credentials, submits forms, uses other HTTP methods, puts payloads in parameters or
headers, or requests paths beyond those listed. UDP is not used. Candidate hosts (found but not in
scope) and excluded hosts are never contacted. Everything else comes from third parties: CT logs
(crt.sh and Cert Spotter), web archives, passive DNS and search (AlienVault OTX, HackerTarget,
urlscan.io and Anubis), public DNS resolvers, RDAP/WHOIS, BGP data, keyed APIs and cloud-storage
provider endpoints. Only hostnames are recorded from Cert Spotter, OTX, HackerTarget, urlscan.io and
Anubis. When one of these five reports that its free quota is spent, its stage alone stops, and its
checks are retried on the next run.

All network access goes through one package. On every supported platform, a test fails if any other
package imports a network package or `syscall`, or uses `golang.org/x/sys/unix` for anything other
than signals and file locking, and if any package imports `os/exec`.

## Passive-only mode

`--passive` restricts a run to third-party sources. The stages that contact target-owned systems
(`httpprobe`, `crawl`, `sensitive-paths`, `ports` and `takeover`'s HTTP fingerprinting) are
shown as `not-configured (passive-only)`. Takeover findings that DNS evidence alone supports are
still reported. The restriction applies to that run only; a later run without `--passive` performs
the skipped checks.

## Authorisation acknowledgement

Before any stage that contacts target-owned systems, recon requires you to confirm you are
authorised to test the engagement's scope.

- On a terminal, you can confirm at the prompt or with `--authorised` (`--authorized` also works).
- With `--json` or no terminal there is no prompt, and only `--authorised` counts.
- The confirmation is remembered per engagement.
- Without it, those stages are shown as `not-configured (no authorisation)`.

## Large netblocks

If the in-scope IPv4 address count (ASN-expanded netblocks included) exceeds `netblock_limit`,
recon stops before contacting any address in them, shows the total and exits with code 3. Re-run
with `--allow-large-netblocks` to proceed. The approval is remembered with the engagement.

## Console and JSON

The console shows each stage's state as it changes: `running`, `done` (with the number of checks and
failures), `done-previously`, `failed` or `not-configured` (with the reason). A `+` line is printed
for each find, with its severity for findings. A summary lists counts and the high and medium
findings. `--verbose` also shows warnings, including failed checks.

`--json` prints one JSON event per line on stdout, with no styling or prompts.

## Output files

Everything is in `<output-dir>/<engagement>/`:

| File | Contents |
|---|---|
| `scope.csv` | Inputs and the netblocks and roots in scope, and where each came from |
| `candidates.csv` | Related domains, organisations and netblocks found but not in scope; pass one as an input to promote it |
| `excluded.csv` | Excluded items and the reason |
| `subdomains.txt` | In-scope hostnames |
| `resolutions.csv` | DNS records for in-scope names, with a `source` column: `resolve` (recon's own lookup), `shodan` (reported by Shodan only) or `resolve;shodan`. Records only Shodan reports decide nothing: they never make a name resolved or an address contacted, port-checked or probed. |
| `unresolved.txt` | In-scope names that did not resolve |
| `wildcard-excluded.txt` | Names dropped because their domain answers every name (wildcard DNS) |
| `ips.csv` | Addresses with ASN, owner, hosting provider, scope, port eligibility and hostnames |
| `provider-hosts.csv` | Names that point at shared cloud or SaaS providers, with the evidence |
| `web-services.csv` | Web services found: status, title, server, technologies, redirects and TLS details |
| `urls.csv` | URLs from crawling and web archives, with status and source |
| `open-ports.csv` | Open TCP ports with the banner the service sent, if any |
| `email-posture.csv` | SPF, DMARC and MX results per root domain |
| `storage-unattributed.csv` | Guessed cloud-storage buckets that nothing in scope references |
| `risk-takeover.csv` | Subdomain takeover findings |
| `risk-storage.csv` | Cloud-storage findings: buckets that exist, are public or are listable |
| `risk-sensitive-paths.csv` | Sensitive paths that answered with their expected signature |
| `risk-email.csv` | SPF and DMARC weaknesses |
| `risk-ports.csv` | Open ports on the risky-port list |
| `risk-certificates.csv` | Expired or soon-to-expire certificates |

A file is only written when it has rows, so a missing `risk-*.csv` means no findings of that kind
(a file that later has no rows is removed). Files are sorted. Every CSV ends with `current`, `first_seen` and `last_seen` columns, and records
that were not found by a later run are kept and marked not current. The `.recon/` directory holds
the state database and the run lock. Don't edit it. Finding severities are listed by
`recon --help`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The run completed, including with failed checks or `not-configured` stages |
| 1 | Fatal runtime error, an engagement already locked by another run, or an output directory that is not a recon engagement |
| 2 | Invalid input or configuration. Nothing was contacted |
| 3 | The netblock limit was exceeded without `--allow-large-netblocks` |
| 130 | Interrupted (SIGINT, SIGTERM or SIGHUP). Completed work is saved; re-run to continue |

## Migrating from the Python version

- **Old output directories** are not resumable. recon refuses them (exit 1, naming the directory)
  and never writes into them. Use a different `-e` name, or move the old directory away.
- **Retired:** the `reconsite` single-site command and XSS and SQL injection testing are gone.
- **No external tools:** Amass, subfinder, massdns, httprobe, hakrawler, dalfox and the rest are
  no longer needed, and neither is `install.py`.
