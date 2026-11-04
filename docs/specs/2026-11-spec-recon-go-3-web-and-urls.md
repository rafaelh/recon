# Spec 3 of 6: recon (Go) — Web services and URLs

## Goal

Identify every web service the target exposes and the URLs behind them, contacting them only as an
ordinary browser would. Depends on Specs 1 and 2. Not run in passive-only mode except behaviour 6.

## Behaviours

1. Each resolved, non-wildcard, in-scope, non-excluded hostname (including those on shared provider
   infrastructure) and each wildcard representative is checked for HTTP and HTTPS on ports 80 and
   443, and on any open port found to speak HTTP(S).
2. Open HTTP(S) ports on in-scope IPs with no in-scope hostname are recorded as web services by IP
   and receive the same checks as hostname-based services.
3. For each live service the run records URL, status, title, server, technologies identified from
   headers, cookies and page markers, redirect target, and TLS certificate subject, SANs, issuer and
   expiry. Invalid, expired or self-signed certificates are still recorded and don't stop the probe.
4. Redirects are recorded and followed only while they stay on in-scope, non-excluded hosts; an
   out-of-scope redirect target is recorded as a candidate and not requested.
5. Hostnames in certificate SANs that are in scope flow through all stages; others are recorded as
   candidates. Wildcard SANs (`*.example.com`) contribute their base name only.
6. Historical URLs for in-scope hosts are recorded from public archives; they are never requested.
   This runs in passive-only mode.
7. A light crawl of each live service follows same-host links only, to a configurable maximum depth
   and page count, using GET only, never submitting forms, and without regard to robots.txt. Found
   URLs are recorded.

# Design

## Decisions

| # | Decision | Answer | Rationale |
|---|----------|--------|-----------|
| D1 | Stages | Two new `Target` stages, `httpprobe` and `crawl`, registered after `ipowner` (and after Spec 4's port stage once it exists). B6 extends the existing `ThirdParty` stages `wayback` and `commoncrawl` | Spec 1 says `Contact` is single-valued. The archive stages already download every URL and keep only the hosts, so B6 adds no requests and runs under `--passive` |
| D2 | Hostname targets (B1) | Every name in `View.ProbeHostnames()` gets check `h:80` (http) and `h:443` (https). It covers resolved, in-scope, non-excluded, non-wildcard-only names, plus one representative per wildcard zone, including names on shared infrastructure | Spec 2 D12 requires `ProbeHostnames()`. The conventional scheme per port is used; see the amendments |
| D3 | `open_port` contract (Spec 4 must honour it) | Kind `open_port`, key `netip.AddrPort.String()` (IPv6 bracketed), attrs `ip`, `port` (int) and `banner` (string). A port with a non-empty unprompted banner is never HTTP-probed. Tests use a fake stage that emits these records | Spec 4 isn't built. Spec 1 B9 already names IP+port as the natural key. HTTP servers never speak first |
| D4 | Port detection, once per address and port (B1, B2) | One check per `open_port` record with an empty banner, key `port\|<addrport>`. Its **representative** is the lexicographically smallest `ProbeHostnames()` name that resolves to the address. If no such name exists and the address is `Scope.InScopeIP`, the representative is the IP literal (B2). Otherwise there is no check. Ports 80 and 443 whose representative is a hostname are skipped, because D2 covers them. A representative that already has a detection check on that port, through an earlier-sorting address, is skipped too (D5). The request is `egress.RootAt(rep, scheme, port, addr)`: it dials only the check's address, and egress refuses it unless that address is one of the name's permitted addresses. Scheme: 80 is http and 443 is https. Any other port tries https first, then falls back to http on any `NoService` except `Refused` (connection refused). A live answer emits the representative's `web_service`, plus an internal `http_port` record (key addrport, attrs `scheme` and `host` = the representative) | A port is tested once, not once per vhost. Without this, a shared in-scope IP with 50 names would spend up to 2×15 s per name on RDP or SMB. Pinning the dial keeps `http_port` true for its address. A name on several addresses would otherwise be answered by whichever address egress dials first. Falling back only on `TLSFailed` would miss plain servers that reset or hang on a ClientHello |
| D5 | Vhosts on detected ports | For each `http_port` record, every other `ProbeHostnames()` name that resolves to its address gets check `h:<port>` with the recorded scheme. These checks appear in the pass after detection, and passes repeat (Spec 1 D5) | Hostnames are only probed on ports known to speak HTTP. The representative is stored on the record, so its check is not duplicated when an earlier-sorting name appears later. `Checks()` yields each (host, port) once across D2, D4 and D5, except that a pinned detection check (D4) counts only for its own address: a name that is the representative of one address and a vhost of another answering address is probed at both. For example, a host with two addresses that both have 8080 open gets one detection check, and an IP-literal `http_port` on 443 never duplicates a later hostname's `h:443` |
| D6 | IP services in egress (B2) | `TargetHTTP` gains an IP-literal path. When the host parses as a `netip.Addr`, the request is allowed iff `Scope.InScopeIP(a)` and not `Scope.ExcludedFor(a, shared)`. Egress dials that address and sends no SNI. The Host header is the literal. URLs bracket IPv6 even on default ports (today `do()` sets `u.Host = host` on 80/443). `Link` and `Redirect` from an IP response follow the same rule | Today egress refuses IP literals three times over: `ClassifyHost` returns Candidate, the malformed-host check rejects `:[]`, and `vetted` has no resolution for them. Spec 1's verification left this to Spec 3 |
| D7 | Live service | Any egress `Response`, whatever its status, is live. `NoService` and `Refused` complete the check with no record | B3. Spec 1 D14 |
| D8 | `web_service` record (B3) | Key: origin URL with any default port omitted (`https://a.example.com`, `http://[2001:db8::1]:8080`). **From the first response:** `status`, `redirect` (Location), and the TLS attrs `tls_subject`, `tls_sans` (DNS and IP SANs, `;`), `tls_issuer`, `tls_expiry` (leaf NotAfter as a UTC `YYYY-MM-DD`), `tls_error` (`CertVerifyErr`) and `tls_self_signed` (`leaf.CheckSignatureFrom(leaf) == nil`). **From the last page reached in the followed chain (user):** `final_url`, `title`, `server` and `technologies`. Also recorded: `url`, `host`, `port` and `scheme` | (user) A 301 to a login page then shows the login page. TLS comes from the service's own first response, so an http service never borrows another host's certificate (Spec 5.8 reads these attrs). Egress already skips verification and still reports `CertVerifyErr` |
| D9 | Title | Parse `text/html` with `golang.org/x/net/html` (already in `go.mod`). Take the first `<title>`, collapse whitespace, cap it at 200 runes and replace invalid UTF-8 | No new dependency |
| D10 | (user) Technologies | `github.com/projectdiscovery/wappalyzergo` (MIT). Its `Fingerprint(headers, body)` is fed egress's `Header` and `Body`; cookies arrive through `Set-Cookie`. One instance per process via `sync.OnceValues`. If loading fails, httpprobe warns and `technologies` stays empty. Results are sorted and joined with `;`. `X-Powered-By` is covered by its fingerprints | Thousands of maintained fingerprints. `go list -deps` shows no `net`, `net/http` or `os/exec`; its only third-party dependency is `x/net/html`. It adds about 4 MB to the binary |
| D11 | Redirects (B4) | Follow up to 10 hops with `egress.Redirect`, using a visited set. Before following each hop, emit a `url` observation for the target and a `hostname` observation for its host, **unless that host is the check's own host or an IP literal**. Scope then classifies the host as in scope, candidate or excluded. Egress refuses out-of-scope, excluded and unresolved in-scope targets, and the chain stops with nothing sent. An unresolved in-scope target is resolved and probed as its own service in a later pass | B4 records candidates even when the request is refused. Emitting the probed host itself would turn permutation-only names into seeds (Spec 2 D14, via `Record.Stages`). IP literals would land in candidates.csv because `ClassifyHost` returns Candidate for every IP |
| D12 | SANs (B5) | For each leaf `DNSNames` entry, emit `hostname`. `*.x.example.com` contributes `x.example.com`. The check's own host and malformed names are skipped (`input.ParseDomain`). IP SANs are recorded in `tls_sans` only | B5. SAN names become permutation seeds through the existing Spec 2 D14 rule, as Spec 2 B2 intends |
| D13 | Scope inside `Run` | `Check.Input` carries a struct holding the target and the `*scope.Scope` taken from `View.Scope()` in `Checks()` | `Run` has no `View`. D11 and D14 need to classify hosts |
| D14 | Crawl (B7) | One check per current `web_service` record, keyed `<service-url>\|depth=D\|pages=P`. Order is BFS from a `Root` GET (depth 0, counted in P). Pages are parsed only when they are `text/html`. Relative links resolve against the page's first http(s) `<base href>`, as in a browser.<br>**Fetched:** same-origin links (same scheme, host and port; `egress.Link` checks only the host) from `a[href]`, `area[href]` and `iframe[src]` without a static-asset extension, up to depth D and P GETs.<br>**Recorded, never fetched:** `link[href]`, `script[src]` and `form[action]` targets, and static assets.<br>**Never requested:** `robots.txt` and `sitemap.xml` (Spec 1 B12).<br>**Recorded as `url`:** every link whose host is in scope or the same IP, capped at 20×P observations per check, so the cap sits in the key through P.<br>**Hosts:** a `hostname` is emitted only for in-scope link hosts other than the check's own host (user). Off-scope link hosts are ignored.<br>**Redirects:** same-origin redirects are followed. If the root redirects to another origin, the target is recorded and the crawl ends, because that service has its own crawl. GET only.<br>**Errors:** only an error on the root GET fails the check. `NoService`, `Refused` or an error on any other page skips that page. Context cancellation returns its error.<br>**Disabling:** `crawl.max_pages: 0` makes the stage not-configured (`disabled`), and `max_depth: 0` crawls the root only | `Link` needs a live `Response`, so a crawl must be one check. Restricting fetches to one origin avoids crawling `http://a` and `https://a` twice. The URL cap stops calendar and faceted-search pages from exploding. A single bad page should not redo 100 fetches |
| D15 | `url` record | Key: normalised URL (lowercase scheme and host, no default port, no fragment, query kept, IPv6 bracketed). Attrs: `url`, `host`, and `status` (crawl and redirect only, for fetched URLs). `found_by` is the sorted list of observing stages | Spec 1 B9 natural key. One URL seen by the crawl and an archive is one row |
| D16 | (user) Archived URLs (B6) | `wayback` and `commoncrawl` also emit `url` observations for URLs under the root.<br>**Filtering:** static-asset extensions are dropped (images, css, fonts, media, pdf, archives). The rest are normalised (D15).<br>**Capping:** the cap is round-robin across hosts in sorted order up to new setting `archive.max_urls` (flag `--archive-max-urls`, default 20000, validated > 0, shown in help), so early-sorting hosts can't take the whole cap. It applies to URLs only; hostname extraction is unchanged.<br>**Check keys:** for these two stages only, the key becomes `<root>\|urls=N`, so changing the cap re-runs them (Spec 1 B6). `Checks()` gains a per-stage key function. `Run` reads the root from `c.Input`, not `c.Key`, and `result` gains a `urls` field.<br>**Never requested:** egress has no constructor for them | No new requests, and they run under `--passive`. Changing the key only for these two stages means crtsh, virustotal and securitytrails don't re-run (and keyed quota isn't spent again). Reading the root from `c.Key` would break the `HasSuffix` filter |
| D17 | Scope filter on read | New `scope.Scope.WebHostInScope(host)`: an IP literal is `InScopeIP` and not excluded; a name has `ClassifyHost == InScope`. `kinds.Kind` gains `HostAttr string` (`"host"` for `web_service` and `url`). `categoryOf` and the two output files use the same function, so summary totals equal CSV rows | Spec 1 D16 computes scope on read, so an exclusion added later hides archived URLs. Without a shared function the summary and the CSVs would disagree |
| D18 | Outputs | `web-services.csv`: `url, host, port, scheme, status, title, server, technologies, redirect, final_url, tls_subject, tls_sans, tls_issuer, tls_expiry, tls_error, tls_self_signed`. `urls.csv`: `url, host, status, found_by`. `runner.render()`'s hard-coded kind list gains `web_service` and `url`. New internal kind `http_port` (no category) | Names reserved in Spec 1. Without the kind list change, the CSVs render empty |
| D19 | Passive | `httpprobe` and `crawl` are Target stages, so they are not-configured (`passive-only`) through the existing gate. `wayback` and `commoncrawl` run | B6 and Spec 1 B13 |

## Packages and changes

- `internal/egress/http.go`: the D6 IP-literal path (policy, dial, no SNI, IPv6 bracketing on default ports); `Response` gains `ContentType()` or stages read `Header`. Tests are added to `egress_test.go`.
- `internal/scope`: `WebHostInScope`.
- `internal/kinds`: `HostAttr`, and the `http_port` kind.
- `internal/run/runner.go`: `categoryOf` applies `HostAttr`; `render()` adds `web_service`, `url` and `http_port`; `View` gains `OpenPorts()` (current `open_port` records parsed into `AddrPort` and banner) and `HostsFor(addr)` (`ProbeHostnames()` names resolving to an address, sorted).
- `internal/stages/web` (new):
  - `probe.go`: `httpprobe`, implementing D2, D4, D5, D7, D8, D11 and D12;
  - `crawl.go`: D14;
  - `html.go`: title and link extraction, plus the static-extension list (shared with D16);
  - `tech.go`: the wappalyzergo wrapper;
  - `urlnorm.go`: D15 normalisation, shared with `subdomains`.
- `internal/stages/subdomains/subdomains.go`: D16 (per-stage key function, `Input` root, `result.urls`, filter and round-robin cap).
- `internal/config`: `archive.max_urls` and `--archive-max-urls`, with validation and its help default. `crawl.max_pages: 0` means disabled.
- `internal/output`: `web-services.csv` and `urls.csv`, both filtered by `WebHostInScope`.
- `internal/cli/cli.go`: `defaultStages()` appends `web.NewProbe()` and `web.NewCrawl()` after `ipowner`.
- `go.mod`: adds `github.com/projectdiscovery/wappalyzergo`.

## Test plan

Integration tests go through `cli.Execute` with:
- `httptest` plain and TLS servers (self-signed, expired and valid-chain certificates generated in the test);
- `egress.Options.DialMap`;
- the loopback fake DNS;
- a fake stage that emits `open_port` records (D3);
- per-source `httptest` servers for wayback and Common Crawl.

Request counters on every fake server assert what was and wasn't contacted.

| B | Tests |
|---|-------|
| 1 | A `ProbeHostnames()` name is probed as `http:80` and `https:443`; a wildcard representative and a shared-infra host are probed; a wildcard-only non-representative and an excluded host are not. A non-standard open port runs one detection check via the smallest hostname, and the other vhosts are probed in a later pass with the detected scheme. The https→http fallback works for a plain server that resets the connection and for one that hangs. A port with a banner, and a detected non-HTTP port, give zero vhost requests. A closed 80 gives no record and a completed check |
| 2 | An in-scope IP with an open port and no hostname is probed by IP literal (IPv4 and IPv6, no SNI, correct Host header, bracketed URL). An in-scope IP with a `ProbeHostnames()` name is probed only by hostname. Egress refuses an out-of-scope IP literal, and an in-scope IP in an excluded CIDR |
| 3 | Every D8 attr is recorded. Expired and self-signed certificates are recorded with `tls_error` and `tls_self_signed`, and the probe completes. wappalyzergo detects a header, a cookie and a meta-generator marker. The title is trimmed and capped. Changes to the service flow through the `--redo httpprobe` contract |
| 4 | An in-scope chain `http://a → https://a/login`: `status` and `redirect` come from hop 1, while `title`, `technologies` and `final_url` come from the last page, and TLS attrs are empty on the http service. An out-of-scope target appears in candidates.csv with zero requests to it. An excluded target is not requested. The hop cap and a loop both terminate. A redirect to the probed host itself, or to an IP, adds no `hostname` record. A permutation-only name that redirects to itself is still not a seed |
| 5 | An in-scope SAN is resolved and probed in the same run. An out-of-scope SAN appears in candidates.csv. `*.x.example.com` yields `x.example.com`. A SAN equal to the probed host doesn't make a permutation-only name a seed |
| 6 | Under `--passive`, wayback and Common Crawl URLs appear in urls.csv with `found_by`, and static assets are filtered. The round-robin cap is deterministic across runs, and changing the cap creates new checks. crtsh check keys are unchanged. An archived URL is never requested (the server counter is zero, and the API has no constructor). An exclusion added later hides the URLs from urls.csv and from the summary count |
| 7 | Depth and page caps are respected, and the root counts toward P. Only same-origin pages are fetched. `form[action]`, `script[src]` and static links are recorded but not fetched. `robots.txt` and `sitemap.xml` are never requested. Every request is a GET. An off-scope link host is not a candidate; an in-scope other host becomes a `hostname`. The URL cap is 20×P. A failing non-root page still completes the check; a failing root page is retried next run. A root that redirects to another origin ends the crawl. `--crawl-pages 0` shows `disabled`. Changing the depth or page settings creates new checks |
| Plumbing | Summary totals equal the CSV row counts. The new files are sorted and CSV-safe and have first-seen and last-seen dates. `web_service` is printed and `url` is only counted. The boundary test still passes, so `internal/stages/web` imports no `net`, `net/http` or `crypto/tls`, though `crypto/x509` is allowed |

## Spec amendments made

- **B1 (detail):** on ports 80 and 443 only the conventional scheme is checked (http on 80, https on 443). Other open ports are checked with https, falling back to http.
- **B1 (detail):** "found to speak HTTP(S)" is decided once per address and port, using a representative host (D4). Other vhosts are probed only on ports that answered.
- **B1 (known gap):** a name with several addresses is detected on a port only at its first-sorting address with that port open (D4, D5). If that address does not speak HTTP and a later one does, the name is missed on that port. When that name is also the later address's representative, the later address gets no detection check. Its other names are then not probed on that port either.
- **Spec 1 (egress):** `TargetHTTP` gains `RootAt`, so a detection check's answer comes from the address it is keyed by (D4).
- **Spec 1 B11 (user):** out-of-scope hosts in crawled links are not recorded as candidates. Redirect targets (B4) and SANs (B5) still are. Archive URLs are always under an in-scope root.
- **Spec 4 (contract):** Spec 4's port stage must emit `open_port` records as D3 defines them.

## Out of scope for Spec 3

- Port scanning itself (Spec 4) and findings built from these records (Spec 5).
- Links that only appear after JavaScript runs, and robots.txt or sitemap.xml as URL sources.
- Re-probing services automatically. Use `--redo httpprobe` or `--redo crawl`.
- Known limitations:
  - A redirect hop to an in-scope host that isn't resolved yet stops the chain, and the check is recorded. `final_url` and `title` stay at the last page reached until `--redo httpprobe`.
  - Lowering `archive.max_urls` doesn't shrink urls.csv, because observations under the old check key stay current until `--redo wayback` or `--redo commoncrawl`.
  - Wappalyzer fingerprints change only with the dependency version.
  - A hostname probe dials whichever vetted address of the host connects first, which may be a shared one. So `http_port` records that some address of the representative answered HTTP on that port, not necessarily that exact address. `web_service` is keyed by host:port, so B1 holds. Specs 4 and 5 must not read `http_port` as proof about one address.
  - The tests cannot show a certificate that verifies: egress verifies against the system roots, which a certificate generated in a test never satisfies. CA-issued test certificates are recorded with `tls_error` "unknown authority"; an empty `tls_error` for a trusted chain is not covered by a test.
  - A transient error (not `NoService` or `Refused`) on any request in an `httpprobe` redirect chain fails the whole check, so no `web_service` is recorded until the next run. Only the crawl treats non-root errors as skippable.
  - The crawl's URL cap (20×P) drops later URLs silently, and with them the status of a fetched page that was dropped.
  - An archive stage holds every URL it fetched (at most 30 pages per source) in memory before capping.
  - `WebHostInScope` hides an address of a host excluded by name, even if that address is shared infrastructure that egress would still dial (it cannot see `Shared`).
  - An IP-literal service outlives a hostname that later resolves to the same address, and "no in-scope hostname" (B2) holds only for names that existed when its detection check ran. `port|<addrport>` is keyed by address and port, so the check is not redone; the new name gets its own vhost check through D5, and the IP-keyed `web_service` stays current.
  - `technologies` entries carry a version when wappalyzergo detects one (`Nginx:1.25.3`), so a version bump shows as a changed value.

# Implementation (Develop)

**How it was built.** Tests were written first and failed, then the code was written until they passed. `go test ./...` and `go test -race` on the touched packages pass.

- `internal/egress/http.go`: D6. An IP literal is parsed before the malformed-host check and allowed iff `InScopeIP` and not `ExcludedFor`. It is dialled directly with no SNI, and IPv6 is bracketed in the URL and Host header on every port. A zoned or bracketed literal is refused. `origin` now stores the request URI, so `Link` and `Redirect` resolve relative references against the page's real URL, not `/`. `Response` gains `URL()` (absolute, default port omitted) and `ContentType()`.
- `internal/scope`: `WebHostInScope`. `internal/kinds`: `HostAttr`, `http_port`. `internal/output`: `web-services.csv`, `urls.csv` and `WebVisible`, which `runner.categoryOf` also calls. `internal/run`: `View.OpenPorts()`, `View.HostsFor()` (indexed once per pass), and `render()` loads `web_service` and `url`.
- `internal/config`: `archive.max_urls` and `--archive-max-urls` (default 20000, at least 1). `crawl.max_pages: 0` disables the crawl.
- `internal/stages/web`: `probe.go` (D2, D4, D5, D7, D8, D11, D12), `crawl.go` (D14), `html.go`, `tech.go` (wappalyzergo behind `sync.OnceValues`) and `urlnorm.go` (D15, shared with `subdomains`).
- `internal/stages/subdomains`: D16. `wayback` and `commoncrawl` key their checks `<root>|urls=N`, read the root from `Input`, and emit `url` observations after the static-asset filter and the round-robin cap.
- `internal/cli`: `defaultStages()` appends `httpprobe` and `crawl` after `ipowner`.

**How each behaviour was tested** (all through `cli.Execute`, except where noted):

| B | Tests |
|---|-------|
| 1 | `TestWebB1_HostnamesProbedOn80And443`, `…WildcardSharedAndExcluded`, `…NonStandardPortDetectedOnce`, `…SchemeDetectionAndFallback` (reset, hang, TLS, closed), `…BannerAndNonHTTPPortsGetNoVhostRequests` |
| 2 | `TestWebB2_IPLiteralService` (IPv4, IPv6, no SNI, Host header), `…ANameWinsOverTheIP`, `…OutOfScopeAndExcludedIPsAreNotProbed`; egress `TestIPLiteral*` |
| 3 | `TestWebB3_AllAttributes`, `…ExpiredAndSelfSignedCertificatesAreRecorded`, `…TitleIsTrimmedAndCapped`, `…AnyStatusIsALiveService`, `…RedoHTTPProbeRefreshesTheService` |
| 4 | `TestWebB4_InScopeRedirectChain`, `…OutOfScopeRedirectIsACandidateAndNotRequested`, `…ExcludedRedirectTargetIsNotRequested`, `…LoopAndHopCapTerminate`, `…RedirectToSelfOrAnIPAddsNoHostname`, `TestWebB4B5_PermutationOnlyNameIsNeverSeededByItsOwnService` |
| 5 | `TestWebB5_SANsFlowThroughOrBecomeCandidates`, and the B4/B5 permutation test above |
| 6 | `TestWebB6_ArchivedURLsUnderPassive`, `…CapIsRoundRobinDeterministicAndPartOfTheCheckKey`, `…CapSettingIsValidatedAndDocumented`, `…AnExclusionAddedLaterHidesArchivedURLs` |
| 7 | `TestWebB7_FetchesAndRecordsAsSpecified`, `…PageAndDepthCaps`, `…RecordedURLsAreCappedAt20TimesPages`, `…Errors`, `…RootRedirectToAnotherOriginEndsTheCrawl`, `…SameOriginRedirectsAreFollowedAndOnlyHTMLIsParsed`, `…DisabledAndSettingsAreInTheCheckKey` |
| Plumbing | `TestWebPlumbing_FilesAreSortedSafeDatedAndCounted`, scope `TestWebHostInScope`, kinds `TestWebKinds`, the existing import-boundary test (covers `internal/stages/web`) |

Mutating the code (redirect emitting its own host, the crawl following forms, a non-round-robin cap) made the matching tests fail. Making egress send an IP as SNI did not, because Go's TLS client omits SNI for an address anyway.

**Deviations from the plan.**

- `tls_self_signed` is `RawIssuer == RawSubject` plus `CheckSignature` on the leaf, not `CheckSignatureFrom(leaf)`. `CheckSignatureFrom` rejects a self-signed leaf that is not marked as a CA, so it would report such a certificate as not self-signed.
- D13: only `crawl` carries the `Scope` in its `Input`. `httpprobe` does not need it, because scope classifies the hostnames it emits.
- A `web_service` or `url` record with no `host` attribute takes its host from its key URL when counted or listed, so records from older fixtures still count.
- `final_url` is always recorded, as the normalised URL of the last page reached (`https://a.example.com/` with no redirect). An empty path normalises to `/`.
- `httpprobe` sets `status` on the `url` record of each redirect hop it fetches, as D15 asks. The crawl skips `robots.txt` and `sitemap.xml` both as links and as same-origin redirect targets; it records them but does not request them. The rule lives in the crawl, because Spec 1 B12 limits requests to listed paths and crawled links without naming those files.
- Archive URLs within a host are taken in sorted order, and `found_by` is the stage names joined with `,` as in `candidates.csv`.
- `render()` loads `web_service` and `url` only; no file needs `http_port`.
- Existing tests changed: the synthetic `web_service` records in `TestRedo` now carry a `host`, and `TestDefaultRegistry` lists the two new files.
- `go.mod` adds wappalyzergo v0.3.8, which also raised `go.yaml.in/yaml/v3` to v3.0.5.


# Verification

**Result: the goal and B1–B7 are met, with the two caveats below.** No code was changed during verification.

I checked each behaviour against the code in `internal/stages/web`, `internal/egress/http.go`, `internal/stages/subdomains`, `internal/output`, `internal/scope` and `internal/run`. All 41 tests named under Implementation exist and pass. Together they cover every row of the test plan, including:

- the hang fallback;
- IPv6 IP-literal services through `cli.Execute`;
- wappalyzer detection by header, cookie and meta generator;
- unchanged crtsh check keys.

`go build`, `go vet` and `go test ./...` pass, and `go test -race` passes on `internal/cli` with `-count=1`. `gofmt` reports nothing.

| B | Status |
|---|--------|
| 1 | Met. 80/443 hostname checks, one detection check per address and port, the https→http fallback, and vhost checks on detected ports. See caveat 1 |
| 2 | Met against the D3 contract. See caveat 1 |
| 3 | Met. Every D8 attr is recorded, and invalid certificates are recorded without stopping the probe |
| 4 | Met. See caveat 2 |
| 5 | Met |
| 6 | Met. Archived URLs are recorded under `--passive` and never requested |
| 7 | Met. Every request is a GET, robots.txt and sitemap.xml are never requested, and the caps hold |

**Caveats**

1. **Spec 4 dependency.** No production stage emits `open_port` yet. Only Spec 4 will. Until then, B2 and the open-port part of B1 are proven only through the fake D3 stage in the tests. In a real run today, only hostnames on ports 80 and 443 are probed.
2. **IP-literal redirect targets.** An out-of-scope IP-literal redirect target is never requested, which is correct. It is not recorded as a candidate, though, because D11 deliberately emits no `hostname` for IPs, and `urls.csv` hides out-of-scope hosts. It is visible only in `web-services.csv` as the `redirect` attr, and only when it is the first hop. This falls slightly short of B4's wording, and the shortfall is accepted by D11.
