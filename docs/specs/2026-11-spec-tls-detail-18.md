# Spec 18: TLS detail and weak protocol findings

## Goal

The TLS version, cipher and trust state of each in-scope HTTPS service are recorded from the
probe's single handshake, and services that offer nothing newer than TLS 1.1, or present a
certificate for the wrong name, are low findings.

## Behaviours

1. Every HTTPS request to an in-scope service (probe, crawl, sensitive paths, takeover
   fingerprinting, origin check) accepts TLS 1.0 and 1.1 and additionally offers CBC-mode and RSA
   key-exchange suites, but not RC4 or 3DES, so a service whose best version is 1.0 or 1.1 is
   recorded with that version instead of failing and is then crawled and checked like any other.
   Requests to third-party sources keep today's minimum version. A service supporting TLS 1.2 or
   later records the same `tls_version` as before; its `tls_cipher` is whatever it picks from the
   wider offer. SSL 3.0-only services still fail. Old versions offered alongside new ones are not
   detected; the README says so.
2. `web-services.csv` gains `tls_version` (`TLS 1.2` style), `tls_cipher` (the IANA suite name)
   and `tls_trust`, which replaces `tls_error` and `tls_self_signed` and holds the first that
   applies of `expired` (including not yet valid), `hostname-mismatch`, `self-signed`,
   `untrusted-chain`, else `trusted`. `tls_issuer` and `tls_sans` are unchanged. Values come from
   the service's own first response, not a redirect target, and are as of the probe; the README
   notes that `untrusted-chain` depends on the running machine's root store.
3. A service negotiating TLS 1.0 or 1.1 is a low finding `legacy-tls` in `risk-certificates.csv`.
   The existing `self-signed` finding is kept. A new low finding `hostname-mismatch` is made for a
   certificate that does not name the probed hostname, except for services addressed by IP literal
   or hosts served by a known provider (CDN or SaaS).
4. A service whose TLS handshake fails is not recorded as an HTTPS service, as today, and produces
   no TLS finding.
5. Findings are marked not current after `--redo httpprobe` negotiates a modern version or a
   matching certificate. Existing engagements have empty `tls_version` and `tls_cipher` until
   `--redo httpprobe`; the README says so, and its `risk-certificates.csv` row mentions legacy
   TLS and hostname mismatch.

# Design

**Status:** ready to build (wave 1). **Depends on:** nothing. Spec 12 merged first, and the
design was re-checked against it on 2026-11-14: the column and probe seams below are as built.
**Used by:** Spec 7 (its origin check goes through the same target client). **Shares with Specs
12 and 13:** `web-services.csv`.

## Decisions

- **One TLS configuration for every target request.** All target HTTP goes through
  `targetHTTP.do`, so the change is there: `MinVersion: tls.VersionTLS10` and an explicit
  `CipherSuites` list built once from `tls.CipherSuites()` plus the CBC and RSA key-exchange
  suites of `tls.InsecureCipherSuites()`, excluding any suite whose name contains `RC4` or `3DES`.
  The third-party client is untouched.
- **Egress reports what was negotiated**: `Response.TLSVersion` (`tls.VersionName`: `TLS 1.2`),
  `Response.TLSCipher` (`tls.CipherSuiteName`), and `Response.CertTrust()`, which replaces
  `CertVerifyErr` and returns the first that applies of `expired`, `hostname-mismatch`,
  `self-signed`, `untrusted-chain`, `trusted`. The self-signed test moves from the probe into
  egress so the order is decided in one place.
- **Attributes**: `tls_version`, `tls_cipher` and `tls_trust` are added to `WebServiceAttrs`.
  `tls_self_signed` is still written (the existing finding reads it); `tls_error` is no longer
  written but stays in the struct so old records decode.
- **Old records get a trust value on read**: `kinds.TLSTrust(attrs)` returns `tls_trust` when set
  and otherwise maps the old `tls_error` text and `tls_self_signed` to the same five values.
  `web-services.csv` shows `tls_version`, `tls_cipher`, `tls_trust` in place of `tls_error` and
  `tls_self_signed`. As built, the columns are `webServiceColumns` and the cells
  `webServiceCells` in `internal/output/output.go`, and the list ends with Spec 12's `hsts`,
  `insecure_cookies`, `directory_listing` and `version_disclosure`. The three new columns take
  the place of the two old ones, before `hsts`, not the end of the list.
- **The probe seam as built.** `service()` in `probe.go` sets `TLSError` from
  `first.CertVerifyErr()` and `TLSSelfSigned` from its own `selfSigned(leaf)`. Both move behind
  `first.CertTrust()`. The values come from `first`, the service's own response, which is also
  `chain[0]` of the `hop` chain Spec 12 added; the posture call beside it is not touched.
- **Findings** extend the `certificates` category: `legacy-tls` (low) when `tls_version` is
  `TLS 1.0` or `TLS 1.1`; `hostname-mismatch` (low) when trust is `hostname-mismatch`, the host is
  not an IP literal and `inv.ProviderServed(host)` is false (a new inventory method: a provider
  CNAME on the chain or a shared-provider address). They join the existing `;`-joined type of the
  one row per service.

## Changes

- `internal/egress/http.go`: TLS config, the three accessors, `CertTrust`.
- `internal/stages/web/probe.go`: attributes from the first response.
- `internal/kinds/table.go`: three fields at the end of `WebServiceAttrs`; `TLSTrust`.
- `internal/inventory/inventory.go`: `ProviderServed`.
- `internal/output/output.go`: columns. `internal/findings/findings.go`, `table.go`: two types.
- `README.md`: columns, the root-store note, what is not detected, the `risk-certificates.csv` row.

## Tests

- `internal/egress` (test TLS servers): a TLS 1.0-only and a 1.1-only server answer and report
  their version; an RSA-CBC-only server answers; an RC4-only or 3DES-only server is `tls-failed`;
  each trust value from a crafted chain against the fixed clock; third-party requests still
  refuse TLS 1.1.
- `internal/findings`: both new types, the IP-literal and provider exceptions, combined types.
- `internal/cli/tls_test.go`: a legacy service is recorded, crawled and checked for sensitive
  paths; columns; old records show a derived `tls_trust` and empty version until
  `--redo httpprobe`; findings go not current after a redo against a fixed service.

## Carried from built specs

Follow-ups and limits of the specs already built that bear on this one.

- **Posture on legacy services (Spec 12).** A service that only speaks TLS 1.0 or 1.1 is now
  recorded as an HTTPS service, so the probe also stores its `web_posture` and it can get the
  HSTS and cookie findings. That follows from behaviour 1 and needs no code.
- **Two provider tests (Spec 12).** Posture findings are skipped for a host `SaaSServed` says a
  SaaS platform serves. The `hostname-mismatch` exception is wider (CDN or SaaS), which is why it
  needs the new `ProviderServed`. Keep both; do not widen `SaaSServed`.
- **Akamai addresses in Linode's list (Spec 5, follow-up 1).** Those addresses classify as
  dedicated, so a host on one, with no Akamai CNAME, is not `ProviderServed` and can get a
  `hostname-mismatch` finding for a CDN certificate. Spec 7's design asks the user to settle
  that classification; nothing is decided here.
- **A finding that is no longer derived keeps only what its key holds (Specs 3 and 12).** A
  not-current `risk-certificates.csv` row has blank cells beyond its key, as today.
- **New fields go at the end.** The three fields are appended to `WebServiceAttrs`, and Spec 7's
  `body_len` follows them.
- **`Kind` is not comparable (Spec 3).** Compare `Name()`.

## Out of scope

Enumerating every version a server offers; SSL 3.0; any extra handshake.
