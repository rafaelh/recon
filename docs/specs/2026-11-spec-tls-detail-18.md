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
