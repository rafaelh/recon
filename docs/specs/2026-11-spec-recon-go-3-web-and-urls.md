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
