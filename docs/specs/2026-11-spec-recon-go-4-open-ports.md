# Spec 4 of 6: recon (Go) — Open ports

## Goal

Find which common TCP services the target's own IPs expose, connecting only as any client would.
Depends on Specs 1 and 2. Not run in passive-only mode.

## Behaviours

1. Each IP eligible under Spec 2.9 receives a completed TCP handshake to each port in a configurable
   list (default: about the top 100 TCP ports), IPv4 and IPv6 alike.
2. Open ports are recorded with any banner the service sends unprompted. Closed or filtered ports are
   recorded as checked so they are not retried.
3. Open ports that speak HTTP(S) are passed to web service probing (Spec 3.1/3.2).
