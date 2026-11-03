# Spec 6 of 6: recon (Go) — Cutover

## Goal

Make the Go `recon` the only implementation in this repository, installable as a single binary, and
remove the Python version. Depends on Specs 1–5 being complete.

## Behaviours

1. The Go `recon` builds into a single binary for macOS and Linux (amd64 and arm64) with no runtime
   dependency on external recon tools.
2. The repository contains no Python code, Python packaging, Python version pins, Python-specific
   ignore entries, helper notes referencing the old tools, or scripts that install the external tools
   the old version used.
3. The README documents installation, configuration (including where API keys go), usage, the passive
   boundary, passive-only mode, the authorisation acknowledgement, and the meaning of each output.
4. Output directories from the Python version are not resumable (Spec 1.4).
5. XSS/SQLi testing and the separate single-site command are retired.
