#!/bin/bash
set -Eeuo pipefail
trap 'print_error "massdns install failed."' ERR
source "$(dirname "$0")/_common.sh"

# https://github.com/blechschmidt/massdns - built from source. The repo is kept
# (not just the binary) because recon uses lists/resolvers.txt from it.
MASSDNS_DIR="$RECON_TOOLS_DIR/massdns"

if [ ! -x "$MASSDNS_DIR/bin/massdns" ]; then
    print_green "Installing massdns"
    [ -d "$MASSDNS_DIR/.git" ] || git clone --quiet https://github.com/blechschmidt/massdns "$MASSDNS_DIR"
elif repo_has_updates "$MASSDNS_DIR"; then
    print_green "Updating massdns"
    git -C "$MASSDNS_DIR" pull --quiet --ff-only
else
    exit 0
fi

# Upstream: `make` on Linux, `make nolinux` everywhere else
if [ "$(os_name)" = "macos" ]; then
    make -C "$MASSDNS_DIR" nolinux
else
    make -C "$MASSDNS_DIR"
fi
ln -sf "$MASSDNS_DIR/bin/massdns" "$RECON_BIN_DIR/massdns"
