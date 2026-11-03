#!/bin/bash
set -Eeuo pipefail
trap 'print_error "dalfox install failed."' ERR
source "$(dirname "$0")/_common.sh"

# https://github.com/hahwul/dalfox - v3 is written in Rust, so `go install` no
# longer works. Upstream publishes prebuilt binaries on the releases page.
DALFOX_DIR="$RECON_TOOLS_DIR/dalfox"

LATEST=$(curl -fsSLo /dev/null -w '%{url_effective}' https://github.com/hahwul/dalfox/releases/latest)
LATEST="${LATEST##*/}"
if [ -f "$DALFOX_DIR/VERSION" ] && [ "$(cat "$DALFOX_DIR/VERSION")" = "$LATEST" ]; then
    exit 0
fi
if [ -f "$DALFOX_DIR/VERSION" ]; then
    print_green "Updating dalfox to $LATEST"
else
    print_green "Installing dalfox $LATEST"
fi

ASSET="dalfox-$LATEST-$(os_name)-$(arch_name)"
URL="https://github.com/hahwul/dalfox/releases/download/$LATEST/$ASSET.tar.gz"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

curl -fsSL -o "$TMP/$ASSET.tar.gz" "$URL"
EXPECTED=$(curl -fsSL "$URL.sha256" | awk '{print $1}')
if command -v sha256sum >/dev/null; then
    ACTUAL=$(sha256sum "$TMP/$ASSET.tar.gz" | awk '{print $1}')
else
    ACTUAL=$(shasum -a 256 "$TMP/$ASSET.tar.gz" | awk '{print $1}')
fi
if [ "$EXPECTED" != "$ACTUAL" ]; then
    print_error "dalfox checksum mismatch for $ASSET.tar.gz"
    exit 1
fi

tar -xzf "$TMP/$ASSET.tar.gz" -C "$TMP"
mkdir -p "$DALFOX_DIR"
install -m 0755 "$TMP/$ASSET/dalfox" "$DALFOX_DIR/dalfox"
echo "$LATEST" > "$DALFOX_DIR/VERSION"
ln -sf "$DALFOX_DIR/dalfox" "$RECON_BIN_DIR/dalfox"
