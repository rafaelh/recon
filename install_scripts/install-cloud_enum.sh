#!/bin/bash
set -Eeuo pipefail
trap 'print_error "cloud_enum install failed."' ERR
source "$(dirname "$0")/_common.sh"

# https://github.com/initstring/cloud_enum - upstream uses uv. A clone is kept
# (rather than `uv tool install`) so enum_tools/*_regions.py and fuzz.txt stay
# easy to edit.
CLOUD_ENUM_DIR="$RECON_TOOLS_DIR/cloud_enum"

# === Exit without proceeding if run in WSL ===
if [ -f /mnt/c/Windows/System32/wsl.exe ]; then
    exit 0
fi

if [ ! -x "$CLOUD_ENUM_DIR/.venv/bin/cloud_enum" ]; then
    print_green "Installing cloud_enum"
    [ -d "$CLOUD_ENUM_DIR/.git" ] || git clone --quiet https://github.com/initstring/cloud_enum "$CLOUD_ENUM_DIR"
elif repo_has_updates "$CLOUD_ENUM_DIR"; then
    print_green "Updating cloud_enum"
    git -C "$CLOUD_ENUM_DIR" pull --quiet --ff-only
else
    exit 0
fi

uv sync --quiet --no-dev --project "$CLOUD_ENUM_DIR"
ln -sf "$CLOUD_ENUM_DIR/.venv/bin/cloud_enum" "$RECON_BIN_DIR/cloud_enum"
