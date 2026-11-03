#!/bin/bash
# Shared settings for the install-*.sh scripts. Sourced, not run directly.

GREEN="\033[1;32m"
RED="\033[1;31m"
ENDCOLOR="\033[0m"

RECON_TOOLS_DIR="${RECON_TOOLS_DIR:-$HOME/.recon-tools}"
RECON_BIN_DIR="$RECON_TOOLS_DIR/bin"
mkdir -p "$RECON_BIN_DIR"

print_green() { echo -e "${GREEN}[+] ${ENDCOLOR}$1"; }
print_error() { echo -e "${RED}[!] ${ENDCOLOR}$1"; }

# Returns "macos" or "linux"
os_name() {
    case "$(uname -s)" in
        Darwin) echo "macos" ;;
        *)      echo "linux" ;;
    esac
}

# Returns "x86_64" or "aarch64"
arch_name() {
    case "$(uname -m)" in
        arm64|aarch64) echo "aarch64" ;;
        *)             echo "x86_64" ;;
    esac
}

# Returns 0 if the git repo in $1 is behind its upstream branch
repo_has_updates() {
    git -C "$1" fetch --quiet
    [ "$(git -C "$1" rev-parse HEAD)" != "$(git -C "$1" rev-parse '@{upstream}')" ]
}
