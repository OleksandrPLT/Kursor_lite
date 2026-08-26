#!/usr/bin/env bash
# Installs Kursor by Intech as a persistent background service on macOS,
# using launchd (macOS has no systemd — this is its equivalent of the
# Linux install.sh's systemd unit, per the project plan's M8 milestone,
# adapted for a Mac-as-server deployment).
#
# Run from the project root, on the machine that will actually run the
# server (e.g. directly on the target Mac Pro):
#   sudo ./scripts/install-macos.sh
#
# What it does:
#   1. Builds kursord from source (go build — this machine's own arch,
#      so it works whether you're on Intel or Apple Silicon).
#   2. Installs the binary + a data dir under /usr/local.
#   3. Registers a LaunchDaemon so it starts at boot (no login required)
#      and restarts itself if it crashes.
#   4. Prints the LAN URL + the first-run admin password.

set -euo pipefail

APP_NAME="kursor"
LABEL="org.intech.kursor"
INSTALL_DIR="/usr/local/opt/${APP_NAME}"
BIN_PATH="${INSTALL_DIR}/bin/kursord"
DATA_DIR="/usr/local/var/${APP_NAME}"
WWW_ROOT="${DATA_DIR}/wwwroot"
LOG_DIR="/usr/local/var/log/${APP_NAME}"
PLIST_PATH="/Library/LaunchDaemons/${LABEL}.plist"
PORT="${KURSOR_PORT:-8888}"

log() { echo "==> $*"; }
die() { echo "error: $*" >&2; exit 1; }

[ "$(uname -s)" = "Darwin" ] || die "this script is for macOS only — see scripts/install.sh for Linux"

if [ "$(id -u)" -ne 0 ]; then
  die "run with sudo: sudo ./scripts/install-macos.sh"
fi

# --- 1. Go toolchain ---------------------------------------------------
# `sudo` drops the invoking user's PATH, so a Go installed only for them
# (e.g. under ~/sdk/go, the way this project's own dev setup did it)
# won't be on root's PATH even though it's on disk. Check both.
REAL_HOME="$(eval echo "~${SUDO_USER:-$(whoami)}")"
if ! command -v go >/dev/null 2>&1; then
  if [ -x "${REAL_HOME}/sdk/go/bin/go" ]; then
    export PATH="${REAL_HOME}/sdk/go/bin:$PATH"
  elif [ -x "/usr/local/go/bin/go" ]; then
    export PATH="/usr/local/go/bin:$PATH"
  fi
fi
command -v go >/dev/null 2>&1 || die "Go is not installed. Install it first (e.g. https://go.dev/dl/), then re-run this script."
log "using $(go version)"

# --- 2. Build -------------------------------------------------------
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"
log "building kursord from $PROJECT_ROOT ..."
BUILD_DIR="$(mktemp -d)"
GOOS=darwin go build -o "${BUILD_DIR}/kursord" ./cmd/kursord
log "build ok"

# --- 3. Install files -------------------------------------------------
log "installing to ${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}/bin" "$DATA_DIR" "$WWW_ROOT" "$LOG_DIR"
install -m 0755 "${BUILD_DIR}/kursord" "$BIN_PATH"
rm -rf "$BUILD_DIR"

# Real (non-root) owner, so the invoking user can still read logs/data
# without sudo. The daemon itself runs as root below — same tradeoff as
# the Linux install.sh (site/db/file management needs it); see SECURITY
# notes in the project plan.
REAL_USER="${SUDO_USER:-$(whoami)}"
chown -R "$REAL_USER" "$DATA_DIR" "$LOG_DIR" 2>/dev/null || true

# --- 4. launchd unit ----------------------------------------------------
log "writing ${PLIST_PATH}"
cat > "$PLIST_PATH" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${BIN_PATH}</string>
        <string>--addr</string>
        <string>:${PORT}</string>
        <string>--data-dir</string>
        <string>${DATA_DIR}</string>
        <string>--www-root</string>
        <string>${WWW_ROOT}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/kursord.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/kursord.log</string>
</dict>
</plist>
PLIST
chmod 0644 "$PLIST_PATH"

# --- 5. load it ----------------------------------------------------------
log "starting the service"
launchctl bootout system "$LABEL" >/dev/null 2>&1 || true
if ! launchctl bootstrap system "$PLIST_PATH" 2>/dev/null; then
  # Older macOS (pre-10.11 launchctl syntax) fallback.
  launchctl load -w "$PLIST_PATH"
fi

sleep 2

LAN_IP="$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo "<your-mac-ip>")"

echo ""
echo "=========================================="
echo " Kursor by Intech installed as a launchd service"
echo " Panel URL:  http://${LAN_IP}:${PORT}  (also http://localhost:${PORT})"
echo " Logs:       ${LOG_DIR}/kursord.log"
echo " Data:       ${DATA_DIR}"
echo "=========================================="
echo ""

if grep -q "first run" "${LOG_DIR}/kursord.log" 2>/dev/null; then
  echo "First-run admin credentials:"
  grep -A3 "first run" "${LOG_DIR}/kursord.log" | tail -4
  echo ""
fi

echo "Manage the service with:"
echo "  sudo launchctl kickstart -k system/${LABEL}   # restart"
echo "  sudo launchctl bootout system ${LABEL}         # stop"
echo "  ./scripts/uninstall-macos.sh                   # remove entirely"
