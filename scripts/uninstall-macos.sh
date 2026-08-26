#!/usr/bin/env bash
# Removes the Kursor by Intech launchd service installed by
# install-macos.sh. Data (the sqlite db, wwwroot) is kept unless you pass
# --purge — mirrors the Linux uninstall.sh's "ask before deleting data"
# caution from the project plan.

set -euo pipefail

LABEL="org.intech.kursor"
INSTALL_DIR="/usr/local/opt/kursor"
DATA_DIR="/usr/local/var/kursor"
LOG_DIR="/usr/local/var/log/kursor"
PLIST_PATH="/Library/LaunchDaemons/${LABEL}.plist"

[ "$(id -u)" -eq 0 ] || { echo "run with sudo: sudo ./scripts/uninstall-macos.sh" >&2; exit 1; }

echo "==> stopping the service"
launchctl bootout system "$LABEL" >/dev/null 2>&1 || launchctl unload -w "$PLIST_PATH" 2>/dev/null || true

echo "==> removing launchd unit and binary"
rm -f "$PLIST_PATH"
rm -rf "$INSTALL_DIR"

if [ "${1:-}" = "--purge" ]; then
  echo "==> removing data (--purge): ${DATA_DIR}, ${LOG_DIR}"
  rm -rf "$DATA_DIR" "$LOG_DIR"
else
  echo "==> keeping data at ${DATA_DIR} and logs at ${LOG_DIR} (pass --purge to delete them too)"
fi

echo "done."
