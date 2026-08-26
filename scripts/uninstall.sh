#!/usr/bin/env bash
# Removes the Kursor by Intech systemd service installed by install.sh.
# Data (the sqlite db, wwwroot) is kept unless you pass --purge.

set -euo pipefail

UNIT_NAME="kursor.service"
INSTALL_DIR="/opt/kursor"
DATA_DIR="/var/lib/kursor"
WWW_ROOT="/var/www/kursor"
LOG_DIR="/var/log/kursor"
UNIT_PATH="/etc/systemd/system/${UNIT_NAME}"

[ "$(id -u)" -eq 0 ] || { echo "run with sudo: sudo ./scripts/uninstall.sh" >&2; exit 1; }

echo "==> stopping and disabling ${UNIT_NAME}"
systemctl stop "$UNIT_NAME" 2>/dev/null || true
systemctl disable "$UNIT_NAME" 2>/dev/null || true

echo "==> removing systemd unit and binary"
rm -f "$UNIT_PATH"
systemctl daemon-reload
rm -rf "$INSTALL_DIR"

echo "==> removing MOTD banner"
rm -f /etc/update-motd.d/50-kursor
if [ -f /etc/motd ]; then
  sed -i "/# >>> kursor motd/,/# <<< kursor motd <<</d" /etc/motd 2>/dev/null || true
fi

if [ "${1:-}" = "--purge" ]; then
  echo "==> removing data (--purge): ${DATA_DIR}, ${WWW_ROOT}, ${LOG_DIR}"
  rm -rf "$DATA_DIR" "$WWW_ROOT" "$LOG_DIR"
else
  echo "==> keeping data at ${DATA_DIR}, sites at ${WWW_ROOT}, and logs at ${LOG_DIR} (pass --purge to delete them too)"
fi

echo "done."
