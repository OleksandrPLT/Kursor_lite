#!/usr/bin/env bash
# Ships a new build of kursord to an already-installed host (one that
# ran scripts/install.sh) and restarts the service — the whole "push an
# update" story for this project, since there's nothing else to ship:
#   - one static binary (go:embed bakes in every template/static asset,
#     so there's no separate "sync the frontend" step)
#   - schema migrations run automatically on the new binary's own
#     startup (see internal/store.Open -> migrate()), so there's no
#     manual DB step either
#
# Usage:
#   ./scripts/deploy.sh user@host [linux/amd64|linux/arm64]
#
# Requires SSH key access to the host with sudo (passwordless sudo, or
# run interactively where a sudo password prompt is fine — this script
# doesn't try to suppress that).

set -euo pipefail

log() { echo "==> $*"; }
die() { echo "error: $*" >&2; exit 1; }

[ $# -ge 1 ] || die "usage: $0 user@host [linux/amd64|linux/arm64]"
TARGET="$1"
PLATFORM="${2:-linux/amd64}"
GOOS="${PLATFORM%/*}"
GOARCH="${PLATFORM#*/}"

APP_NAME="kursor"
UNIT_NAME="kursor.service"
BIN_PATH="/opt/${APP_NAME}/bin/kursord"
REMOTE_TMP="/tmp/kursord.new.$$"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

if ! command -v go >/dev/null 2>&1; then
  if [ -x "$HOME/sdk/go/bin/go" ]; then export PATH="$HOME/sdk/go/bin:$PATH"; fi
fi
command -v go >/dev/null 2>&1 || die "Go is not installed locally — this script cross-compiles on your machine, not the target host."

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

log "building kursord for ${GOOS}/${GOARCH} ..."
GOOS="$GOOS" GOARCH="$GOARCH" go build -o "${BUILD_DIR}/kursord" ./cmd/kursord
log "build ok ($(du -h "${BUILD_DIR}/kursord" | cut -f1))"

log "uploading to ${TARGET}:${REMOTE_TMP}"
scp -q "${BUILD_DIR}/kursord" "${TARGET}:${REMOTE_TMP}"

log "installing and restarting ${UNIT_NAME} on ${TARGET}"
ssh "$TARGET" bash -s -- "$REMOTE_TMP" "$BIN_PATH" "$UNIT_NAME" <<'REMOTE'
set -euo pipefail
NEW_BIN="$1"
BIN_PATH="$2"
UNIT_NAME="$3"

chmod +x "$NEW_BIN"
sudo mv "$NEW_BIN" "$BIN_PATH"
sudo systemctl restart "$UNIT_NAME"
sleep 1
sudo systemctl is-active --quiet "$UNIT_NAME" || { echo "service failed to come back up — check: journalctl -u ${UNIT_NAME} -n 50" >&2; exit 1; }
echo "service is active"
REMOTE

log "verifying panel responds..."
if ssh "$TARGET" 'curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/login' | grep -q 200; then
  log "deploy ok — /login responded 200"
else
  echo "warning: /login didn't respond 200 after restart — check the service logs on the host." >&2
fi
