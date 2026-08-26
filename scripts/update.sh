#!/usr/bin/env bash
# Run THIS ON THE SERVER ITSELF, inside a git clone of the repo (the
# same clone install.sh was run from, or a fresh one — see below) — the
# "pull from GitHub and redeploy" half of the workflow scripts/deploy.sh
# covers from your own machine. Whichever one is more convenient for a
# given moment; both end at the same place (new binary, service
# restarted, DB migrated automatically on the new binary's own startup).
#
# First time on a fresh server:
#   git clone https://github.com/OleksandrPLT/Kursor_lite.git
#   cd Kursor_lite
#   sudo ./scripts/install.sh
#
# Every update after that:
#   cd Kursor_lite
#   sudo ./scripts/update.sh

set -euo pipefail

APP_NAME="kursor"
UNIT_NAME="kursor.service"
BIN_PATH="/opt/${APP_NAME}/bin/kursord"

log() { echo "==> $*"; }
die() { echo "error: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run with sudo: sudo ./scripts/update.sh"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"
[ -d .git ] || die "this isn't a git checkout — clone the repo first (see the comment at the top of this script)."

REAL_HOME="$(eval echo "~${SUDO_USER:-$(whoami)}")"
if ! command -v go >/dev/null 2>&1; then
  if [ -x "${REAL_HOME}/sdk/go/bin/go" ]; then
    export PATH="${REAL_HOME}/sdk/go/bin:$PATH"
  elif [ -x "/usr/local/go/bin/go" ]; then
    export PATH="/usr/local/go/bin:$PATH"
  fi
fi
command -v go >/dev/null 2>&1 || die "Go is not installed on this server. Install it, or use scripts/deploy.sh from your own machine instead (it cross-compiles and ships the binary, no Go needed here)."

log "pulling latest from origin..."
BEFORE="$(git rev-parse HEAD)"
git pull --ff-only
AFTER="$(git rev-parse HEAD)"
if [ "$BEFORE" = "$AFTER" ]; then
  log "already up to date ($AFTER) — rebuilding anyway in case local files changed"
fi

log "building kursord..."
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo dev)"
go build -ldflags "-X kursor/internal/version.GitCommit=${GIT_COMMIT}" -o "${BUILD_DIR}/kursord" ./cmd/kursord
log "build ok"

install -m 0755 "${BUILD_DIR}/kursord" "$BIN_PATH"

log "restarting ${UNIT_NAME}..."
systemctl restart "$UNIT_NAME"
sleep 1
systemctl is-active --quiet "$UNIT_NAME" || die "service failed to come back up — check: journalctl -u ${UNIT_NAME} -n 50"

log "up and running: $(git log -1 --format='%h %s')"
