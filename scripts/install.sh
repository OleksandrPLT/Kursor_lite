#!/usr/bin/env bash
# Installs Kursor by Intech as a systemd service on Linux — the primary
# ("загальну") target; see install-macos.sh for the launchd variant used
# on the Mac Pro deployment.
#
# Run from the project root, on the machine that will actually run the
# panel:
#   sudo ./scripts/install.sh
#
# What it does:
#   1. Builds kursord from source for this host's own arch.
#   2. Lays out /opt/kursor (binary), /var/lib/kursor (data/sqlite),
#      /var/www/kursor (managed site docroots), /var/log/kursor.
#   3. Installs a systemd unit so it starts at boot and restarts itself
#      if it ever crashes.
#   4. Drops a Kursor by Intech banner into the box's login MOTD, so
#      anyone who lands on this machine — via a real SSH session or
#      Kursor's own web terminal — sees at a glance what it's running.
#   5. Prints the panel URL + the first-run admin password.

set -euo pipefail

APP_NAME="kursor"
UNIT_NAME="kursor.service"
INSTALL_DIR="/opt/${APP_NAME}"
BIN_PATH="${INSTALL_DIR}/bin/kursord"
DATA_DIR="/var/lib/${APP_NAME}"
WWW_ROOT="/var/www/${APP_NAME}"
LOG_DIR="/var/log/${APP_NAME}"
UNIT_PATH="/etc/systemd/system/${UNIT_NAME}"
PORT="${KURSOR_PORT:-8888}"

# --- brand banner --------------------------------------------------------
# Exact Intech palette (see project brand notes) via 24-bit ANSI — the
# same two colors and the same "▌ KURSOR" / "▌ by Intech" shape the web
# terminal prints on every session and the systemd MOTD drop-in below
# prints on every login, so the mark is consistent everywhere you land
# on this box.
YELLOW='\033[38;2;255;213;0m'
BLUE='\033[38;2;0;87;183m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

banner() {
  printf "${YELLOW}${BOLD}▌ KURSOR${RESET}\n"
  printf "${BLUE}${BOLD}▌ by Intech${RESET}${DIM}  ·  intech.org.ua${RESET}\n\n"
}

log() { echo "==> $*"; }
die() { echo "error: $*" >&2; exit 1; }

# --- spinner ---------------------------------------------------------------
# Runs $2.. in the background and shows a spinner next to label $1 until
# it finishes — purely cosmetic, but every step below is a real command
# (build, systemctl calls, file writes), never faked.
spin() {
  local label="$1"; shift
  "$@" >/tmp/kursor-install-step.log 2>&1 &
  local pid=$!
  local frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  local i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r%s %s" "${frames:i++%${#frames}:1}" "$label"
    sleep 0.08
  done
  wait "$pid"
  local status=$?
  if [ $status -eq 0 ]; then
    printf "\r✔ %s\n" "$label"
  else
    printf "\r✘ %s\n" "$label"
    cat /tmp/kursor-install-step.log >&2
  fi
  rm -f /tmp/kursor-install-step.log
  return $status
}

banner

[ "$(uname -s)" = "Linux" ] || die "this script is for Linux only — see scripts/install-macos.sh for macOS"
[ "$(id -u)" -eq 0 ] || die "run with sudo: sudo ./scripts/install.sh"

# --- 1. Go toolchain -------------------------------------------------------
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

# --- 2. Build ---------------------------------------------------------------
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"
BUILD_DIR="$(mktemp -d)"
spin "building kursord" go build -o "${BUILD_DIR}/kursord" ./cmd/kursord

# --- 3. Install files --------------------------------------------------
spin "creating directories" mkdir -p "${INSTALL_DIR}/bin" "$DATA_DIR" "$WWW_ROOT" "$LOG_DIR"
install -m 0755 "${BUILD_DIR}/kursord" "$BIN_PATH"
rm -rf "$BUILD_DIR"

# --- 4. systemd unit ---------------------------------------------------
# Runs as root — site/database/file management and the web terminal need
# it; see the project's SECURITY notes for that trade-off (same one
# install-macos.sh documents for the launchd path).
log "writing ${UNIT_PATH}"
cat > "$UNIT_PATH" <<UNIT
[Unit]
Description=Kursor by Intech — server control panel
After=network.target

[Service]
Type=simple
ExecStart=${BIN_PATH}
Environment=KURSOR_ADDR=:${PORT}
Environment=KURSOR_DATA_DIR=${DATA_DIR}
Environment=KURSOR_WWW_ROOT=${WWW_ROOT}
Restart=on-failure
RestartSec=2
StandardOutput=append:${LOG_DIR}/kursord.log
StandardError=append:${LOG_DIR}/kursord.log

[Install]
WantedBy=multi-user.target
UNIT

spin "reloading systemd" systemctl daemon-reload
spin "starting ${UNIT_NAME}" systemctl enable --now "$UNIT_NAME"

sleep 2

# --- 5. MOTD banner -----------------------------------------------------
# Ubuntu/Debian render /etc/update-motd.d/* dynamically on every login and
# ignore a hand-edited /etc/motd; anything else (RHEL/CentOS/etc.) just
# reads /etc/motd directly. Cover both, so the banner shows up on a real
# SSH login to this box either way — not just inside Kursor's own web
# terminal.
if [ -d /etc/update-motd.d ]; then
  log "installing MOTD banner (update-motd.d)"
  cat > /etc/update-motd.d/50-kursor <<MOTD
#!/bin/sh
printf '${YELLOW}${BOLD}▌ KURSOR${RESET}\n'
printf '${BLUE}${BOLD}▌ by Intech${RESET}${DIM}  ·  intech.org.ua${RESET}\n\n'
MOTD
  chmod 0755 /etc/update-motd.d/50-kursor
else
  log "installing MOTD banner (/etc/motd)"
  BEGIN_MARK="# >>> kursor motd — do not edit below by hand >>>"
  END_MARK="# <<< kursor motd <<<"
  touch /etc/motd
  sed -i "/${BEGIN_MARK}/,/${END_MARK}/d" /etc/motd 2>/dev/null || true
  {
    echo "$BEGIN_MARK"
    printf '▌ KURSOR\n▌ by Intech  ·  intech.org.ua\n'
    echo "$END_MARK"
    cat /etc/motd
  } > /etc/motd.new && mv /etc/motd.new /etc/motd
fi

# --- 6. firewall ---------------------------------------------------------
# Only ever opens the panel's own port, automatically — every other port
# a Kursor module can use (VPN, DNS, a site's 80/443, ...) stays closed
# until you actually turn that module on from the UI; see
# configs/PORTS.md for the full "what opens when" reference, printed
# again below.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  log "opening port ${PORT}/tcp (ufw)"
  ufw allow "${PORT}/tcp" >/dev/null 2>&1 || true
elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
  log "opening port ${PORT}/tcp (firewalld)"
  firewall-cmd --permanent --add-port="${PORT}/tcp" >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
else
  log "no active ufw/firewalld detected — skipping automatic firewall rule"
fi

# --- done ----------------------------------------------------------------
LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -n "$LAN_IP" ] || LAN_IP="<this-server-ip>"

echo ""
echo "=========================================="
echo " Kursor by Intech installed as a systemd service"
echo " Panel URL:  http://${LAN_IP}:${PORT}  (also http://localhost:${PORT})"
echo " Logs:       ${LOG_DIR}/kursord.log  (also: journalctl -u ${UNIT_NAME} -f)"
echo " Data:       ${DATA_DIR}"
echo "=========================================="
echo ""

if grep -q "first run" "${LOG_DIR}/kursord.log" 2>/dev/null; then
  echo "First-run admin credentials:"
  grep -A3 "first run" "${LOG_DIR}/kursord.log" | tail -4
  echo ""
fi

echo "Ports opened so far: ${PORT}/tcp (this panel) only."
echo "VPN/DNS/site ports are NOT opened automatically — open them yourself"
echo "when you actually turn those modules on. See configs/PORTS.md."
echo ""
echo "Manage the service with:"
echo "  sudo systemctl restart ${UNIT_NAME}"
echo "  sudo systemctl stop ${UNIT_NAME}"
echo "  journalctl -u ${UNIT_NAME} -f"
echo "  sudo ./scripts/uninstall.sh   # remove entirely"
