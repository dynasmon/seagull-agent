#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="seagull-agent"
KEEP_IDENTITY="1"

usage() {
  cat <<'USAGE'
Usage: uninstall.sh [--purge]

  --purge   Also remove /etc/seagull and /var/lib/seagull (identity, certificates, spool)
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge) KEEP_IDENTITY="0"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[uninstall] unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "[uninstall] run as root" >&2
  exit 1
fi

systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
systemctl disable "${SERVICE_NAME}" 2>/dev/null || true

rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
rm -rf "/etc/systemd/system/${SERVICE_NAME}.service.d"
systemctl daemon-reload || true

rm -f /usr/local/bin/seagull-agent

if [[ "${KEEP_IDENTITY}" == "0" ]]; then
  rm -rf /etc/seagull /var/lib/seagull /var/log/seagull
  echo "[uninstall] removed binary, unit, configuration, and identity state"
else
  echo "[uninstall] removed binary and unit; kept /etc/seagull and /var/lib/seagull"
  echo "[uninstall] re-run with --purge to remove identity state"
fi
