#!/usr/bin/env bash
set -euo pipefail

SEAGULL_PACKAGE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export SEAGULL_PACKAGE_DIR
source "${SEAGULL_PACKAGE_DIR}/lib/common.sh"
source "${SEAGULL_PACKAGE_DIR}/lib/envfile.sh"
source "${SEAGULL_PACKAGE_DIR}/lib/layout.sh"
source "${SEAGULL_PACKAGE_DIR}/lib/service.sh"

PURGE=0
REMOVE_USER=0

usage() {
  cat <<'USAGE'
Usage: uninstall.sh [--purge] [--remove-user]

Stops and removes the service, unit and binary. Identity, configuration and
spooled telemetry are kept unless --purge is given.

  --purge         Also remove /etc/seagull, /var/lib/seagull and /var/log/seagull
  --remove-user   Also remove the seagull service user (implies --purge)
  -h, --help      Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge) PURGE=1; shift ;;
    --remove-user) PURGE=1; REMOVE_USER=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

main() {
  require_root
  layout_init
  acquire_install_lock

  if systemd_available; then
    systemctl disable --now "${SERVICE_NAME}" >/dev/null 2>&1 || true
    systemctl stop seagull-agent-ca-sync.timer >/dev/null 2>&1 || true
    systemctl disable seagull-agent-ca-sync.timer >/dev/null 2>&1 || true
  fi

  service_remove_unit
  layout_configure_log_read ""
  rm -f "$(rooted /etc/systemd/system/seagull-agent-ca-sync.service)"
  rm -f "$(rooted /etc/systemd/system/seagull-agent-ca-sync.timer)"
  rm -f "$(rooted /usr/local/lib/seagull/seagull-agent-sync-ca.sh)"
  rm -f "${BIN_PATH}"
  rm -rf "${RELEASE_DIR}"
  rm -f "${RELEASE_STATE_PATH}"

  if [[ "${PURGE}" == "1" ]]; then
    rm -rf "${CONFIG_DIR}" "${STATE_DIR}" "${LOG_DIR}"
    log "removed the binary, unit, configuration and identity state"
  else
    log "removed the binary and unit; kept ${CONFIG_DIR} and ${STATE_DIR}"
    log "re-run with --purge to remove identity state"
  fi

  if [[ "${REMOVE_USER}" == "1" ]] && ! is_staged_root; then
    if id -u "${SEAGULL_USER}" >/dev/null 2>&1; then
      userdel "${SEAGULL_USER}" >/dev/null 2>&1 || true
      log "removed the ${SEAGULL_USER} service user"
    fi
  fi
}

main "$@"
