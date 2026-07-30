#!/usr/bin/env bash
set -euo pipefail

SEAGULL_PACKAGE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export SEAGULL_PACKAGE_DIR
source "${SEAGULL_PACKAGE_DIR}/lib/common.sh"
source "${SEAGULL_PACKAGE_DIR}/lib/envfile.sh"
source "${SEAGULL_PACKAGE_DIR}/lib/layout.sh"
source "${SEAGULL_PACKAGE_DIR}/lib/service.sh"
source "${SEAGULL_PACKAGE_DIR}/lib/state.sh"

TARGET=""

usage() {
  cat <<'USAGE'
Usage: rollback.sh [--to VERSION] [--list]

Restores a previously installed release from the local release store. Agent
identity, credential, spool and configuration are never touched.

  --to VERSION   Release to activate (default: the previous release)
  --list         List the releases available on this host
  -h, --help     Show this help
USAGE
}

list_releases() {
  layout_init
  if [[ ! -d "${RELEASE_DIR}" ]]; then
    log "no releases stored on this host"
    return 0
  fi
  local current previous name
  current="$(state_read_release current)"
  previous="$(state_read_release previous)"
  while IFS= read -r name; do
    local marker=""
    [[ "${name}" == "${current}" ]] && marker=" (current)"
    [[ "${name}" == "${previous}" ]] && marker=" (previous)"
    printf '%s%s\n' "${name}" "${marker}"
  done < <(find "${RELEASE_DIR}" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort)
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --to) TARGET="$2"; shift 2 ;;
    --list) list_releases; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

main() {
  require_root
  layout_init

  local current
  current="$(state_read_release current)"
  if [[ -z "${TARGET}" ]]; then
    TARGET="$(state_read_release previous)"
  fi
  [[ -n "${TARGET}" ]] || die "no previous release recorded; pass --to VERSION (see --list)"
  [[ -f "$(state_release_path "${TARGET}")" ]] || die "release ${TARGET} is not stored on this host (see --list)"
  if [[ "${TARGET}" == "${current}" ]]; then
    log "seagull-agent ${TARGET} is already active"
    return 0
  fi

  local profile capabilities
  profile="$(env_value SEAGULL_AGENT_PROFILE "${ENV_PATH}")"
  profile="${profile:-sensor}"
  capabilities="$(service_derive_capabilities "${profile}" "$(env_value SEAGULL_SOURCES "${ENV_PATH}")" "$(env_value SEAGULL_LATERAL_MODE "${ENV_PATH}")")"

  state_activate_release "${TARGET}"
  service_write_profile_dropin "${profile}" "${capabilities}"

  if systemd_available; then
    service_restart || true
    if ! service_wait_healthy 25; then
      service_report_failure
      die "rollback to ${TARGET} did not start cleanly"
    fi
  fi

  state_record_release "${TARGET}" "${current}"
  log "rolled back seagull-agent ${current:-unknown} -> ${TARGET}"
}

main "$@"
