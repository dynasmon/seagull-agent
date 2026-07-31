#!/usr/bin/env bash
set -euo pipefail

SEAGULL_PACKAGE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export SEAGULL_PACKAGE_DIR
source "${SEAGULL_PACKAGE_DIR}/lib/common.sh"
source "${SEAGULL_PACKAGE_DIR}/lib/validation.sh"
source "${SEAGULL_PACKAGE_DIR}/lib/envfile.sh"
source "${SEAGULL_PACKAGE_DIR}/lib/layout.sh"
source "${SEAGULL_PACKAGE_DIR}/lib/service.sh"
source "${SEAGULL_PACKAGE_DIR}/lib/state.sh"

TARGET=""
SNAPSHOT_DIR=""

cleanup() {
  if [[ -n "${SNAPSHOT_DIR}" && -d "${SNAPSHOT_DIR}" ]]; then
    rm -rf "${SNAPSHOT_DIR}"
  fi
}
trap cleanup EXIT

usage() {
  cat <<'USAGE'
Usage: rollback.sh [--to VERSION] [--list]

Restores a release from the local immutable release store without changing
identity, credentials, telemetry backlog or local configuration.

  --to VERSION   Release to activate
  --list         List releases available on this host
  -h, --help     Show this help
USAGE
}

list_releases() {
  layout_init
  if [[ ! -d "${RELEASE_DIR}" ]]; then
    log "no releases stored on this host"
    return 0
  fi
  local current previous name marker
  current="$(state_read_release current)"
  previous="$(state_read_release previous)"
  while IFS= read -r name; do
    marker=""
    [[ "${name}" == "${current}" ]] && marker=" (current)"
    [[ "${name}" == "${previous}" ]] && marker=" (previous)"
    printf '%s%s\n' "${name}" "${marker}"
  done < <(find "${RELEASE_DIR}" -mindepth 1 -maxdepth 1 -type d ! -name '.*' -printf '%f\n' | sort -V)
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --to)
      require_option_value "$1" "${2-}"
      TARGET="$2"
      shift 2
      ;;
    --list)
      list_releases
      exit 0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

restore_current_after_failure() {
  local current="$1"
  local failed="$2"
  service_stop
  state_activate_release "${current}"
  service_install_unit
  state_record_release "${current}" "${failed}"
  if systemd_available; then
    if ! service_restart || ! service_wait_healthy 30 0; then
      service_report_failure
      die "rollback failed and the original release could not be restarted"
    fi
  fi
  die "rollback to ${failed} failed; restored ${current}"
}

main() {
  require_root
  require_systemd
  layout_init
  acquire_install_lock

  local current
  current="$(state_read_release current)"
  [[ -n "${current}" ]] || die "no active release is recorded"
  validate_semver "${current}"
  if [[ -z "${TARGET}" ]]; then
    TARGET="$(state_read_release previous)"
  fi
  [[ -n "${TARGET}" ]] || die "no previous release is recorded; pass --to VERSION"
  validate_semver "${TARGET}"
  [[ -f "$(state_release_path "${TARGET}")" ]] || die "release ${TARGET} is not stored on this host"
  [[ -f "$(state_release_unit_path "${TARGET}")" ]] || die "release ${TARGET} has no stored systemd unit"
  if [[ "${TARGET}" == "${current}" ]]; then
    log "seagull-agent ${TARGET} is already active"
    return 0
  fi

  local profile sources capabilities
  profile="$(env_value SEAGULL_AGENT_PROFILE "${ENV_PATH}")"
  profile="${profile:-sensor}"
  validate_profile "${profile}"
  sources="$(env_value SEAGULL_SOURCES "${ENV_PATH}")"
  sources="${sources:-authlog,proc,proc_exec,fim,scan,ddos,l7}"
  sources="$(validate_sources "${sources}")"
  layout_configure_log_read "${sources}"
  capabilities="$(service_derive_capabilities "${profile}" "${sources}" "$(env_value SEAGULL_LATERAL_MODE "${ENV_PATH}")")"

  SNAPSHOT_DIR="$(mktemp -d)"
  state_snapshot_identity "${SNAPSHOT_DIR}"
  service_stop
  state_activate_release "${TARGET}"
  service_write_profile_dropin "${profile}" "${capabilities}"
  service_install_unit
  state_assert_identity_preserved "${SNAPSHOT_DIR}"
  state_record_release "${TARGET}" "${current}"

  if systemd_available; then
    service_restart || true
    if ! service_wait_healthy 30 0; then
      service_report_failure
      restore_current_after_failure "${current}" "${TARGET}"
    fi
  fi

  log "rolled back seagull-agent ${current} -> ${TARGET}"
}

main "$@"
