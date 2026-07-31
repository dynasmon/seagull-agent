#!/usr/bin/env bash
set -euo pipefail

SEAGULL_PACKAGE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export SEAGULL_PACKAGE_DIR
source "${SEAGULL_PACKAGE_DIR}/lib/common.sh"
source "${SEAGULL_PACKAGE_DIR}/lib/validation.sh"
source "${SEAGULL_PACKAGE_DIR}/lib/envfile.sh"
source "${SEAGULL_PACKAGE_DIR}/lib/layout.sh"
source "${SEAGULL_PACKAGE_DIR}/lib/artifact.sh"
source "${SEAGULL_PACKAGE_DIR}/lib/service.sh"
source "${SEAGULL_PACKAGE_DIR}/lib/state.sh"
source "${SEAGULL_PACKAGE_DIR}/lib/migrate.sh"

AUTO_ROLLBACK=1
ALLOW_DOWNGRADE=0
SNAPSHOT_DIR=""

cleanup() {
  if [[ -n "${SNAPSHOT_DIR}" && -d "${SNAPSHOT_DIR}" ]]; then
    rm -rf "${SNAPSHOT_DIR}"
  fi
}
trap cleanup EXIT

usage() {
  cat <<'USAGE'
Usage: upgrade.sh [--allow-downgrade] [--no-rollback]

Installs the release in this package while preserving endpoint identity,
credentials, telemetry backlog, trust state and local configuration.

  --allow-downgrade  Permit a target version older than the active release
  --no-rollback      Keep a failed target active instead of restoring the prior release
  -h, --help         Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --allow-downgrade)
      ALLOW_DOWNGRADE=1
      shift
      ;;
    --no-rollback)
      AUTO_ROLLBACK=0
      shift
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

preserve_untracked_release() {
  local version="$1"
  [[ -n "${version}" ]] || return 0
  if [[ -f "$(state_release_path "${version}")" ]]; then
    return 0
  fi
  local unit="${UNIT_PATH}"
  if [[ ! -f "${unit}" ]]; then
    unit="${SEAGULL_PACKAGE_DIR}/share/systemd/seagull-agent.service"
  fi
  state_store_release "${version}" "${BIN_PATH}" "${unit}" >/dev/null
}

restore_release() {
  local version="$1"
  local failed="$2"
  warn "upgrade to ${failed} failed; restoring ${version}"
  service_stop
  state_activate_release "${version}"
  service_install_unit
  state_record_release "${version}" "${failed}"
  if systemd_available; then
    if ! service_restart || ! service_wait_healthy 30 0; then
      service_report_failure
      die "upgrade and automatic rollback both failed"
    fi
  fi
  die "upgrade failed and was rolled back to ${version}"
}

main() {
  require_root
  require_systemd
  layout_init
  acquire_install_lock

  [[ -f "${ENV_PATH}" ]] || die "no existing installation found at ${ENV_PATH}; run install.sh first"
  [[ -x "${BIN_PATH}" ]] || die "no installed agent binary found at ${BIN_PATH}"
  artifact_verify_package "${SEAGULL_PACKAGE_DIR}"
  layout_create_directories
  migrate_legacy_installation
  layout_secure_secrets

  local target previous rollback
  target="$(artifact_version "${SEAGULL_PACKAGE_DIR}")"
  previous="$(state_read_release current)"
  rollback="$(state_read_release previous)"
  if [[ -z "${previous}" ]]; then
    previous="$(state_detect_active_version)"
    [[ -n "${previous}" ]] || die "unable to determine the installed release version"
    preserve_untracked_release "${previous}"
    state_record_release "${previous}" ""
  fi
  validate_semver "${previous}"
  if [[ -n "${rollback}" ]]; then
    validate_semver "${rollback}"
  fi
  if [[ "$(semver_compare "${target}" "${previous}")" == "-1" && "${ALLOW_DOWNGRADE}" != "1" ]]; then
    die "refusing downgrade ${previous} -> ${target}; pass --allow-downgrade to authorize it"
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

  if [[ "${target}" == "${previous}" ]]; then
    state_store_release \
      "${target}" \
      "${SEAGULL_PACKAGE_DIR}/seagull-agent" \
      "${SEAGULL_PACKAGE_DIR}/share/systemd/seagull-agent.service" \
      "${SEAGULL_PACKAGE_DIR}/VERSION" >/dev/null
    service_stop
    state_activate_release "${target}"
    service_write_profile_dropin "${profile}" "${capabilities}"
    service_install_unit
    state_record_release "${target}" "${rollback}"
    if systemd_available; then
      if ! service_restart || ! service_wait_healthy 30 0; then
        service_report_failure
        die "failed to reconcile seagull-agent ${target}"
      fi
    fi
    log "reconciled active seagull-agent ${target}"
    return 0
  fi

  SNAPSHOT_DIR="$(mktemp -d)"
  state_snapshot_identity "${SNAPSHOT_DIR}"
  preserve_untracked_release "${previous}"
  state_store_release \
    "${target}" \
    "${SEAGULL_PACKAGE_DIR}/seagull-agent" \
    "${SEAGULL_PACKAGE_DIR}/share/systemd/seagull-agent.service" \
    "${SEAGULL_PACKAGE_DIR}/VERSION" >/dev/null

  service_stop
  state_activate_release "${target}"
  service_write_profile_dropin "${profile}" "${capabilities}"
  service_install_unit
  state_assert_identity_preserved "${SNAPSHOT_DIR}"
  state_record_release "${target}" "${previous}"

  if systemd_available; then
    service_restart || true
    if ! service_wait_healthy 30 0; then
      service_report_failure
      if [[ "${AUTO_ROLLBACK}" == "1" ]]; then
        restore_release "${previous}" "${target}"
      fi
      die "upgrade to ${target} failed"
    fi
  fi

  state_prune_releases "${target}" "${previous}"
  log "upgraded seagull-agent ${previous} -> ${target} (profile: ${profile})"
}

main "$@"
