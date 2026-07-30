#!/usr/bin/env bash
set -euo pipefail

SEAGULL_PACKAGE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export SEAGULL_PACKAGE_DIR
source "${SEAGULL_PACKAGE_DIR}/lib/common.sh"
source "${SEAGULL_PACKAGE_DIR}/lib/envfile.sh"
source "${SEAGULL_PACKAGE_DIR}/lib/layout.sh"
source "${SEAGULL_PACKAGE_DIR}/lib/artifact.sh"
source "${SEAGULL_PACKAGE_DIR}/lib/service.sh"
source "${SEAGULL_PACKAGE_DIR}/lib/state.sh"
source "${SEAGULL_PACKAGE_DIR}/lib/migrate.sh"

AUTO_ROLLBACK=1
SNAPSHOT_DIR=""

cleanup() {
  if [[ -n "${SNAPSHOT_DIR}" && -d "${SNAPSHOT_DIR}" ]]; then
    rm -rf "${SNAPSHOT_DIR}"
  fi
}
trap cleanup EXIT

usage() {
  cat <<'USAGE'
Usage: upgrade.sh [--no-rollback]

Replaces the installed binary and unit with the version in this package while
preserving the agent identity, credential, spool, trust anchor and local
configuration. On failure the previous release is restored automatically.

  --no-rollback   Leave the failed release in place instead of restoring
  -h, --help      Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-rollback) AUTO_ROLLBACK=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

main() {
  require_root
  layout_init

  [[ -f "${ENV_PATH}" ]] || die "no existing installation found at ${ENV_PATH}; run install.sh first"

  artifact_verify_manifest "${SEAGULL_PACKAGE_DIR}"
  artifact_verify_signature "${SEAGULL_PACKAGE_DIR}"
  artifact_binary_runtime_deps "${SEAGULL_PACKAGE_DIR}/seagull-agent"

  local target previous
  target="$(artifact_version "${SEAGULL_PACKAGE_DIR}")"
  previous="$(state_read_release current)"

  if [[ "${target}" == "${previous}" ]]; then
    log "seagull-agent ${target} is already the active release"
  fi

  SNAPSHOT_DIR="$(mktemp -d)"
  state_snapshot_identity "${SNAPSHOT_DIR}"

  if [[ -n "${previous}" && ! -f "$(state_release_path "${previous}")" && -f "${BIN_PATH}" ]]; then
    state_store_release "${previous}" "${BIN_PATH}" >/dev/null
  fi

  layout_create_directories
  migrate_legacy_installation

  local profile capabilities
  profile="$(env_value SEAGULL_AGENT_PROFILE "${ENV_PATH}")"
  profile="${profile:-sensor}"
  capabilities="$(service_derive_capabilities "${profile}" "$(env_value SEAGULL_SOURCES "${ENV_PATH}")" "$(env_value SEAGULL_LATERAL_MODE "${ENV_PATH}")")"

  state_store_release "${target}" "${SEAGULL_PACKAGE_DIR}/seagull-agent" >/dev/null
  state_activate_release "${target}"
  service_write_profile_dropin "${profile}" "${capabilities}"
  service_install_unit "${SEAGULL_PACKAGE_DIR}/share/systemd/seagull-agent.service"
  layout_secure_secrets

  if systemd_available; then
    service_restart || true
    if ! service_wait_healthy 25; then
      service_report_failure
      if [[ "${AUTO_ROLLBACK}" == "1" && -n "${previous}" && -f "$(state_release_path "${previous}")" ]]; then
        warn "upgrade to ${target} failed; restoring ${previous}"
        state_activate_release "${previous}"
        state_record_release "${previous}" "${target}"
        service_restart || true
        die "upgrade failed and was rolled back to ${previous}"
      fi
      die "upgrade to ${target} failed"
    fi
  fi

  state_assert_identity_preserved "${SNAPSHOT_DIR}"
  state_record_release "${target}" "${previous}"
  state_prune_releases "${target}" "${previous}"

  log "upgraded seagull-agent ${previous:-unknown} -> ${target} (profile: ${profile})"
}

main "$@"
