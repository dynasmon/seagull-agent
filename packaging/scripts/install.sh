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

ARG_API_URL="${SEAGULL_API_URL:-}"
ARG_ENROLL_URL="${SEAGULL_ENROLL_URL:-}"
ARG_AGENT_ID="${SEAGULL_AGENT_ID:-}"
ARG_PROFILE="${SEAGULL_AGENT_PROFILE:-}"
ARG_TOKEN="${SEAGULL_AGENT_ENROLL_TOKEN:-}"
ARG_TOKEN_FILE="${SEAGULL_AGENT_ENROLL_TOKEN_FILE:-}"
ARG_CA_FILE="${SEAGULL_AGENT_CA_FILE:-}"
ARG_TLS_SERVER_NAME="${SEAGULL_TLS_SERVER_NAME:-}"
ARG_SOURCES="${SEAGULL_SOURCES:-}"
ARG_CAPABILITIES="${SEAGULL_AGENT_CAPABILITIES:-}"
ARG_BINARY=""
ARG_START="auto"

usage() {
  cat <<'USAGE'
Usage: install.sh [options]

  --api-url URL             Agent API base URL (mTLS listener), e.g. https://siem.example.com:8444/agent
  --enroll-url URL          Enrollment base URL (server-TLS listener), e.g. https://siem.example.com:8445
  --agent-id ID             Stable agent identifier
  --profile NAME            Security profile: sensor (default) or managed
  --enroll-token TOKEN      One-time enrollment token minted by the server
  --enroll-token-file PATH  File containing the enrollment token
  --ca-file PATH            Server CA bundle to trust; omit to use the system trust store
  --tls-server-name NAME    Expected TLS server name when it differs from the URL host
  --sources LIST            Comma separated collectors to enable
  --capabilities LIST       Explicit Linux capability set, or "none"; omit to derive from the profile
  --binary PATH             Agent binary to install (default: the binary shipped in this package)
  --start                   Start the service after install even without an enrollment secret
  --no-start                Install and enable only; never start
  -h, --help                Show this help

The installer is idempotent. Re-running it never replaces an existing agent
identity, credential, spool or local configuration.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-url) ARG_API_URL="$2"; shift 2 ;;
    --enroll-url) ARG_ENROLL_URL="$2"; shift 2 ;;
    --agent-id) ARG_AGENT_ID="$2"; shift 2 ;;
    --profile) ARG_PROFILE="$2"; shift 2 ;;
    --enroll-token) ARG_TOKEN="$2"; shift 2 ;;
    --enroll-token-file) ARG_TOKEN_FILE="$2"; shift 2 ;;
    --ca-file) ARG_CA_FILE="$2"; shift 2 ;;
    --tls-server-name) ARG_TLS_SERVER_NAME="$2"; shift 2 ;;
    --sources) ARG_SOURCES="$2"; shift 2 ;;
    --capabilities) ARG_CAPABILITIES="$2"; shift 2 ;;
    --binary) ARG_BINARY="$2"; shift 2 ;;
    --start) ARG_START="always"; shift ;;
    --no-start) ARG_START="never"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

validate_profile() {
  case "${ARG_PROFILE}" in
    ""|sensor|managed) ;;
    *) die "invalid --profile '${ARG_PROFILE}' (expected sensor or managed)" ;;
  esac
}

effective_profile() {
  if [[ -n "${ARG_PROFILE}" ]]; then
    printf '%s' "${ARG_PROFILE}"
    return
  fi
  local existing
  existing="$(env_value SEAGULL_AGENT_PROFILE "${ENV_PATH}")"
  if [[ -n "${existing}" ]]; then
    printf '%s' "${existing}"
    return
  fi
  printf 'sensor'
}

install_env_file() {
  if [[ ! -f "${ENV_PATH}" ]]; then
    install -m 0600 "${SEAGULL_PACKAGE_DIR}/share/env/seagull-agent.env.example" "${ENV_PATH}"
    log "created ${ENV_PATH}"
  else
    log "keeping existing ${ENV_PATH}"
  fi
  chmod 0600 "${ENV_PATH}"
}

configure_env_file() {
  local profile="$1"
  local root
  root="$(install_root)"

  [[ -n "${ARG_AGENT_ID}" ]] && set_env_value SEAGULL_AGENT_ID "${ARG_AGENT_ID}" "${ENV_PATH}"
  [[ -n "${ARG_API_URL}" ]] && set_env_value SEAGULL_API_URL "${ARG_API_URL}" "${ENV_PATH}"
  [[ -n "${ARG_ENROLL_URL}" ]] && set_env_value SEAGULL_ENROLL_URL "${ARG_ENROLL_URL}" "${ENV_PATH}"
  [[ -n "${ARG_TLS_SERVER_NAME}" ]] && set_env_value SEAGULL_TLS_SERVER_NAME "${ARG_TLS_SERVER_NAME}" "${ENV_PATH}"
  [[ -n "${ARG_SOURCES}" ]] && set_env_value SEAGULL_SOURCES "${ARG_SOURCES}" "${ENV_PATH}"
  set_env_value SEAGULL_AGENT_PROFILE "${profile}" "${ENV_PATH}"

  ensure_env_value SEAGULL_AGENT_IDENTITY_STATE_FILE "${IDENTITY_PATH#${root}}" "${ENV_PATH}"
  ensure_env_value SEAGULL_AGENT_CREDENTIAL_FILE "${CREDENTIAL_PATH#${root}}" "${ENV_PATH}"
  ensure_env_value SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE "${TOKEN_PATH#${root}}" "${ENV_PATH}"
  ensure_env_value SEAGULL_TLS_CERT_FILE "${CLIENT_CERT_PATH#${root}}" "${ENV_PATH}"
  ensure_env_value SEAGULL_TLS_KEY_FILE "${CLIENT_KEY_PATH#${root}}" "${ENV_PATH}"
  ensure_env_value SEAGULL_AGENT_SPOOL_DIR "${SPOOL_DIR#${root}}" "${ENV_PATH}"

  if [[ -z "$(env_value SEAGULL_API_URL "${ENV_PATH}")" ]]; then
    warn "SEAGULL_API_URL is not set; pass --api-url or edit ${ENV_PATH}"
  fi
  if [[ -z "$(env_value SEAGULL_AGENT_ID "${ENV_PATH}")" ]]; then
    warn "SEAGULL_AGENT_ID is not set; pass --agent-id or edit ${ENV_PATH}"
  fi
}

install_ca_file() {
  [[ -n "${ARG_CA_FILE}" ]] || return 0
  [[ -f "${ARG_CA_FILE}" ]] || die "CA file not found: ${ARG_CA_FILE}"
  install -m 0644 "${ARG_CA_FILE}" "${CA_PATH}"
  set_env_value SEAGULL_TLS_CA_FILE "${CA_PATH#$(install_root)}" "${ENV_PATH}"
  log "installed server CA to ${CA_PATH}"
}

install_enroll_token() {
  local token="${ARG_TOKEN}"
  if [[ -z "${token}" && -n "${ARG_TOKEN_FILE}" ]]; then
    [[ -f "${ARG_TOKEN_FILE}" ]] || die "enroll token file not found: ${ARG_TOKEN_FILE}"
    token="$(trim "$(tr -d '\r\n' < "${ARG_TOKEN_FILE}")")"
  fi
  [[ -n "${token}" ]] || return 0
  install -d -m 0755 "$(dirname -- "${TOKEN_PATH}")"
  ( umask 077 && printf '%s' "${token}" > "${TOKEN_PATH}" )
  own "${TOKEN_PATH}"
  remove_env_key SEAGULL_AGENT_BOOTSTRAP_TOKEN "${ENV_PATH}"
  log "wrote the enrollment token to ${TOKEN_PATH}"
}

resolve_capabilities() {
  local profile="$1"
  case "${ARG_CAPABILITIES}" in
    none) printf '' ;;
    "") service_derive_capabilities "${profile}" "$(env_value SEAGULL_SOURCES "${ENV_PATH}")" "$(env_value SEAGULL_LATERAL_MODE "${ENV_PATH}")" ;;
    *) printf '%s' "${ARG_CAPABILITIES}" ;;
  esac
}

maybe_start() {
  case "${ARG_START}" in
    never)
      log "start skipped (--no-start)"
      return 0
      ;;
    auto)
      if ! state_runtime_ready; then
        log "start skipped: no enrollment token and no existing identity"
        log "provide --enroll-token and re-run, or start manually: systemctl start ${SERVICE_NAME}"
        return 0
      fi
      ;;
  esac
  if ! systemd_available; then
    return 0
  fi
  service_restart
  if service_wait_healthy 20; then
    log "service started"
    return 0
  fi
  service_report_failure
  die "the agent did not stay running after install"
}

main() {
  require_root
  require_systemd
  validate_profile
  layout_init

  if [[ -z "${ARG_BINARY}" ]]; then
    ARG_BINARY="${SEAGULL_PACKAGE_DIR}/seagull-agent"
    artifact_verify_manifest "${SEAGULL_PACKAGE_DIR}"
    artifact_verify_signature "${SEAGULL_PACKAGE_DIR}"
  fi
  [[ -f "${ARG_BINARY}" ]] || die "agent binary not found: ${ARG_BINARY}"
  artifact_binary_runtime_deps "${ARG_BINARY}"

  local version
  version="$(artifact_version "${SEAGULL_PACKAGE_DIR}")"

  layout_ensure_user
  layout_grant_log_read
  layout_create_directories

  install_env_file
  migrate_legacy_installation

  local profile
  profile="$(effective_profile)"
  configure_env_file "${profile}"
  install_ca_file
  install_enroll_token
  layout_secure_secrets

  local previous
  previous="$(state_read_release current)"
  state_store_release "${version}" "${ARG_BINARY}" >/dev/null
  state_activate_release "${version}"
  state_record_release "${version}" "${previous}"
  state_prune_releases "${version}" "${previous}"

  service_write_profile_dropin "${profile}" "$(resolve_capabilities "${profile}")"
  service_install_unit "${SEAGULL_PACKAGE_DIR}/share/systemd/seagull-agent.service"
  maybe_start

  log "installed seagull-agent ${version} (profile: ${profile})"
  log "configuration: ${ENV_PATH}"
  log "logs: journalctl -u ${SERVICE_NAME} -f"
}

main "$@"
