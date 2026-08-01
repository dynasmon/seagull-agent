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

ARG_API_URL="${SEAGULL_API_URL:-}"
ARG_ENROLL_URL="${SEAGULL_ENROLL_URL:-}"
ARG_AGENT_ID="${SEAGULL_AGENT_ID:-}"
ARG_PROFILE="${SEAGULL_AGENT_PROFILE:-}"
ARG_TOKEN="${SEAGULL_AGENT_ENROLL_TOKEN:-}"
ARG_TOKEN_FILE="${SEAGULL_AGENT_ENROLL_TOKEN_FILE:-}"
ARG_PROMPT_TOKEN=0
ARG_CA_FILE="${SEAGULL_AGENT_CA_FILE:-}"
ARG_TLS_SERVER_NAME="${SEAGULL_TLS_SERVER_NAME:-}"
ARG_SOURCES="${SEAGULL_SOURCES:-}"
ARG_START="auto"
RESOLVED_TOKEN=""
EFFECTIVE_AGENT_ID=""
EFFECTIVE_API_URL=""
EFFECTIVE_ENROLL_URL=""
EFFECTIVE_PROFILE=""
EFFECTIVE_SOURCES=""
START_REQUIRES_ENROLLMENT=0

usage() {
  cat <<'USAGE'
Usage: install.sh [options]

  --api-url URL             Agent API base URL, e.g. https://siem.example.com:8444/agent
  --enroll-url URL          Enrollment base URL, e.g. https://siem.example.com:8445
  --agent-id ID             Stable agent identifier
  --profile NAME            Security profile: sensor or managed
  --enroll-token TOKEN      One-time enrollment token minted by the server
  --enroll-token-file PATH  File containing the enrollment token
  --prompt-enroll-token     Read the enrollment token interactively without echo
  --ca-file PATH            Server CA bundle; omit to use the system trust store
  --tls-server-name NAME    Expected TLS name when it differs from the URL host
  --sources LIST            Comma-separated collectors to enable
  --start                   Require the service to start after installation
  --no-start                Install and enable without starting the service
  -h, --help                Show this help

The installer is idempotent and preserves existing identity, credentials,
telemetry backlog and local configuration.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-url)
      require_option_value "$1" "${2-}"
      ARG_API_URL="$2"
      shift 2
      ;;
    --enroll-url)
      require_option_value "$1" "${2-}"
      ARG_ENROLL_URL="$2"
      shift 2
      ;;
    --agent-id)
      require_option_value "$1" "${2-}"
      ARG_AGENT_ID="$2"
      shift 2
      ;;
    --profile)
      require_option_value "$1" "${2-}"
      ARG_PROFILE="$2"
      shift 2
      ;;
    --enroll-token)
      require_option_value "$1" "${2-}"
      ARG_TOKEN="$2"
      shift 2
      ;;
    --enroll-token-file)
      require_option_value "$1" "${2-}"
      ARG_TOKEN_FILE="$2"
      shift 2
      ;;
    --prompt-enroll-token)
      ARG_PROMPT_TOKEN=1
      shift
      ;;
    --ca-file)
      require_option_value "$1" "${2-}"
      ARG_CA_FILE="$2"
      shift 2
      ;;
    --tls-server-name)
      require_option_value "$1" "${2-}"
      ARG_TLS_SERVER_NAME="$2"
      shift 2
      ;;
    --sources)
      require_option_value "$1" "${2-}"
      ARG_SOURCES="$2"
      shift 2
      ;;
    --start)
      ARG_START="always"
      shift
      ;;
    --no-start)
      ARG_START="never"
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

install_env_file() {
  if [[ ! -f "${ENV_PATH}" ]]; then
    install -m 0600 "${SEAGULL_PACKAGE_DIR}/share/env/seagull-agent.env.example" "${ENV_PATH}"
    log "created ${ENV_PATH}"
  else
    log "keeping existing ${ENV_PATH}"
  fi
  chmod 0600 "${ENV_PATH}"
}

resolve_token() {
  local methods=0
  [[ -n "${ARG_TOKEN}" ]] && methods=$((methods + 1))
  [[ -n "${ARG_TOKEN_FILE}" ]] && methods=$((methods + 1))
  [[ "${ARG_PROMPT_TOKEN}" == "1" ]] && methods=$((methods + 1))
  if (( methods > 1 )); then
    die "use one enrollment token input method"
  fi
  if [[ "${ARG_PROMPT_TOKEN}" == "1" ]]; then
    [[ -t 0 ]] || die "interactive enrollment token input requires a terminal"
    if ! IFS= read -r -s -p "Enrollment token: " RESOLVED_TOKEN; then
      printf '\n' >&2
      die "unable to read enrollment token"
    fi
    printf '\n' >&2
    RESOLVED_TOKEN="$(trim "${RESOLVED_TOKEN}")"
  elif [[ -n "${ARG_TOKEN_FILE}" ]]; then
    RESOLVED_TOKEN="$(read_single_line_secret "enrollment token" "${ARG_TOKEN_FILE}")"
  else
    RESOLVED_TOKEN="$(trim "${ARG_TOKEN}")"
  fi
  if [[ -z "${RESOLVED_TOKEN}" ]] && ! state_identity_present && [[ -s "${TOKEN_PATH}" ]]; then
    RESOLVED_TOKEN="$(read_single_line_secret "enrollment token" "${TOKEN_PATH}")"
  fi
}

resolve_configuration() {
  local existing_id token_id=""
  existing_id="$(env_value SEAGULL_AGENT_ID "${ENV_PATH}")"
  if [[ -n "${RESOLVED_TOKEN}" ]]; then
    token_id="$(bootstrap_token_agent_id "${RESOLVED_TOKEN}")"
  fi
  EFFECTIVE_AGENT_ID="$(trim "${ARG_AGENT_ID}")"
  if [[ -z "${EFFECTIVE_AGENT_ID}" ]]; then
    EFFECTIVE_AGENT_ID="${existing_id:-${token_id}}"
  fi
  [[ -n "${EFFECTIVE_AGENT_ID}" ]] || die "agent id is required"
  validate_agent_id "${EFFECTIVE_AGENT_ID}"
  if state_identity_present && [[ -n "${existing_id}" && "${existing_id}" != "${EFFECTIVE_AGENT_ID}" ]]; then
    die "agent id cannot change after enrollment"
  fi
  if [[ -n "${token_id}" && "${token_id}" != "${EFFECTIVE_AGENT_ID}" ]]; then
    die "enrollment token belongs to agent '${token_id}', not '${EFFECTIVE_AGENT_ID}'"
  fi

  EFFECTIVE_API_URL="$(trim "${ARG_API_URL}")"
  if [[ -z "${EFFECTIVE_API_URL}" ]]; then
    EFFECTIVE_API_URL="$(env_value SEAGULL_API_URL "${ENV_PATH}")"
  fi
  [[ -n "${EFFECTIVE_API_URL}" ]] || die "agent API URL is required"
  validate_https_url "agent API URL" "${EFFECTIVE_API_URL}"

  EFFECTIVE_ENROLL_URL="$(trim "${ARG_ENROLL_URL}")"
  if [[ -z "${EFFECTIVE_ENROLL_URL}" ]]; then
    EFFECTIVE_ENROLL_URL="$(env_value SEAGULL_ENROLL_URL "${ENV_PATH}")"
  fi
  if [[ -n "${EFFECTIVE_ENROLL_URL}" ]]; then
    validate_https_url "enrollment URL" "${EFFECTIVE_ENROLL_URL}"
  elif [[ -n "${RESOLVED_TOKEN}" ]] && ! state_identity_present; then
    die "enrollment URL is required for a fresh enrollment"
  fi

  EFFECTIVE_PROFILE="$(trim "${ARG_PROFILE}")"
  if [[ -z "${EFFECTIVE_PROFILE}" ]]; then
    EFFECTIVE_PROFILE="$(env_value SEAGULL_AGENT_PROFILE "${ENV_PATH}")"
  fi
  EFFECTIVE_PROFILE="${EFFECTIVE_PROFILE:-sensor}"
  validate_profile "${EFFECTIVE_PROFILE}"

  EFFECTIVE_SOURCES="$(trim "${ARG_SOURCES}")"
  if [[ -z "${EFFECTIVE_SOURCES}" ]]; then
    EFFECTIVE_SOURCES="$(env_value SEAGULL_SOURCES "${ENV_PATH}")"
  fi
  EFFECTIVE_SOURCES="${EFFECTIVE_SOURCES:-authlog,proc,proc_exec,fim,scan,ddos,l7}"
  EFFECTIVE_SOURCES="$(validate_sources "${EFFECTIVE_SOURCES}")"

  ARG_TLS_SERVER_NAME="$(trim "${ARG_TLS_SERVER_NAME}")"
  if [[ -z "${ARG_TLS_SERVER_NAME}" ]]; then
    ARG_TLS_SERVER_NAME="$(env_value SEAGULL_TLS_SERVER_NAME "${ENV_PATH}")"
  fi
  validate_tls_server_name "${ARG_TLS_SERVER_NAME}"
}

configure_env_file() {
  set_env_value SEAGULL_AGENT_ID "${EFFECTIVE_AGENT_ID}" "${ENV_PATH}"
  set_env_value SEAGULL_API_URL "${EFFECTIVE_API_URL}" "${ENV_PATH}"
  if [[ -n "${EFFECTIVE_ENROLL_URL}" ]]; then
    set_env_value SEAGULL_ENROLL_URL "${EFFECTIVE_ENROLL_URL}" "${ENV_PATH}"
  fi
  set_env_value SEAGULL_AGENT_PROFILE "${EFFECTIVE_PROFILE}" "${ENV_PATH}"
  set_env_value SEAGULL_SOURCES "${EFFECTIVE_SOURCES}" "${ENV_PATH}"
  if [[ -n "${ARG_TLS_SERVER_NAME}" ]]; then
    set_env_value SEAGULL_TLS_SERVER_NAME "${ARG_TLS_SERVER_NAME}" "${ENV_PATH}"
  fi
  ensure_env_value SEAGULL_AGENT_CONFIG_FILE "$(unrooted "${STATE_DIR}")/agent.config.json" "${ENV_PATH}"
  ensure_env_value SEAGULL_AGENT_IDENTITY_STATE_FILE "$(unrooted "${IDENTITY_PATH}")" "${ENV_PATH}"
  ensure_env_value SEAGULL_AGENT_CREDENTIAL_FILE "$(unrooted "${CREDENTIAL_PATH}")" "${ENV_PATH}"
  ensure_env_value SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE "$(unrooted "${TOKEN_PATH}")" "${ENV_PATH}"
  ensure_env_value SEAGULL_TLS_CERT_FILE "$(unrooted "${CLIENT_CERT_PATH}")" "${ENV_PATH}"
  ensure_env_value SEAGULL_TLS_KEY_FILE "$(unrooted "${CLIENT_KEY_PATH}")" "${ENV_PATH}"
  ensure_env_value SEAGULL_AGENT_SPOOL_DIR "$(unrooted "${SPOOL_DIR}")" "${ENV_PATH}"
  ensure_env_value SEAGULL_AUTHLOG_CHECKPOINT_FILE "$(unrooted "${CHECKPOINT_DIR}")/authlog.json" "${ENV_PATH}"
  ensure_env_value SEAGULL_RESPONSE_ACTION_JOURNAL_DIR "$(unrooted "${RESPONSE_ACTION_DIR}")" "${ENV_PATH}"
}

install_ca_file() {
  [[ -n "${ARG_CA_FILE}" ]] || return 0
  [[ -s "${ARG_CA_FILE}" ]] || die "CA file not found or empty: ${ARG_CA_FILE}"
  if ! "${SEAGULL_PACKAGE_DIR}/seagull-agent" validate-ca "${ARG_CA_FILE}" >/dev/null; then
    die "CA file is not a valid certificate authority bundle"
  fi
  atomic_replace_from_stdin "${CA_PATH}" 0644 < "${ARG_CA_FILE}"
  own "${CA_PATH}"
  set_env_value SEAGULL_TLS_CA_FILE "$(unrooted "${CA_PATH}")" "${ENV_PATH}"
  log "installed server CA to ${CA_PATH}"
}

install_enroll_token() {
  [[ -n "${RESOLVED_TOKEN}" ]] || return 0
  printf '%s\n' "${RESOLVED_TOKEN}" | atomic_replace_from_stdin "${TOKEN_PATH}" 0600
  own "${TOKEN_PATH}"
  remove_env_key SEAGULL_AGENT_BOOTSTRAP_TOKEN "${ENV_PATH}"
  log "stored the enrollment token in ${TOKEN_PATH}"
}

maybe_start() {
  case "${ARG_START}" in
    never)
      log "start skipped (--no-start)"
      return 0
      ;;
    auto)
      if ! state_runtime_ready; then
        log "start skipped because no enrollment token or existing identity is available"
        return 0
      fi
      ;;
    always)
      state_runtime_ready || die "cannot start without an enrollment token or existing identity"
      ;;
  esac
  systemd_available || return 0
  service_restart
  if service_wait_healthy 60 "${START_REQUIRES_ENROLLMENT}"; then
    log "service started"
    return 0
  fi
  service_report_failure
  die "the agent failed its post-install health check"
}

main() {
  require_root
  require_systemd
  layout_init
  acquire_install_lock
  artifact_verify_package "${SEAGULL_PACKAGE_DIR}"

  local version
  version="$(artifact_version "${SEAGULL_PACKAGE_DIR}")"

  layout_ensure_user
  layout_create_directories
  install_env_file
  migrate_legacy_installation
  resolve_token

  if ! state_identity_present && [[ -n "${RESOLVED_TOKEN}" ]]; then
    START_REQUIRES_ENROLLMENT=1
  fi

  resolve_configuration
  layout_configure_log_read "${EFFECTIVE_SOURCES}"
  configure_env_file
  install_ca_file
  install_enroll_token
  layout_secure_secrets

  local current previous
  current="$(state_read_release current)"
  previous="$(state_read_release previous)"
  if [[ -n "${current}" && "${current}" != "${version}" ]]; then
    die "release ${current} is installed; use upgrade.sh to install ${version}"
  fi

  state_store_release \
    "${version}" \
    "${SEAGULL_PACKAGE_DIR}/seagull-agent" \
    "${SEAGULL_PACKAGE_DIR}/share/systemd/seagull-agent.service" \
    "${SEAGULL_PACKAGE_DIR}/VERSION" >/dev/null
  service_stop
  state_activate_release "${version}"
  service_write_profile_dropin "${EFFECTIVE_PROFILE}" "$(service_derive_capabilities "${EFFECTIVE_PROFILE}" "${EFFECTIVE_SOURCES}" "$(env_value SEAGULL_LATERAL_MODE "${ENV_PATH}")")"
  service_install_unit
  state_record_release "${version}" "${previous}"
  state_prune_releases "${version}" "${previous}"
  maybe_start

  log "installed seagull-agent ${version} (profile: ${EFFECTIVE_PROFILE})"
  log "configuration: ${ENV_PATH}"
  log "logs: journalctl -u ${SERVICE_NAME} -f"
}

main "$@"
