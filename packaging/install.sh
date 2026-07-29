#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/env-util.sh"

SERVICE_NAME="seagull-agent"
SERVICE_FILE="${SCRIPT_DIR}/${SERVICE_NAME}.service"
ENV_EXAMPLE="${SCRIPT_DIR}/${SERVICE_NAME}.env.example"

INSTALL_BIN_PATH="/usr/local/bin/seagull-agent"
INSTALL_SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
INSTALL_DROPIN_DIR="/etc/systemd/system/${SERVICE_NAME}.service.d"
INSTALL_PROFILE_DROPIN="${INSTALL_DROPIN_DIR}/20-seagull-profile.conf"
INSTALL_ENV_PATH="/etc/seagull/agent.env"
INSTALL_CONFIG_DIR="/etc/seagull"
INSTALL_PKI_DIR="/etc/seagull/pki"
INSTALL_STATE_DIR="/var/lib/seagull"
INSTALL_RUNTIME_PKI_DIR="/var/lib/seagull/pki"
INSTALL_QUARANTINE_DIR="/var/lib/seagull/quarantine"
INSTALL_SPOOL_DIR="/var/lib/seagull/spool"
INSTALL_LOG_DIR="/var/log/seagull"

DEFAULT_CA_TARGET="/etc/seagull/pki/root_ca.crt"
DEFAULT_TOKEN_FILE="/var/lib/seagull/bootstrap.token"
DEFAULT_CLIENT_CERT_FILE="${INSTALL_RUNTIME_PKI_DIR}/client.crt"
DEFAULT_CLIENT_KEY_FILE="${INSTALL_RUNTIME_PKI_DIR}/client.key"

ARG_API_URL="${SEAGULL_API_URL:-}"
ARG_ENROLL_URL="${SEAGULL_ENROLL_URL:-}"
ARG_AGENT_ID="${SEAGULL_AGENT_ID:-}"
ARG_PROFILE="${SEAGULL_AGENT_PROFILE:-}"
ARG_TOKEN="${SEAGULL_AGENT_ENROLL_TOKEN:-${SEAGULL_AGENT_BOOTSTRAP_TOKEN:-}}"
ARG_TOKEN_FILE="${SEAGULL_AGENT_ENROLL_TOKEN_FILE:-}"
ARG_CA_FILE="${SEAGULL_AGENT_CA_FILE:-}"
ARG_TLS_SERVER_NAME="${SEAGULL_TLS_SERVER_NAME:-}"
ARG_BINARY="${SEAGULL_AGENT_BINARY:-}"
ARG_START="auto"

usage() {
  cat <<'USAGE'
Usage: install.sh [options]

Options:
  --api-url URL            Agent API base URL (mTLS listener), e.g. https://siem.example.com:8444/agent
  --enroll-url URL         Enrollment base URL (server-TLS listener), e.g. https://siem.example.com:8445
  --agent-id ID            Stable agent identifier
  --profile NAME           Security profile: sensor (default) or managed
  --enroll-token TOKEN     One-time enrollment token minted by the server
  --enroll-token-file PATH File containing the enrollment token
  --ca-file PATH           Server CA bundle to trust; omit to use the system trust store
  --tls-server-name NAME   Expected TLS server name when it differs from the URL host
  --binary PATH            Agent binary to install (default: seagull-agent next to this script)
  --start                  Start the service after install even without readiness checks
  --no-start               Install and enable only; never start
  -h, --help               Show this help
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
    --binary) ARG_BINARY="$2"; shift 2 ;;
    --start) ARG_START="always"; shift ;;
    --no-start) ARG_START="never"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[install] unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "[install] run as root" >&2
    exit 1
  fi
}

require_systemd() {
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "[install] systemd is required by this installer" >&2
    exit 1
  fi
}

resolve_binary() {
  if [[ -z "${ARG_BINARY}" ]]; then
    ARG_BINARY="${SCRIPT_DIR}/seagull-agent"
  fi
  if [[ ! -f "${ARG_BINARY}" ]]; then
    echo "[install] agent binary not found: ${ARG_BINARY}" >&2
    echo "[install] pass --binary /path/to/seagull-agent" >&2
    exit 1
  fi
}

check_binary_runtime_deps() {
  if ! command -v ldd >/dev/null 2>&1; then
    return
  fi
  local missing
  missing="$(ldd "${ARG_BINARY}" 2>/dev/null | awk '/not found/ {print $1}' | sort -u | tr '\n' ' ')"
  missing="$(trim "${missing}")"
  if [[ -z "${missing}" ]]; then
    return
  fi
  echo "[install] missing runtime libraries: ${missing}" >&2
  if [[ "${missing}" == *libpcap* ]]; then
    echo "[install] install libpcap first (apt install libpcap0.8, dnf install libpcap, apk add libpcap)" >&2
  fi
  exit 1
}

validate_profile() {
  case "${ARG_PROFILE}" in
    ""|sensor|managed) ;;
    *)
      echo "[install] invalid --profile '${ARG_PROFILE}' (expected sensor or managed)" >&2
      exit 2
      ;;
  esac
}

ensure_service_user() {
  if ! id -u seagull >/dev/null 2>&1; then
    useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin seagull
    echo "[install] created user: seagull"
  fi
  if getent group adm >/dev/null 2>&1; then
    usermod -a -G adm seagull || true
  fi
}

create_directories() {
  install -d -m 0755 "${INSTALL_CONFIG_DIR}"
  install -d -m 0755 "${INSTALL_PKI_DIR}"
  install -d -m 0755 "${INSTALL_STATE_DIR}"
  install -d -m 0700 "${INSTALL_RUNTIME_PKI_DIR}"
  install -d -m 0700 "${INSTALL_QUARANTINE_DIR}"
  install -d -m 0700 "${INSTALL_SPOOL_DIR}"
  install -d -m 0755 "${INSTALL_LOG_DIR}"

  chown seagull:seagull "${INSTALL_STATE_DIR}"
  chown seagull:seagull "${INSTALL_RUNTIME_PKI_DIR}"
  chown seagull:seagull "${INSTALL_QUARANTINE_DIR}"
  chown seagull:seagull "${INSTALL_SPOOL_DIR}"
  chown seagull:seagull "${INSTALL_LOG_DIR}"
}

install_binary() {
  local was_active="0"
  if systemctl is-active --quiet "${SERVICE_NAME}"; then
    was_active="1"
  fi
  install -m 0755 "${ARG_BINARY}" "${INSTALL_BIN_PATH}"
  if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_raw,cap_net_admin=eip "${INSTALL_BIN_PATH}" || true
  fi
  BINARY_REPLACED_WHILE_ACTIVE="${was_active}"
}

effective_profile() {
  local from_env=""
  if [[ -f "${INSTALL_ENV_PATH}" ]]; then
    from_env="$(trim "$(read_env_value SEAGULL_AGENT_PROFILE "${INSTALL_ENV_PATH}")")"
  fi
  if [[ -n "${ARG_PROFILE}" ]]; then
    printf '%s' "${ARG_PROFILE}"
    return
  fi
  if [[ -n "${from_env}" ]]; then
    printf '%s' "${from_env}"
    return
  fi
  if [[ -f "${INSTALL_ENV_PATH}" ]]; then
    printf 'managed'
    return
  fi
  printf 'sensor'
}

install_env_file() {
  if [[ ! -f "${INSTALL_ENV_PATH}" ]]; then
    install -m 0600 "${ENV_EXAMPLE}" "${INSTALL_ENV_PATH}"
    echo "[install] created ${INSTALL_ENV_PATH}"
  else
    echo "[install] keeping existing ${INSTALL_ENV_PATH}"
  fi
  chmod 0600 "${INSTALL_ENV_PATH}"
}

configure_env_file() {
  local profile="$1"

  if [[ -n "${ARG_AGENT_ID}" ]]; then
    set_env_value SEAGULL_AGENT_ID "${ARG_AGENT_ID}" "${INSTALL_ENV_PATH}"
  fi
  if [[ -n "${ARG_API_URL}" ]]; then
    set_env_value SEAGULL_API_URL "${ARG_API_URL}" "${INSTALL_ENV_PATH}"
  fi
  if [[ -n "${ARG_ENROLL_URL}" ]]; then
    set_env_value SEAGULL_ENROLL_URL "${ARG_ENROLL_URL}" "${INSTALL_ENV_PATH}"
  fi
  if [[ -n "${ARG_TLS_SERVER_NAME}" ]]; then
    set_env_value SEAGULL_TLS_SERVER_NAME "${ARG_TLS_SERVER_NAME}" "${INSTALL_ENV_PATH}"
  fi
  set_env_value SEAGULL_AGENT_PROFILE "${profile}" "${INSTALL_ENV_PATH}"

  ensure_env_value SEAGULL_AGENT_IDENTITY_STATE_FILE "${INSTALL_STATE_DIR}/agent.identity.json" "${INSTALL_ENV_PATH}"
  ensure_env_value SEAGULL_AGENT_CREDENTIAL_FILE "${INSTALL_STATE_DIR}/agent.credential" "${INSTALL_ENV_PATH}"
  ensure_env_value SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE "${DEFAULT_TOKEN_FILE}" "${INSTALL_ENV_PATH}"
  ensure_env_value SEAGULL_TLS_CERT_FILE "${DEFAULT_CLIENT_CERT_FILE}" "${INSTALL_ENV_PATH}"
  ensure_env_value SEAGULL_TLS_KEY_FILE "${DEFAULT_CLIENT_KEY_FILE}" "${INSTALL_ENV_PATH}"
  ensure_env_value SEAGULL_AGENT_SPOOL_DIR "${INSTALL_SPOOL_DIR}" "${INSTALL_ENV_PATH}"

  local api_url agent_id
  api_url="$(trim "$(read_env_value SEAGULL_API_URL "${INSTALL_ENV_PATH}")")"
  agent_id="$(trim "$(read_env_value SEAGULL_AGENT_ID "${INSTALL_ENV_PATH}")")"
  if [[ -z "${api_url}" ]]; then
    echo "[install] warning: SEAGULL_API_URL is not set; pass --api-url or edit ${INSTALL_ENV_PATH}"
  fi
  if [[ -z "${agent_id}" ]]; then
    echo "[install] warning: SEAGULL_AGENT_ID is not set; pass --agent-id or edit ${INSTALL_ENV_PATH}"
  fi
}

migrate_legacy_layout() {
  local legacy_token="/etc/seagull/bootstrap.token"
  local legacy_cert="/etc/seagull/pki/agent.crt"
  local legacy_key="/etc/seagull/pki/agent.key"

  if [[ -f "${legacy_token}" && ! -s "${DEFAULT_TOKEN_FILE}" ]]; then
    install -o seagull -g seagull -m 0600 "${legacy_token}" "${DEFAULT_TOKEN_FILE}"
    rm -f "${legacy_token}"
    echo "[install] migrated legacy bootstrap token to ${DEFAULT_TOKEN_FILE}"
  fi

  if [[ -f "${legacy_cert}" && -f "${legacy_key}" && ! -f "${DEFAULT_CLIENT_CERT_FILE}" ]]; then
    install -o seagull -g seagull -m 0644 "${legacy_cert}" "${DEFAULT_CLIENT_CERT_FILE}"
    install -o seagull -g seagull -m 0600 "${legacy_key}" "${DEFAULT_CLIENT_KEY_FILE}"
    rm -f "${legacy_cert}" "${legacy_key}"
    echo "[install] migrated legacy client certificate to ${INSTALL_RUNTIME_PKI_DIR}"
  fi

  local cert_env key_env
  cert_env="$(trim "$(read_env_value SEAGULL_TLS_CERT_FILE "${INSTALL_ENV_PATH}")")"
  key_env="$(trim "$(read_env_value SEAGULL_TLS_KEY_FILE "${INSTALL_ENV_PATH}")")"
  if [[ "${cert_env}" == "${legacy_cert}" || "${key_env}" == "${legacy_key}" ]]; then
    set_env_value SEAGULL_TLS_CERT_FILE "${DEFAULT_CLIENT_CERT_FILE}" "${INSTALL_ENV_PATH}"
    set_env_value SEAGULL_TLS_KEY_FILE "${DEFAULT_CLIENT_KEY_FILE}" "${INSTALL_ENV_PATH}"
    echo "[install] rewrote legacy client certificate paths in ${INSTALL_ENV_PATH}"
  fi
}

install_ca_file() {
  if [[ -z "${ARG_CA_FILE}" ]]; then
    return
  fi
  if [[ ! -f "${ARG_CA_FILE}" ]]; then
    echo "[install] CA file not found: ${ARG_CA_FILE}" >&2
    exit 1
  fi
  install -m 0644 "${ARG_CA_FILE}" "${DEFAULT_CA_TARGET}"
  chown root:root "${DEFAULT_CA_TARGET}" || true
  set_env_value SEAGULL_TLS_CA_FILE "${DEFAULT_CA_TARGET}" "${INSTALL_ENV_PATH}"
  echo "[install] installed server CA to ${DEFAULT_CA_TARGET}"
}

install_enroll_token() {
  local token="${ARG_TOKEN}"
  if [[ -z "${token}" && -n "${ARG_TOKEN_FILE}" ]]; then
    if [[ ! -f "${ARG_TOKEN_FILE}" ]]; then
      echo "[install] enroll token file not found: ${ARG_TOKEN_FILE}" >&2
      exit 1
    fi
    token="$(trim "$(tr -d '\r\n' < "${ARG_TOKEN_FILE}")")"
  fi
  if [[ -z "${token}" ]]; then
    return
  fi
  local token_file
  token_file="$(trim "$(read_env_value SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE "${INSTALL_ENV_PATH}")")"
  if [[ -z "${token_file}" ]]; then
    token_file="${DEFAULT_TOKEN_FILE}"
    set_env_value SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE "${token_file}" "${INSTALL_ENV_PATH}"
  fi
  install -d -m 0755 "$(dirname -- "${token_file}")"
  printf '%s' "${token}" > "${token_file}"
  chown seagull:seagull "${token_file}" || true
  chmod 0600 "${token_file}" || true
  set_env_value SEAGULL_AGENT_BOOTSTRAP_TOKEN "" "${INSTALL_ENV_PATH}"
  echo "[install] wrote enrollment token to ${token_file}"
}

write_profile_dropin() {
  local profile="$1"
  install -d -m 0755 "${INSTALL_DROPIN_DIR}"
  if [[ "${profile}" == "managed" ]]; then
    cat > "${INSTALL_PROFILE_DROPIN}" <<'DROPIN'
[Service]
AmbientCapabilities=
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_KILL
CapabilityBoundingSet=
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_KILL
DROPIN
  else
    cat > "${INSTALL_PROFILE_DROPIN}" <<'DROPIN'
[Service]
AmbientCapabilities=
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
DROPIN
  fi
  chmod 0644 "${INSTALL_PROFILE_DROPIN}"
  echo "[install] applied ${profile} profile capability set"
}

install_service_file() {
  install -m 0644 "${SERVICE_FILE}" "${INSTALL_SERVICE_PATH}"
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}"
  systemctl reset-failed "${SERVICE_NAME}" || true
}

runtime_ready() {
  local token_file credential_file identity_state_file
  token_file="$(trim "$(read_env_value SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE "${INSTALL_ENV_PATH}")")"
  credential_file="$(trim "$(read_env_value SEAGULL_AGENT_CREDENTIAL_FILE "${INSTALL_ENV_PATH}")")"
  identity_state_file="$(trim "$(read_env_value SEAGULL_AGENT_IDENTITY_STATE_FILE "${INSTALL_ENV_PATH}")")"

  if [[ -n "${credential_file}" && -s "${credential_file}" ]]; then
    return 0
  fi
  if [[ -n "${identity_state_file}" && -s "${identity_state_file}" ]]; then
    return 0
  fi
  if [[ -n "${token_file}" && -s "${token_file}" ]]; then
    return 0
  fi
  if [[ -n "$(trim "$(read_env_value SEAGULL_AGENT_BOOTSTRAP_TOKEN "${INSTALL_ENV_PATH}")")" ]]; then
    return 0
  fi
  return 1
}

maybe_start() {
  case "${ARG_START}" in
    never)
      echo "[install] start skipped (--no-start)"
      return
      ;;
    always) ;;
    auto)
      if ! runtime_ready; then
        echo "[install] start skipped: no enrollment token or existing identity yet"
        echo "[install] provide --enroll-token and re-run, or start manually: systemctl start ${SERVICE_NAME}"
        return
      fi
      ;;
  esac
  if systemctl restart "${SERVICE_NAME}"; then
    echo "[install] service started"
  else
    echo "[install] warning: service failed to start" >&2
    echo "[install] inspect with: systemctl status ${SERVICE_NAME} --no-pager" >&2
  fi
}

main() {
  require_root
  require_systemd
  resolve_binary
  check_binary_runtime_deps
  validate_profile

  if [[ ! -f "${SERVICE_FILE}" || ! -f "${ENV_EXAMPLE}" ]]; then
    echo "[install] packaging assets missing next to install.sh" >&2
    exit 1
  fi

  ensure_service_user
  create_directories
  install_binary
  install_env_file

  local profile
  profile="$(effective_profile)"
  configure_env_file "${profile}"
  migrate_legacy_layout
  install_ca_file
  install_enroll_token
  write_profile_dropin "${profile}"
  install_service_file
  maybe_start

  echo
  echo "[install] done (profile: ${profile})"
  echo "[install] review ${INSTALL_ENV_PATH}"
  echo "[install] logs: journalctl -u ${SERVICE_NAME} -f"
}

main "$@"
