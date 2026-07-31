SEAGULL_USER="${SEAGULL_USER:-seagull}"
SEAGULL_GROUP="${SEAGULL_GROUP:-seagull}"

layout_init() {
  BIN_PATH="$(rooted /usr/local/bin/seagull-agent)"
  RELEASE_DIR="$(rooted /usr/local/lib/seagull/releases)"
  CONFIG_DIR="$(rooted /etc/seagull)"
  ENV_PATH="${CONFIG_DIR}/agent.env"
  PKI_DIR="${CONFIG_DIR}/pki"
  STATE_DIR="$(rooted /var/lib/seagull)"
  RUNTIME_PKI_DIR="${STATE_DIR}/pki"
  CA_PATH="${RUNTIME_PKI_DIR}/server-ca.crt"
  CLIENT_CERT_PATH="${RUNTIME_PKI_DIR}/client.crt"
  CLIENT_KEY_PATH="${RUNTIME_PKI_DIR}/client.key"
  QUARANTINE_DIR="${STATE_DIR}/quarantine"
  SPOOL_DIR="${STATE_DIR}/spool"
  CHECKPOINT_DIR="${STATE_DIR}/checkpoints"
  RESPONSE_ACTION_DIR="${STATE_DIR}/response-actions"
  TOKEN_PATH="${STATE_DIR}/bootstrap.token"
  IDENTITY_PATH="${STATE_DIR}/agent.identity.json"
  CREDENTIAL_PATH="${STATE_DIR}/agent.credential"
  RELEASE_STATE_PATH="${STATE_DIR}/agent.release"
  LOG_DIR="$(rooted /var/log/seagull)"
  UNIT_PATH="$(rooted /etc/systemd/system/seagull-agent.service)"
  DROPIN_DIR="$(rooted /etc/systemd/system/seagull-agent.service.d)"
  PROFILE_DROPIN="${DROPIN_DIR}/20-seagull-profile.conf"
  LOCK_PATH="$(rooted /run/lock/seagull-agent.lock)"
}

layout_ensure_user() {
  if is_staged_root; then
    return 0
  fi
  if ! getent group "${SEAGULL_GROUP}" >/dev/null 2>&1; then
    groupadd --system "${SEAGULL_GROUP}"
    log "created service group ${SEAGULL_GROUP}"
  fi
  if ! id -u "${SEAGULL_USER}" >/dev/null 2>&1; then
    useradd --system --gid "${SEAGULL_GROUP}" --home-dir /nonexistent --shell /usr/sbin/nologin "${SEAGULL_USER}"
    log "created service user ${SEAGULL_USER}"
  fi
}

layout_configure_log_read() {
  local sources="$1"
  if is_staged_root; then
    return 0
  fi
  if ! getent group adm >/dev/null 2>&1; then
    return 0
  fi
  if [[ ",${sources}," == *,authlog,* ]]; then
    usermod -a -G adm "${SEAGULL_USER}"
    return 0
  fi
  if id -nG "${SEAGULL_USER}" | tr ' ' '\n' | grep -Fxq adm; then
    gpasswd -d "${SEAGULL_USER}" adm >/dev/null
  fi
}

own() {
  if is_staged_root; then
    return 0
  fi
  chown "${SEAGULL_USER}:${SEAGULL_GROUP}" "$1"
}

layout_create_directories() {
  install -d -m 0755 "${CONFIG_DIR}"
  install -d -m 0755 "${PKI_DIR}"
  install -d -m 0755 "${STATE_DIR}"
  install -d -m 0700 "${RUNTIME_PKI_DIR}"
  install -d -m 0700 "${QUARANTINE_DIR}"
  install -d -m 0700 "${SPOOL_DIR}"
  install -d -m 0700 "${CHECKPOINT_DIR}"
  install -d -m 0700 "${RESPONSE_ACTION_DIR}"
  install -d -m 0755 "${LOG_DIR}"
  install -d -m 0755 "${RELEASE_DIR}"

  own "${STATE_DIR}"
  own "${RUNTIME_PKI_DIR}"
  own "${QUARANTINE_DIR}"
  own "${SPOOL_DIR}"
  own "${CHECKPOINT_DIR}"
  own "${RESPONSE_ACTION_DIR}"
  own "${LOG_DIR}"
}

layout_secure_secrets() {
  local path
  for path in "${ENV_PATH}" "${TOKEN_PATH}" "${CREDENTIAL_PATH}" "${IDENTITY_PATH}" "${CLIENT_KEY_PATH}"; do
    if [[ -f "${path}" ]]; then
      chmod 0600 "${path}"
    fi
  done
  if [[ -f "${ENV_PATH}" ]]; then
    if ! is_staged_root; then
      chown root:root "${ENV_PATH}"
    fi
  fi
  for path in "${TOKEN_PATH}" "${CREDENTIAL_PATH}" "${IDENTITY_PATH}" "${CLIENT_KEY_PATH}"; do
    if [[ -f "${path}" ]]; then
      own "${path}"
    fi
  done
  if [[ -f "${CLIENT_CERT_PATH}" ]]; then
    chmod 0644 "${CLIENT_CERT_PATH}"
    own "${CLIENT_CERT_PATH}"
  fi
  if [[ -f "${CA_PATH}" ]]; then
    chmod 0644 "${CA_PATH}"
    own "${CA_PATH}"
  fi
}
