migrate_legacy_installation() {
  migrate_legacy_pki_layout
  migrate_legacy_token_layout
  migrate_legacy_profile
  migrate_drop_repo_ca_sync
}

migrate_legacy_pki_layout() {
  local legacy_cert="${PKI_DIR}/agent.crt"
  local legacy_key="${PKI_DIR}/agent.key"

  if [[ -f "${legacy_cert}" && -f "${legacy_key}" && ! -f "${CLIENT_CERT_PATH}" ]]; then
    install -d -m 0700 "${RUNTIME_PKI_DIR}"
    install -m 0644 "${legacy_cert}" "${CLIENT_CERT_PATH}"
    install -m 0600 "${legacy_key}" "${CLIENT_KEY_PATH}"
    own "${CLIENT_CERT_PATH}"
    own "${CLIENT_KEY_PATH}"
    rm -f "${legacy_cert}" "${legacy_key}"
    log "migrated client certificate to ${RUNTIME_PKI_DIR}"
  fi

  local cert_env key_env
  cert_env="$(env_value SEAGULL_TLS_CERT_FILE "${ENV_PATH}")"
  key_env="$(env_value SEAGULL_TLS_KEY_FILE "${ENV_PATH}")"
  if [[ "${cert_env}" == "/etc/seagull/pki/agent.crt" || "${key_env}" == "/etc/seagull/pki/agent.key" ]]; then
    set_env_value SEAGULL_TLS_CERT_FILE "${CLIENT_CERT_PATH#$(install_root)}" "${ENV_PATH}"
    set_env_value SEAGULL_TLS_KEY_FILE "${CLIENT_KEY_PATH#$(install_root)}" "${ENV_PATH}"
    log "rewrote legacy client certificate paths in ${ENV_PATH}"
  fi
}

migrate_legacy_token_layout() {
  local legacy_token="${CONFIG_DIR}/bootstrap.token"
  if [[ -f "${legacy_token}" && ! -s "${TOKEN_PATH}" ]]; then
    install -d -m 0755 "$(dirname -- "${TOKEN_PATH}")"
    install -m 0600 "${legacy_token}" "${TOKEN_PATH}"
    own "${TOKEN_PATH}"
    rm -f "${legacy_token}"
    log "migrated bootstrap token to ${TOKEN_PATH}"
  fi
}

migrate_legacy_profile() {
  if [[ ! -f "${ENV_PATH}" ]]; then
    return 0
  fi
  if env_key_exists SEAGULL_AGENT_PROFILE "${ENV_PATH}"; then
    return 0
  fi
  set_env_value SEAGULL_AGENT_PROFILE managed "${ENV_PATH}"
  log "recorded the managed profile for an installation that predates explicit profiles"
}

migrate_drop_repo_ca_sync() {
  local script="$(rooted /usr/local/lib/seagull/seagull-agent-sync-ca.sh)"
  local unit="$(rooted /etc/systemd/system/seagull-agent-ca-sync.service)"
  local timer="$(rooted /etc/systemd/system/seagull-agent-ca-sync.timer)"

  if [[ ! -f "${script}" && ! -f "${unit}" && ! -f "${timer}" ]]; then
    return 0
  fi
  if systemd_available; then
    systemctl stop seagull-agent-ca-sync.timer >/dev/null 2>&1 || true
    systemctl disable seagull-agent-ca-sync.timer >/dev/null 2>&1 || true
    systemctl stop seagull-agent-ca-sync.service >/dev/null 2>&1 || true
  fi
  rm -f "${script}" "${unit}" "${timer}"
  remove_env_key SEAGULL_TLS_CA_SOURCE_FILE "${ENV_PATH}"
  if systemd_available; then
    systemctl daemon-reload || true
  fi
  log "removed the platform CA sync timer; the agent now refreshes its trust anchor during enrollment and renewal"
}
