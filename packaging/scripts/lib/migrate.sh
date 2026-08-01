migrate_legacy_installation() {
  migrate_legacy_pki_layout
  migrate_legacy_ca_layout
  migrate_legacy_token_layout
  migrate_legacy_profile
  migrate_drop_repo_ca_sync
}

migrate_legacy_ca_layout() {
  local legacy_ca="${PKI_DIR}/root_ca.crt"
  local configured
  configured="$(env_value SEAGULL_TLS_CA_FILE "${ENV_PATH}")"
  if [[ -f "${legacy_ca}" ]]; then
    if [[ -f "${CA_PATH}" ]]; then
      cmp -s "${legacy_ca}" "${CA_PATH}" || die "legacy and migrated server trust anchors conflict"
    else
      install -m 0644 "${legacy_ca}" "${CA_PATH}"
    fi
    own "${CA_PATH}"
    rm -f "${legacy_ca}"
    log "migrated the server trust anchor to ${CA_PATH}"
  fi
  if [[ "${configured}" == "/etc/seagull/pki/root_ca.crt" ]]; then
    set_env_value SEAGULL_TLS_CA_FILE "$(unrooted "${CA_PATH}")" "${ENV_PATH}"
    log "rewrote the legacy server CA path in ${ENV_PATH}"
  fi
}

migrate_legacy_pki_layout() {
  local legacy_cert="${PKI_DIR}/agent.crt"
  local legacy_key="${PKI_DIR}/agent.key"
  local migrated=0

  if [[ -f "${legacy_cert}" || -f "${legacy_key}" ]]; then
    install -d -m 0700 "${RUNTIME_PKI_DIR}"
  fi
  if [[ -f "${legacy_cert}" ]]; then
    if [[ -f "${CLIENT_CERT_PATH}" ]]; then
      cmp -s "${legacy_cert}" "${CLIENT_CERT_PATH}" || die "legacy and migrated client certificates conflict"
    else
      install -m 0644 "${legacy_cert}" "${CLIENT_CERT_PATH}"
    fi
    own "${CLIENT_CERT_PATH}"
    migrated=1
  fi
  if [[ -f "${legacy_key}" ]]; then
    if [[ -f "${CLIENT_KEY_PATH}" ]]; then
      cmp -s "${legacy_key}" "${CLIENT_KEY_PATH}" || die "legacy and migrated client private keys conflict"
    else
      install -m 0600 "${legacy_key}" "${CLIENT_KEY_PATH}"
    fi
    own "${CLIENT_KEY_PATH}"
    migrated=1
  fi
  if [[ "${migrated}" == "1" ]]; then
    [[ -f "${CLIENT_CERT_PATH}" && -f "${CLIENT_KEY_PATH}" ]] || die "legacy client identity is incomplete"
    rm -f "${legacy_cert}" "${legacy_key}"
    log "migrated client certificate to ${RUNTIME_PKI_DIR}"
  fi

  local cert_env key_env
  cert_env="$(env_value SEAGULL_TLS_CERT_FILE "${ENV_PATH}")"
  key_env="$(env_value SEAGULL_TLS_KEY_FILE "${ENV_PATH}")"
  if [[ "${cert_env}" == "/etc/seagull/pki/agent.crt" || "${key_env}" == "/etc/seagull/pki/agent.key" ]]; then
    set_env_value SEAGULL_TLS_CERT_FILE "$(unrooted "${CLIENT_CERT_PATH}")" "${ENV_PATH}"
    set_env_value SEAGULL_TLS_KEY_FILE "$(unrooted "${CLIENT_KEY_PATH}")" "${ENV_PATH}"
    log "rewrote legacy client certificate paths in ${ENV_PATH}"
  fi
}

migrate_legacy_token_layout() {
  local legacy_token="${CONFIG_DIR}/bootstrap.token"
  if [[ -f "${legacy_token}" ]]; then
    if [[ -s "${TOKEN_PATH}" ]]; then
      cmp -s "${legacy_token}" "${TOKEN_PATH}" || die "legacy and migrated bootstrap tokens conflict"
    else
      install -d -m 0755 "$(dirname -- "${TOKEN_PATH}")"
      install -m 0600 "${legacy_token}" "${TOKEN_PATH}"
    fi
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
  local script
  local unit
  local timer
  script="$(rooted /usr/local/lib/seagull/seagull-agent-sync-ca.sh)"
  unit="$(rooted /etc/systemd/system/seagull-agent-ca-sync.service)"
  timer="$(rooted /etc/systemd/system/seagull-agent-ca-sync.timer)"

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
