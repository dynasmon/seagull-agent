SERVICE_NAME="seagull-agent"

PCAP_SOURCES="scan ddos l7 lateral"

service_pcap_required() {
  local sources="$1"
  local mode="$2"
  local name
  if [[ -z "${sources}" ]]; then
    sources="authlog,proc,proc_exec,fim,scan,ddos,l7"
  fi
  for name in ${PCAP_SOURCES}; do
    if [[ ",${sources}," == *",${name},"* ]]; then
      if [[ "${name}" == "lateral" && "${mode}" == "proc" ]]; then
        continue
      fi
      return 0
    fi
  done
  return 1
}

service_derive_capabilities() {
  local profile="$1"
  local sources="$2"
  local lateral_mode="$3"
  local caps=()

  if service_pcap_required "${sources}" "${lateral_mode}"; then
    caps+=(CAP_NET_RAW)
  fi
  if [[ "${profile}" == "managed" ]]; then
    caps+=(CAP_NET_ADMIN CAP_KILL CAP_DAC_OVERRIDE CAP_FOWNER)
  fi
  if [[ "${#caps[@]}" -eq 0 ]]; then
    return 0
  fi
  printf '%s\n' "${caps[@]}" | sort -u | tr '\n' ' ' | sed 's/ $//'
}

service_write_profile_dropin() {
  local profile="$1"
  local capabilities="$2"

  install -d -m 0755 "${DROPIN_DIR}"
  {
    printf '[Service]\n'
    printf 'Environment=SEAGULL_AGENT_PROFILE=%s\n' "${profile}"
    printf 'AmbientCapabilities=\n'
    printf 'CapabilityBoundingSet=\n'
    if [[ "${profile}" == "managed" ]]; then
      printf 'PrivateTmp=false\n'
      printf 'ProtectHome=false\n'
      printf 'ProtectSystem=full\n'
    else
      printf 'PrivateTmp=true\n'
      printf 'ProtectHome=true\n'
      printf 'ProtectSystem=strict\n'
    fi
    if [[ -n "${capabilities}" ]]; then
      printf 'AmbientCapabilities=%s\n' "${capabilities}"
      printf 'CapabilityBoundingSet=%s\n' "${capabilities}"
    fi
  } > "${PROFILE_DROPIN}"
  chmod 0644 "${PROFILE_DROPIN}"
  if [[ -n "${capabilities}" ]]; then
    log "profile ${profile} granted capabilities: ${capabilities}"
  else
    log "profile ${profile} granted no additional capabilities"
  fi
}

service_install_unit() {
  [[ -f "${UNIT_PATH}" ]] || die "systemd unit is not installed at ${UNIT_PATH}"
  if ! systemd_available; then
    return 0
  fi
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}" >/dev/null
  systemctl reset-failed "${SERVICE_NAME}" >/dev/null 2>&1 || true
}

service_is_active() {
  systemd_available && systemctl is-active --quiet "${SERVICE_NAME}"
}

service_stop() {
  systemd_available || return 0
  systemctl stop "${SERVICE_NAME}" >/dev/null 2>&1 || true
}

service_restart() {
  systemd_available || return 0
  systemctl restart "${SERVICE_NAME}"
}

service_wait_healthy() {
  local timeout="${1:-20}"
  local require_identity="${2:-0}"
  systemd_available || return 0
  local waited=0
  local stable=0
  while [[ "${waited}" -lt "${timeout}" ]]; do
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
      stable=$((stable + 1))
      if [[ "${require_identity}" == "1" ]] && ! state_enrollment_complete; then
        stable=0
      fi
      if [[ "${stable}" -ge 3 ]]; then
        return 0
      fi
    else
      stable=0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  return 1
}

service_report_failure() {
  systemd_available || return 0
  warn "inspect with: systemctl status ${SERVICE_NAME} --no-pager"
  warn "recent logs:"
  journalctl -u "${SERVICE_NAME}" -n 25 --no-pager >&2 2>/dev/null || true
}

service_remove_unit() {
  rm -f "${UNIT_PATH}"
  rm -rf "${DROPIN_DIR}"
  systemd_available || return 0
  systemctl daemon-reload || true
}
