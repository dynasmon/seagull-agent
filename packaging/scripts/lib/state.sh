state_release_dir() {
  printf '%s/%s' "${RELEASE_DIR}" "$1"
}

state_release_path() {
  printf '%s/seagull-agent' "$(state_release_dir "$1")"
}

state_release_unit_path() {
  printf '%s/seagull-agent.service' "$(state_release_dir "$1")"
}

state_release_metadata_path() {
  printf '%s/VERSION' "$(state_release_dir "$1")"
}

state_read_release() {
  env_value "$1" "${RELEASE_STATE_PATH}"
}

state_record_release() {
  local current="$1"
  local previous="$2"
  validate_semver "${current}"
  if [[ -n "${previous}" ]]; then
    validate_semver "${previous}"
  fi
  {
    printf 'current=%s\n' "${current}"
    printf 'previous=%s\n' "${previous}"
  } | atomic_replace_from_stdin "${RELEASE_STATE_PATH}" 0644
}

state_store_release() {
  local version="$1"
  local binary="$2"
  local unit="$3"
  local metadata="${4:-}"
  validate_semver "${version}"
  [[ -f "${binary}" ]] || die "release binary not found: ${binary}"
  [[ -f "${unit}" ]] || die "release systemd unit not found: ${unit}"
  local target
  target="$(state_release_dir "${version}")"
  if [[ -d "${target}" ]]; then
    if ! cmp -s "${binary}" "$(state_release_path "${version}")" || ! cmp -s "${unit}" "$(state_release_unit_path "${version}")"; then
      die "release ${version} already exists with different content"
    fi
    printf '%s' "${target}"
    return
  fi
  install -d -m 0755 "${RELEASE_DIR}"
  local stage
  stage="$(mktemp -d "${RELEASE_DIR}/.${version}.XXXXXX")"
  install -m 0755 "${binary}" "${stage}/seagull-agent"
  install -m 0644 "${unit}" "${stage}/seagull-agent.service"
  if [[ -n "${metadata}" && -f "${metadata}" ]]; then
    install -m 0644 "${metadata}" "${stage}/VERSION"
  else
    printf 'version=%s\n' "${version}" > "${stage}/VERSION"
    chmod 0644 "${stage}/VERSION"
  fi
  sync -f "${stage}/seagull-agent" 2>/dev/null || sync
  sync -f "${stage}/seagull-agent.service" 2>/dev/null || sync
  mv "${stage}" "${target}"
  sync -f "${RELEASE_DIR}" 2>/dev/null || sync
  printf '%s' "${target}"
}

state_activate_release() {
  local version="$1"
  validate_semver "${version}"
  local binary unit
  binary="$(state_release_path "${version}")"
  unit="$(state_release_unit_path "${version}")"
  [[ -f "${binary}" ]] || die "release ${version} binary is not stored"
  [[ -f "${unit}" ]] || die "release ${version} systemd unit is not stored"
  atomic_replace_from_stdin "${BIN_PATH}" 0755 < "${binary}"
  atomic_replace_from_stdin "${UNIT_PATH}" 0644 < "${unit}"
}

state_detect_active_version() {
  [[ -x "${BIN_PATH}" ]] || return 0
  local output candidate
  output="$("${BIN_PATH}" --version 2>/dev/null || true)"
  candidate="$(awk 'NR == 1 && $1 == "seagull-agent" {print $2}' <<< "${output}")"
  if [[ -n "${candidate}" ]] && (validate_semver "${candidate}") >/dev/null 2>&1; then
    printf '%s' "${candidate}"
    return
  fi
  have sha256sum || die "sha256sum is required to preserve the installed release"
  local digest
  digest="$(sha256sum "${BIN_PATH}" | awk '{print substr($1, 1, 12)}')"
  printf '0.0.0-legacy.%s' "${digest}"
}

state_prune_releases() {
  local keep_current="$1"
  local keep_previous="$2"
  local limit="${SEAGULL_RELEASE_RETENTION:-3}"
  if [[ ! "${limit}" =~ ^[0-9]+$ || "${limit}" -lt 2 ]]; then
    die "SEAGULL_RELEASE_RETENTION must be an integer of at least 2"
  fi
  [[ -d "${RELEASE_DIR}" ]] || return 0
  local protected=1
  if [[ -n "${keep_previous}" && "${keep_previous}" != "${keep_current}" ]]; then
    protected=2
  fi
  local remaining=$((limit - protected))
  local kept=0
  local name
  while IFS= read -r name; do
    if [[ "${name}" == "${keep_current}" || "${name}" == "${keep_previous}" ]]; then
      continue
    fi
    if (( kept < remaining )); then
      kept=$((kept + 1))
      continue
    fi
    rm -rf "${RELEASE_DIR:?}/${name}"
  done < <(find "${RELEASE_DIR}" -mindepth 1 -maxdepth 1 -type d ! -name '.*' -printf '%T@ %f\n' 2>/dev/null | sort -rn | awk '{print $2}')
}

state_identity_present() {
  [[ -s "${IDENTITY_PATH}" || -s "${CREDENTIAL_PATH}" ]]
}

state_enrollment_complete() {
  [[ -s "${IDENTITY_PATH}" && -s "${CLIENT_CERT_PATH}" && -s "${CLIENT_KEY_PATH}" ]]
}

state_runtime_ready() {
  if state_identity_present; then
    return 0
  fi
  if [[ -s "${TOKEN_PATH}" ]]; then
    return 0
  fi
  if [[ -n "$(env_value SEAGULL_AGENT_BOOTSTRAP_TOKEN "${ENV_PATH}")" ]]; then
    return 0
  fi
  return 1
}

state_snapshot_identity() {
  local out="$1"
  install -d -m 0700 "${out}"
  local path
  for path in "${IDENTITY_PATH}" "${CREDENTIAL_PATH}" "${TOKEN_PATH}" "${CLIENT_CERT_PATH}" "${CLIENT_KEY_PATH}" "${CA_PATH}" "${ENV_PATH}"; do
    if [[ -f "${path}" ]]; then
      install -m 0600 "${path}" "${out}/$(basename -- "${path}")"
    fi
  done
}

state_assert_identity_preserved() {
  local before="$1"
  local path name
  for path in "${IDENTITY_PATH}" "${CREDENTIAL_PATH}" "${CLIENT_CERT_PATH}" "${CLIENT_KEY_PATH}"; do
    name="$(basename -- "${path}")"
    if [[ -f "${before}/${name}" && ! -f "${path}" ]]; then
      die "package operation lost agent identity file ${path}"
    fi
    if [[ -f "${before}/${name}" ]] && ! cmp -s "${before}/${name}" "${path}"; then
      die "package operation modified agent identity file ${path}"
    fi
  done
}
