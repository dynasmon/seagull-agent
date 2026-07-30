state_release_path() {
  printf '%s/%s/seagull-agent' "${RELEASE_DIR}" "$1"
}

state_read_release() {
  env_value "$1" "${RELEASE_STATE_PATH}"
}

state_record_release() {
  local current="$1"
  local previous="$2"
  install -d -m 0755 "$(dirname -- "${RELEASE_STATE_PATH}")"
  : > "${RELEASE_STATE_PATH}"
  set_env_value current "${current}" "${RELEASE_STATE_PATH}"
  set_env_value previous "${previous}" "${RELEASE_STATE_PATH}"
  chmod 0644 "${RELEASE_STATE_PATH}"
}

state_store_release() {
  local version="$1"
  local binary="$2"
  local target
  target="$(state_release_path "${version}")"
  install -d -m 0755 "$(dirname -- "${target}")"
  install -m 0755 "${binary}" "${target}"
  printf '%s' "${target}"
}

state_activate_release() {
  local version="$1"
  local source
  source="$(state_release_path "${version}")"
  if [[ ! -f "${source}" ]]; then
    die "release ${version} is not present in ${RELEASE_DIR}"
  fi
  install -d -m 0755 "$(dirname -- "${BIN_PATH}")"
  install -m 0755 "${source}" "${BIN_PATH}"
}

state_prune_releases() {
  local keep_current="$1"
  local keep_previous="$2"
  local limit="${SEAGULL_RELEASE_RETENTION:-3}"
  [[ -d "${RELEASE_DIR}" ]] || return 0
  local entries=()
  local dir
  while IFS= read -r dir; do
    entries+=("${dir}")
  done < <(find "${RELEASE_DIR}" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %f\n' 2>/dev/null | sort -rn | awk '{print $2}')
  local kept=0
  local name
  for name in "${entries[@]}"; do
    if [[ "${name}" == "${keep_current}" || "${name}" == "${keep_previous}" ]]; then
      continue
    fi
    kept=$((kept + 1))
    if [[ "${kept}" -ge "${limit}" ]]; then
      rm -rf "${RELEASE_DIR:?}/${name}"
    fi
  done
}

state_identity_present() {
  [[ -s "${IDENTITY_PATH}" || -s "${CREDENTIAL_PATH}" ]]
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
      die "upgrade lost agent identity file ${path}"
    fi
    if [[ -f "${before}/${name}" ]] && ! cmp -s "${before}/${name}" "${path}"; then
      die "upgrade modified agent identity file ${path}"
    fi
  done
}
