MANIFEST_NAME="MANIFEST.sha256"

artifact_verify_manifest() {
  local dir="$1"
  local manifest="${dir}/${MANIFEST_NAME}"
  if [[ ! -f "${manifest}" ]]; then
    die "package integrity manifest missing: ${manifest}"
  fi
  if ! have sha256sum; then
    warn "sha256sum unavailable; skipping package integrity verification"
    return 0
  fi
  if ! (cd "${dir}" && sha256sum --quiet -c "${MANIFEST_NAME}"); then
    die "package integrity verification failed"
  fi
  log "package integrity verified"
}

artifact_verify_signature() {
  local dir="$1"
  local sig="${dir}/${MANIFEST_NAME}.sig"
  if [[ ! -f "${sig}" ]]; then
    return 0
  fi
  if ! have cosign; then
    warn "signature present but cosign is not installed; cannot verify ${sig}"
    return 0
  fi
  local identity="${SEAGULL_COSIGN_IDENTITY:-}"
  local issuer="${SEAGULL_COSIGN_ISSUER:-https://token.actions.githubusercontent.com}"
  if [[ -z "${identity}" ]]; then
    warn "signature present but SEAGULL_COSIGN_IDENTITY is unset; cannot verify ${sig}"
    return 0
  fi
  if ! cosign verify-blob \
    --certificate "${dir}/${MANIFEST_NAME}.pem" \
    --signature "${sig}" \
    --certificate-identity-regexp "${identity}" \
    --certificate-oidc-issuer "${issuer}" \
    "${dir}/${MANIFEST_NAME}"; then
    die "package signature verification failed"
  fi
  log "package signature verified"
}

artifact_binary_runtime_deps() {
  local binary="$1"
  if ! have ldd; then
    return 0
  fi
  local missing
  missing="$(ldd "${binary}" 2>/dev/null | awk '/not found/ {print $1}' | sort -u | tr '\n' ' ')"
  missing="$(trim "${missing}")"
  if [[ -z "${missing}" ]]; then
    return 0
  fi
  warn "missing runtime libraries: ${missing}"
  if [[ "${missing}" == *libpcap* ]]; then
    warn "install libpcap first (apt install libpcap0.8, dnf install libpcap, apk add libpcap)"
  fi
  die "the agent binary cannot run on this host"
}

artifact_version() {
  local dir="$1"
  local value
  value="$(env_value version "${dir}/VERSION")"
  if [[ -z "${value}" ]]; then
    die "package VERSION file is missing or has no version"
  fi
  printf '%s' "${value}"
}
