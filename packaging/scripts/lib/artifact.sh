MANIFEST_NAME="MANIFEST.sha256"

artifact_verify_manifest() {
  local dir="$1"
  local manifest="${dir}/${MANIFEST_NAME}"
  if [[ ! -f "${manifest}" ]]; then
    die "package integrity manifest missing: ${manifest}"
  fi
  if ! have sha256sum; then
    die "sha256sum is required for package integrity verification"
  fi
  if ! (cd "${dir}" && sha256sum --quiet -c "${MANIFEST_NAME}"); then
    die "package integrity verification failed"
  fi
  log "package integrity verified"
}

artifact_verify_signature() {
  local dir="$1"
  local sig="${dir}/${MANIFEST_NAME}.sig"
  local certificate="${dir}/${MANIFEST_NAME}.pem"
  if [[ ! -f "${sig}" && ! -f "${certificate}" ]]; then
    return 0
  fi
  if [[ ! -f "${sig}" || ! -f "${certificate}" ]]; then
    die "package signature material is incomplete"
  fi
  if ! have cosign; then
    die "cosign is required to verify the package signature"
  fi
  local identity="${SEAGULL_COSIGN_IDENTITY:-^https://github\\.com/dynasmon/[Ss]eagull-agent/\\.github/workflows/release\\.yml@refs/tags/v[0-9].*$}"
  local issuer="${SEAGULL_COSIGN_ISSUER:-https://token.actions.githubusercontent.com}"
  if ! cosign verify-blob \
    --certificate "${certificate}" \
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
    warn "install libpcap first (apt install libpcap0.8 or libpcap0.8t64, dnf install libpcap, apk add libpcap)"
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
  validate_semver "${value}"
  printf '%s' "${value}"
}

artifact_verify_target() {
  local dir="$1"
  local package_os package_arch
  package_os="$(env_value os "${dir}/VERSION")"
  package_arch="$(env_value arch "${dir}/VERSION")"
  local host_os host_arch
  host_os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$(uname -m)" in
    x86_64) host_arch="amd64" ;;
    aarch64|arm64) host_arch="arm64" ;;
    *) die "unsupported host architecture: $(uname -m)" ;;
  esac
  if [[ "${package_os}" != "${host_os}" || "${package_arch}" != "${host_arch}" ]]; then
    die "package target ${package_os}/${package_arch} does not match host ${host_os}/${host_arch}"
  fi
}

artifact_verify_binary_identity() {
  local dir="$1"
  local expected
  expected="$(artifact_version "${dir}")"
  local output
  if ! output="$("${dir}/seagull-agent" --version 2>&1)"; then
    die "the agent binary did not execute: ${output}"
  fi
  local actual
  actual="$(awk 'NR == 1 && $1 == "seagull-agent" {print $2}' <<< "${output}")"
  if [[ "${actual}" != "${expected}" ]]; then
    die "binary version '${actual:-unknown}' does not match package version '${expected}'"
  fi
}

artifact_verify_package() {
  local dir="$1"
  local required
  for required in \
    seagull-agent \
    VERSION \
    MANIFEST.sha256 \
    share/systemd/seagull-agent.service \
    share/env/seagull-agent.env.example \
    share/protocol-v1.json \
    share/compatibility.json; do
    [[ -f "${dir}/${required}" ]] || die "package file missing: ${required}"
  done
  artifact_verify_manifest "${dir}"
  artifact_verify_signature "${dir}"
  artifact_verify_target "${dir}"
  artifact_binary_runtime_deps "${dir}/seagull-agent"
  artifact_verify_binary_identity "${dir}"
}
