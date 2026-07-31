validate_single_line() {
  local label="$1"
  local value="$2"
  if [[ "${value}" == *$'\n'* || "${value}" == *$'\r'* ]]; then
    die "${label} must be a single line"
  fi
}

require_option_value() {
  local option="$1"
  local value="${2-}"
  if [[ -z "${value}" || "${value}" == --* ]]; then
    die "${option} requires a value"
  fi
}

validate_agent_id() {
  local value="$1"
  validate_single_line "agent id" "${value}"
  if [[ ! "${value}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
    die "invalid agent id '${value}'"
  fi
}

validate_profile() {
  case "$1" in
    sensor|managed) ;;
    *) die "invalid profile '$1' (expected sensor or managed)" ;;
  esac
}

validate_https_url() {
  local label="$1"
  local value="$2"
  validate_single_line "${label}" "${value}"
  if [[ "${value}" != https://* ]]; then
    die "${label} must use https"
  fi
  if [[ "${value}" == *[\?\#]* || "${value}" == *[\@\ ]* || "${value}" == *$'\t'* || "${value}" == *\\* ]]; then
    die "invalid ${label}"
  fi
  local remainder="${value#https://}"
  local authority="${remainder%%/*}"
  if [[ -z "${authority}" ]]; then
    die "invalid ${label}"
  fi
  local host="${authority}"
  local port=""
  if [[ "${authority}" == \[* ]]; then
    if [[ ! "${authority}" =~ ^\[([0-9A-Fa-f:.]+)\](:([0-9]+))?$ ]]; then
      die "invalid ${label} authority"
    fi
    host="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[3]}"
  else
    if [[ "${authority}" == *:* ]]; then
      host="${authority%:*}"
      port="${authority##*:}"
    fi
    if [[ ! "${host}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]]; then
      die "invalid ${label} host"
    fi
    if [[ "${host}" == *..* ]]; then
      die "invalid ${label} host"
    fi
  fi
  if [[ -n "${port}" ]] && { [[ ! "${port}" =~ ^[0-9]{1,5}$ ]] || (( 10#${port} < 1 || 10#${port} > 65535 )); }; then
    die "invalid ${label} port"
  fi
}

validate_tls_server_name() {
  local value="$1"
  [[ -n "${value}" ]] || return 0
  validate_single_line "TLS server name" "${value}"
  if [[ ! "${value}" =~ ^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$ || "${value}" == *..* ]]; then
    die "invalid TLS server name '${value}'"
  fi
}

validate_sources() {
  local value="$1"
  validate_single_line "sources" "${value}"
  local normalized=""
  local item
  local seen=","
  local values=()
  IFS=',' read -r -a values <<< "${value}"
  if [[ "${#values[@]}" -eq 0 ]]; then
    die "at least one source is required"
  fi
  for item in "${values[@]}"; do
    item="$(trim "${item}")"
    case "${item}" in
      authlog|proc|proc_exec|fim|scan|ddos|l7|lateral|syscollector|vuln) ;;
      *) die "unsupported source '${item}'" ;;
    esac
    if [[ "${seen}" == *",${item},"* ]]; then
      die "duplicate source '${item}'"
    fi
    seen+="${item},"
    if [[ -n "${normalized}" ]]; then
      normalized+=","
    fi
    normalized+="${item}"
  done
  printf '%s' "${normalized}"
}

bootstrap_token_agent_id() {
  local token="$1"
  validate_single_line "enrollment token" "${token}"
  if [[ ! "${token}" =~ ^abt\.(.+)\.([A-Za-z0-9_-]{16,})$ ]]; then
    die "invalid enrollment token format"
  fi
  local agent_id="${BASH_REMATCH[1]}"
  validate_agent_id "${agent_id}"
  printf '%s' "${agent_id}"
}

validate_semver() {
  local value="$1"
  validate_single_line "version" "${value}"
  if [[ ! "${value}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?(\+([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$ ]]; then
    die "invalid semantic version '${value}'"
  fi
  local prerelease="${BASH_REMATCH[5]}"
  local identifier
  local identifiers=()
  if [[ -n "${prerelease}" ]]; then
    IFS='.' read -r -a identifiers <<< "${prerelease}"
    for identifier in "${identifiers[@]}"; do
      if [[ "${identifier}" =~ ^[0-9]+$ && "${identifier}" != "0" && "${identifier}" == 0* ]]; then
        die "invalid semantic version '${value}'"
      fi
    done
  fi
}

semver_core() {
  local value="${1%%+*}"
  printf '%s' "${value%%-*}"
}

semver_prerelease() {
  local value="${1%%+*}"
  if [[ "${value}" == *-* ]]; then
    printf '%s' "${value#*-}"
  fi
}

semver_compare() {
  local left="$1"
  local right="$2"
  validate_semver "${left}"
  validate_semver "${right}"
  local left_core right_core
  left_core="$(semver_core "${left}")"
  right_core="$(semver_core "${right}")"
  local left_parts=()
  local right_parts=()
  IFS='.' read -r -a left_parts <<< "${left_core}"
  IFS='.' read -r -a right_parts <<< "${right_core}"
  local index
  for index in 0 1 2; do
    if (( 10#${left_parts[index]} < 10#${right_parts[index]} )); then
      printf '%s' -1
      return
    fi
    if (( 10#${left_parts[index]} > 10#${right_parts[index]} )); then
      printf '%s' 1
      return
    fi
  done
  local left_pre right_pre
  left_pre="$(semver_prerelease "${left}")"
  right_pre="$(semver_prerelease "${right}")"
  if [[ -z "${left_pre}" && -z "${right_pre}" ]]; then
    printf '%s' 0
    return
  fi
  if [[ -z "${left_pre}" ]]; then
    printf '%s' 1
    return
  fi
  if [[ -z "${right_pre}" ]]; then
    printf '%s' -1
    return
  fi
  local left_ids=()
  local right_ids=()
  IFS='.' read -r -a left_ids <<< "${left_pre}"
  IFS='.' read -r -a right_ids <<< "${right_pre}"
  local count="${#left_ids[@]}"
  if (( ${#right_ids[@]} > count )); then
    count="${#right_ids[@]}"
  fi
  for ((index = 0; index < count; index++)); do
    if (( index >= ${#left_ids[@]} )); then
      printf '%s' -1
      return
    fi
    if (( index >= ${#right_ids[@]} )); then
      printf '%s' 1
      return
    fi
    local left_id="${left_ids[index]}"
    local right_id="${right_ids[index]}"
    if [[ "${left_id}" == "${right_id}" ]]; then
      continue
    fi
    if [[ "${left_id}" =~ ^[0-9]+$ && "${right_id}" =~ ^[0-9]+$ ]]; then
      if (( 10#${left_id} < 10#${right_id} )); then
        printf '%s' -1
      else
        printf '%s' 1
      fi
      return
    fi
    if [[ "${left_id}" =~ ^[0-9]+$ ]]; then
      printf '%s' -1
      return
    fi
    if [[ "${right_id}" =~ ^[0-9]+$ ]]; then
      printf '%s' 1
      return
    fi
    if [[ "${left_id}" < "${right_id}" ]]; then
      printf '%s' -1
    else
      printf '%s' 1
    fi
    return
  done
  printf '%s' 0
}

read_single_line_secret() {
  local label="$1"
  local path="$2"
  [[ -f "${path}" ]] || die "${label} file not found: ${path}"
  local value
  value="$(<"${path}")"
  validate_single_line "${label}" "${value}"
  value="$(trim "${value}")"
  [[ -n "${value}" ]] || die "${label} file is empty: ${path}"
  printf '%s' "${value}"
}
