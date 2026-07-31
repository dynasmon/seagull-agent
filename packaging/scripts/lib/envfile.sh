read_env_value() {
  local key="$1"
  local file="$2"
  if [[ ! -f "${file}" ]]; then
    return 0
  fi
  awk -F= -v k="${key}" '$1==k {print substr($0, index($0, "=")+1)}' "${file}" | tail -n1 | tr -d '\r'
}

env_value() {
  trim "$(read_env_value "$1" "$2")"
}

env_key_exists() {
  local key="$1"
  local file="$2"
  validate_env_key "${key}"
  [[ -f "${file}" ]] && grep -qE "^${key}=" "${file}"
}

remove_env_key() {
  local key="$1"
  local file="$2"
  validate_env_key "${key}"
  [[ -f "${file}" ]] || return 0
  local mode
  mode="$(stat -c '%a' "${file}")"
  awk -F= -v k="${key}" '$1 != k' "${file}" | atomic_replace_from_stdin "${file}" "${mode}"
}

set_env_value() {
  local key="$1"
  local value="$2"
  local file="$3"
  validate_env_key "${key}"
  validate_single_line "${key}" "${value}"
  local mode="600"
  if [[ -f "${file}" ]]; then
    mode="$(stat -c '%a' "${file}")"
  fi
  {
    if [[ -f "${file}" ]]; then
      awk -F= -v k="${key}" '$1 != k' "${file}"
    fi
    printf '%s=%s\n' "${key}" "${value}"
  } | atomic_replace_from_stdin "${file}" "${mode}"
}

ensure_env_value() {
  local key="$1"
  local value="$2"
  local file="$3"
  if ! env_key_exists "${key}" "${file}"; then
    set_env_value "${key}" "${value}" "${file}"
  fi
}

validate_env_key() {
  local key="$1"
  if [[ ! "${key}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    die "invalid environment key '${key}'"
  fi
}
