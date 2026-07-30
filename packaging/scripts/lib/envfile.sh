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
  [[ -f "${file}" ]] && grep -qE "^${key}=" "${file}"
}

remove_env_key() {
  local key="$1"
  local file="$2"
  [[ -f "${file}" ]] || return 0
  sed -i -E "/^${key}=/d" "${file}"
}

set_env_value() {
  local key="$1"
  local value="$2"
  local file="$3"
  remove_env_key "${key}" "${file}"
  printf '%s=%s\n' "${key}" "${value}" >> "${file}"
}

ensure_env_value() {
  local key="$1"
  local value="$2"
  local file="$3"
  if ! env_key_exists "${key}" "${file}"; then
    set_env_value "${key}" "${value}" "${file}"
  fi
}
