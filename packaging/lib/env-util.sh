trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "${s}"
}

read_env_value() {
  local key="$1"
  local file="$2"
  awk -F= -v k="${key}" '$1==k {print substr($0, index($0, "=")+1)}' "${file}" | tail -n1 | tr -d '\r'
}

env_key_exists() {
  local key="$1"
  local file="$2"
  grep -qE "^${key}=" "${file}"
}

set_env_value() {
  local key="$1"
  local value="$2"
  local file="$3"

  remove_env_key "${key}" "${file}"
  printf "%s=%s\n" "${key}" "${value}" >> "${file}"
}

remove_env_key() {
  local key="$1"
  local file="$2"
  sed -i -E "/^${key}=/d" "${file}"
}

normalize_env_key() {
  local key="$1"
  local file="$2"
  if ! env_key_exists "${key}" "${file}"; then
    return
  fi
  local value
  value="$(trim "$(read_env_value "${key}" "${file}")")"
  set_env_value "${key}" "${value}" "${file}"
}

ensure_env_value() {
  local key="$1"
  local value="$2"
  local file="$3"
  if ! env_key_exists "${key}" "${file}"; then
    set_env_value "${key}" "${value}" "${file}"
  fi
}
