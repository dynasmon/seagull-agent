SEAGULL_LOG_PREFIX="${SEAGULL_LOG_PREFIX:-seagull-agent}"

log() {
  printf '[%s] %s\n' "${SEAGULL_LOG_PREFIX}" "$*"
}

warn() {
  printf '[%s] warning: %s\n' "${SEAGULL_LOG_PREFIX}" "$*" >&2
}

die() {
  printf '[%s] error: %s\n' "${SEAGULL_LOG_PREFIX}" "$*" >&2
  exit 1
}

trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "${s}"
}

install_root() {
  local root="${SEAGULL_INSTALL_ROOT:-/}"
  if [[ "${root}" != "/" ]]; then
    root="${root%/}"
  fi
  printf '%s' "${root}"
}

rooted() {
  local root
  root="$(install_root)"
  if [[ "${root}" == "/" ]]; then
    printf '%s' "$1"
    return
  fi
  printf '%s%s' "${root}" "$1"
}

unrooted() {
  local root
  root="$(install_root)"
  if [[ "${root}" == "/" ]]; then
    printf '%s' "$1"
    return
  fi
  printf '%s' "${1#"${root}"}"
}

is_staged_root() {
  [[ "$(install_root)" != "/" ]]
}

require_root() {
  if is_staged_root; then
    return 0
  fi
  if [[ "${EUID}" -ne 0 ]]; then
    die "run as root"
  fi
}

have() {
  command -v "$1" >/dev/null 2>&1
}

systemd_booted() {
  [[ -d /run/systemd/system ]]
}

systemd_available() {
  if is_staged_root; then
    return 1
  fi
  have systemctl && systemd_booted
}

require_systemd() {
  if is_staged_root; then
    return 0
  fi
  if ! have systemctl; then
    die "systemd is required by this installer"
  fi
  if ! systemd_booted; then
    warn "systemd is not the running init system; installing without service activation"
  fi
}

package_dir() {
  printf '%s' "${SEAGULL_PACKAGE_DIR:?package directory is not set}"
}

atomic_replace_from_stdin() {
  local path="$1"
  local mode="$2"
  local dir
  dir="$(dirname -- "${path}")"
  install -d -m 0755 "${dir}"
  local tmp
  tmp="$(mktemp "${dir}/.$(basename -- "${path}").XXXXXX")"
  if ! cat > "${tmp}"; then
    rm -f "${tmp}"
    return 1
  fi
  chmod "${mode}" "${tmp}"
  if [[ -e "${path}" ]]; then
    chown --reference="${path}" "${tmp}" 2>/dev/null || true
  fi
  sync -f "${tmp}" 2>/dev/null || sync
  mv -f "${tmp}" "${path}"
  sync -f "${dir}" 2>/dev/null || sync
}

acquire_install_lock() {
  have flock || die "flock is required"
  install -d -m 0755 "$(dirname -- "${LOCK_PATH}")"
  exec {SEAGULL_LOCK_FD}>"${LOCK_PATH}"
  if ! flock -n "${SEAGULL_LOCK_FD}"; then
    die "another seagull-agent package operation is running"
  fi
}
