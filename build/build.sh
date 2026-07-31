#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SEAGULL_LOG_PREFIX="build"
source "${REPO_ROOT}/packaging/scripts/lib/common.sh"
source "${REPO_ROOT}/packaging/scripts/lib/validation.sh"
BUILDINFO_PKG="github.com/dynasmon/seagull-agent/internal/buildinfo"

VERSION="${SEAGULL_AGENT_VERSION:-}"
CHANNEL="${SEAGULL_AGENT_CHANNEL:-dev}"
DIST_DIR="${SEAGULL_AGENT_DIST_DIR:-${REPO_ROOT}/dist}"
TARGETS="${SEAGULL_AGENT_TARGETS:-}"
STATIC="${SEAGULL_AGENT_STATIC:-0}"
PACKAGE=1
SBOM=1
ARTIFACTS=()

usage() {
  cat <<'USAGE'
Usage: build.sh [options]

  --version V     Semantic version stamped into the binary
  --channel NAME  Release channel: stable, beta or dev
  --targets LIST  Space-separated GOOS/GOARCH targets
  --dist DIR      Output directory
  --static        Link libc and libpcap statically
  --binary-only   Build binaries without release packages
  --no-sbom       Skip CycloneDX SBOM generation
  -h, --help      Show this help

The supported release targets are linux/amd64 and linux/arm64. Builds use cgo
and require a C compiler and libpcap development files for the target.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      require_option_value "$1" "${2-}"
      VERSION="$2"
      shift 2
      ;;
    --channel)
      require_option_value "$1" "${2-}"
      CHANNEL="$2"
      shift 2
      ;;
    --targets)
      require_option_value "$1" "${2-}"
      TARGETS="$2"
      shift 2
      ;;
    --dist)
      require_option_value "$1" "${2-}"
      DIST_DIR="$2"
      shift 2
      ;;
    --static)
      STATIC=1
      shift
      ;;
    --binary-only)
      PACKAGE=0
      SBOM=0
      shift
      ;;
    --no-sbom)
      SBOM=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf '[build] unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

have go || die "go toolchain not found"
have sha256sum || die "sha256sum is required"
have tar || die "GNU tar is required"
have gzip || die "gzip is required"

resolve_version() {
  if [[ -n "${VERSION}" ]]; then
    printf '%s' "${VERSION#v}"
    return
  fi
  local described=""
  if git -C "${REPO_ROOT}" rev-parse --git-dir >/dev/null 2>&1; then
    described="$(git -C "${REPO_ROOT}" describe --tags --match 'v*' --dirty 2>/dev/null || true)"
  fi
  if [[ -n "${described}" ]]; then
    printf '%s' "${described#v}"
    return
  fi
  printf '0.0.0-dev'
}

resolve_commit() {
  if git -C "${REPO_ROOT}" rev-parse --git-dir >/dev/null 2>&1; then
    git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null && return
  fi
  printf 'unknown'
}

resolve_epoch() {
  if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
    printf '%s' "${SOURCE_DATE_EPOCH}"
    return
  fi
  if git -C "${REPO_ROOT}" rev-parse --git-dir >/dev/null 2>&1; then
    git -C "${REPO_ROOT}" log -1 --format=%ct 2>/dev/null && return
  fi
  date -u +%s
}

VERSION="$(resolve_version)"
validate_semver "${VERSION}"
case "${CHANNEL}" in
  stable|beta|dev) ;;
  *) die "invalid release channel '${CHANNEL}'" ;;
esac
validate_single_line "release channel" "${CHANNEL}"
if [[ "${STATIC}" != "0" && "${STATIC}" != "1" ]]; then
  die "SEAGULL_AGENT_STATIC must be 0 or 1"
fi

COMMIT="$(resolve_commit)"
SOURCE_DATE_EPOCH="$(resolve_epoch)"
if [[ ! "${SOURCE_DATE_EPOCH}" =~ ^[0-9]+$ ]]; then
  die "SOURCE_DATE_EPOCH must be a Unix timestamp"
fi
BUILD_DATE="$(date -u -d "@${SOURCE_DATE_EPOCH}" +%Y-%m-%dT%H:%M:%SZ)"
read -r \
  PROTOCOL_VERSION \
  MIN_SERVER_PROTOCOL \
  MAX_SERVER_PROTOCOL \
  EVENT_SCHEMA_VERSION \
  MIN_EVENT_SCHEMA \
  MAX_EVENT_SCHEMA < <(go -C "${REPO_ROOT}" run ./build/metadata)
for value in \
  "${PROTOCOL_VERSION}" \
  "${MIN_SERVER_PROTOCOL}" \
  "${MAX_SERVER_PROTOCOL}" \
  "${EVENT_SCHEMA_VERSION}" \
  "${MIN_EVENT_SCHEMA}" \
  "${MAX_EVENT_SCHEMA}"; do
  if [[ ! "${value}" =~ ^[0-9]+$ ]]; then
    die "invalid protocol build metadata"
  fi
done

HOST_OS="$(go env GOHOSTOS)"
HOST_ARCH="$(go env GOHOSTARCH)"
TARGETS="${TARGETS:-${HOST_OS}/${HOST_ARCH}}"
validate_single_line "targets" "${TARGETS}"

if [[ -z "${DIST_DIR}" ]]; then
  die "output directory is required"
fi
install -d -m 0755 "${DIST_DIR}"
DIST_DIR="$(cd -- "${DIST_DIR}" && pwd -P)"
if [[ "${DIST_DIR}" == "/" ]]; then
  die "refusing to use the filesystem root as the output directory"
fi

BUILD_TAGS="netgo,osusergo"
LDFLAGS="-s -w -buildid="
LDFLAGS+=" -X ${BUILDINFO_PKG}.Version=${VERSION}"
LDFLAGS+=" -X ${BUILDINFO_PKG}.Commit=${COMMIT}"
LDFLAGS+=" -X ${BUILDINFO_PKG}.BuildDate=${BUILD_DATE}"
LDFLAGS+=" -X ${BUILDINFO_PKG}.Channel=${CHANNEL}"
if [[ "${STATIC}" == "1" ]]; then
  LDFLAGS+=" -linkmode=external -extldflags=-static"
fi

resolve_cc() {
  local goarch="$1"
  if [[ "${goarch}" == "${HOST_ARCH}" ]]; then
    printf '%s' "${CC:-}"
    return
  fi
  local variable="CC_${goarch}"
  printf '%s' "${!variable:-}"
}

stage_package() {
  local stage="$1"
  install -d -m 0755 "${stage}/lib" "${stage}/share/systemd" "${stage}/share/env"
  install -m 0755 "${REPO_ROOT}/packaging/scripts/install.sh" "${stage}/install.sh"
  install -m 0755 "${REPO_ROOT}/packaging/scripts/upgrade.sh" "${stage}/upgrade.sh"
  install -m 0755 "${REPO_ROOT}/packaging/scripts/rollback.sh" "${stage}/rollback.sh"
  install -m 0755 "${REPO_ROOT}/packaging/scripts/uninstall.sh" "${stage}/uninstall.sh"
  install -m 0644 "${REPO_ROOT}"/packaging/scripts/lib/*.sh "${stage}/lib/"
  install -m 0644 "${REPO_ROOT}/packaging/systemd/seagull-agent.service" "${stage}/share/systemd/seagull-agent.service"
  install -m 0644 "${REPO_ROOT}/packaging/env/seagull-agent.env.example" "${stage}/share/env/seagull-agent.env.example"
  install -m 0644 "${REPO_ROOT}/packaging/README.md" "${stage}/README.md"
  install -m 0644 "${REPO_ROOT}/LICENSE" "${stage}/LICENSE"
  install -m 0644 "${REPO_ROOT}/protocol/schema/protocol-v1.json" "${stage}/share/protocol-v1.json"
  install -m 0644 "${REPO_ROOT}/protocol/schema/compatibility.json" "${stage}/share/compatibility.json"
}

write_manifest() {
  local stage="$1"
  (
    cd "${stage}"
    find . -type f ! -name MANIFEST.sha256 -print0 |
      LC_ALL=C sort -z |
      xargs -0 sha256sum > MANIFEST.sha256
  )
  chmod 0644 "${stage}/MANIFEST.sha256"
}

create_archive() {
  local name="$1"
  local output="${DIST_DIR}/${name}.tar.gz"
  tar \
    --sort=name \
    --mtime="@${SOURCE_DATE_EPOCH}" \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    --format=posix \
    --pax-option=delete=atime,delete=ctime \
    -cf - \
    -C "${DIST_DIR}" \
    "${name}" |
    gzip -n > "${output}"
  ARTIFACTS+=("${output}")
}

build_target() {
  local goos="$1"
  local goarch="$2"
  case "${goos}/${goarch}" in
    linux/amd64|linux/arm64) ;;
    *) die "unsupported release target: ${goos}/${goarch}" ;;
  esac
  local name="seagull-agent_${VERSION}_${goos}_${goarch}"
  local stage="${DIST_DIR}/${name}"
  local cc
  cc="$(resolve_cc "${goarch}")"
  if [[ "${goarch}" != "${HOST_ARCH}" && -z "${cc}" ]]; then
    die "${goos}/${goarch} requires CC_${goarch}"
  fi
  if [[ -n "${cc}" ]] && ! have "${cc}"; then
    die "C compiler not found: ${cc}"
  fi

  rm -rf "${stage}"
  install -d -m 0755 "${stage}"
  printf '[build] %s/%s version=%s channel=%s static=%s\n' "${goos}" "${goarch}" "${VERSION}" "${CHANNEL}" "${STATIC}"
  (
    cd "${REPO_ROOT}"
    export CGO_ENABLED=1
    export GOOS="${goos}"
    export GOARCH="${goarch}"
    export SOURCE_DATE_EPOCH
    if [[ -n "${cc}" ]]; then
      export CC="${cc}"
    fi
    go build \
      -buildvcs=false \
      -trimpath \
      -tags "${BUILD_TAGS}" \
      -ldflags "${LDFLAGS}" \
      -o "${stage}/seagull-agent" \
      ./cmd/seagull-agent
  )
  chmod 0755 "${stage}/seagull-agent"

  if [[ "${PACKAGE}" != "1" ]]; then
    mv "${stage}/seagull-agent" "${DIST_DIR}/seagull-agent_${goos}_${goarch}"
    rm -rf "${stage}"
    return
  fi

  stage_package "${stage}"
  cat > "${stage}/VERSION" <<EOF
version=${VERSION}
channel=${CHANNEL}
commit=${COMMIT}
build_date=${BUILD_DATE}
source_date_epoch=${SOURCE_DATE_EPOCH}
os=${goos}
arch=${goarch}
protocol_version=${PROTOCOL_VERSION}
min_server_protocol=${MIN_SERVER_PROTOCOL}
max_server_protocol=${MAX_SERVER_PROTOCOL}
event_schema_version=${EVENT_SCHEMA_VERSION}
min_event_schema=${MIN_EVENT_SCHEMA}
max_event_schema=${MAX_EVENT_SCHEMA}
static=${STATIC}
EOF
  chmod 0644 "${stage}/VERSION"

  if [[ "${SBOM}" == "1" ]]; then
    local sbom="${DIST_DIR}/${name}.cdx.json"
    go -C "${REPO_ROOT}" run ./build/sbom \
      --binary "${stage}/seagull-agent" \
      --name seagull-agent \
      --version "${VERSION}" \
      --out "${sbom}"
    ARTIFACTS+=("${sbom}")
  fi

  write_manifest "${stage}"
  create_archive "${name}"
  rm -rf "${stage}"
}

declare -A SEEN_TARGETS=()
for target in ${TARGETS}; do
  if [[ ! "${target}" =~ ^([^/]+)/([^/]+)$ ]]; then
    die "invalid target '${target}'"
  fi
  target_os="${BASH_REMATCH[1]}"
  target_arch="${BASH_REMATCH[2]}"
  if [[ -n "${SEEN_TARGETS[${target}]:-}" ]]; then
    die "duplicate target '${target}'"
  fi
  SEEN_TARGETS["${target}"]=1
  build_target "${target_os}" "${target_arch}"
done

if [[ "${PACKAGE}" == "1" ]]; then
  (
    cd "${DIST_DIR}"
    names=()
    for artifact in "${ARTIFACTS[@]}"; do
      names+=("$(basename -- "${artifact}")")
    done
    printf '%s\0' "${names[@]}" |
      LC_ALL=C sort -z |
      xargs -0 sha256sum > SHA256SUMS
  )
  printf '[build] artifacts in %s\n' "${DIST_DIR}"
  cat "${DIST_DIR}/SHA256SUMS"
fi
