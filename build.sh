#!/usr/bin/env bash
set -euo pipefail

AGENT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
MODULE_PATH="gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/buildinfo"

VERSION="${SEAGULL_AGENT_VERSION:-}"
CHANNEL="${SEAGULL_AGENT_CHANNEL:-dev}"
DIST_DIR="${SEAGULL_AGENT_DIST_DIR:-${AGENT_ROOT}/dist}"
TARGETS="${SEAGULL_AGENT_TARGETS:-}"
EXTRA_LDFLAGS="${SEAGULL_AGENT_EXTRA_LDFLAGS:-}"
STATIC="${SEAGULL_AGENT_STATIC:-0}"
PACKAGE="1"

usage() {
  cat <<'USAGE'
Usage: build.sh [options]

Options:
  --version V        Release version stamped into the binary (default: git describe, else 0.0.0-dev)
  --channel NAME     Release channel: stable, beta or dev (default: dev)
  --targets LIST     Space separated GOOS/GOARCH list (default: host platform)
  --dist DIR         Output directory (default: agent/dist)
  --static           Link libpcap and libc statically (needs static libs in the build image)
  --binary-only      Build binaries without tarballs or checksums
  -h, --help         Show this help

The agent links libpcap through cgo, so the build host needs a C toolchain and
libpcap headers. Cross-architecture targets additionally need a cross compiler,
supplied as CC_<goarch> (for example CC_arm64=aarch64-linux-gnu-gcc).

Artifacts are written as seagull-agent_<version>_<os>_<arch>.tar.gz plus SHA256SUMS.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --channel) CHANNEL="$2"; shift 2 ;;
    --targets) TARGETS="$2"; shift 2 ;;
    --dist) DIST_DIR="$2"; shift 2 ;;
    --static) STATIC="1"; shift ;;
    --binary-only) PACKAGE="0"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[build] unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if ! command -v go >/dev/null 2>&1; then
  echo "[build] go toolchain not found" >&2
  exit 1
fi

HOST_OS="$(go env GOHOSTOS)"
HOST_ARCH="$(go env GOHOSTARCH)"
TARGETS="${TARGETS:-${HOST_OS}/${HOST_ARCH}}"

resolve_version() {
  if [[ -n "${VERSION}" ]]; then
    printf '%s' "${VERSION}"
    return
  fi
  local described=""
  if git -C "${AGENT_ROOT}" rev-parse --git-dir >/dev/null 2>&1; then
    described="$(git -C "${AGENT_ROOT}" describe --tags --match 'agent-v*' --dirty 2>/dev/null || true)"
  fi
  if [[ -n "${described}" ]]; then
    printf '%s' "${described#agent-v}"
    return
  fi
  printf '0.0.0-dev'
}

resolve_commit() {
  if git -C "${AGENT_ROOT}" rev-parse --git-dir >/dev/null 2>&1; then
    local sha
    sha="$(git -C "${AGENT_ROOT}" rev-parse --short=12 HEAD 2>/dev/null || true)"
    if [[ -n "${sha}" ]]; then
      printf '%s' "${sha}"
      return
    fi
  fi
  printf 'unknown'
}

VERSION="$(resolve_version)"
COMMIT="$(resolve_commit)"
if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
  BUILD_DATE="$(date -u -d "@${SOURCE_DATE_EPOCH}" +%Y-%m-%dT%H:%M:%SZ)"
else
  BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fi
PROTOCOL_VERSION="$(grep -oE 'ProtocolVersion[[:space:]]+=[[:space:]]+[0-9]+' "${AGENT_ROOT}/internal/buildinfo/buildinfo.go" | grep -oE '[0-9]+$' | head -1)"

BUILD_TAGS="netgo,osusergo"
LDFLAGS="-s -w"
LDFLAGS+=" -X ${MODULE_PATH}.Version=${VERSION}"
LDFLAGS+=" -X ${MODULE_PATH}.Commit=${COMMIT}"
LDFLAGS+=" -X ${MODULE_PATH}.BuildDate=${BUILD_DATE}"
LDFLAGS+=" -X ${MODULE_PATH}.Channel=${CHANNEL}"
if [[ "${STATIC}" == "1" ]]; then
  LDFLAGS+=" -linkmode external -extldflags \"-static ${EXTRA_LDFLAGS}\""
elif [[ -n "${EXTRA_LDFLAGS}" ]]; then
  LDFLAGS+=" -extldflags \"${EXTRA_LDFLAGS}\""
fi

resolve_cc() {
  local goarch="$1"
  if [[ "${goarch}" == "${HOST_ARCH}" ]]; then
    printf '%s' "${CC:-}"
    return
  fi
  local var="CC_${goarch}"
  printf '%s' "${!var:-}"
}

mkdir -p "${DIST_DIR}"

build_target() {
  local goos="$1"
  local goarch="$2"
  local stage="${DIST_DIR}/seagull-agent_${VERSION}_${goos}_${goarch}"
  local cc
  cc="$(resolve_cc "${goarch}")"

  if [[ "${goarch}" != "${HOST_ARCH}" && -z "${cc}" ]]; then
    echo "[build] ${goos}/${goarch} needs a cross compiler; set CC_${goarch}=<compiler>" >&2
    exit 1
  fi

  rm -rf "${stage}"
  mkdir -p "${stage}"

  echo "[build] ${goos}/${goarch} version=${VERSION} channel=${CHANNEL} static=${STATIC}"
  (
    cd "${AGENT_ROOT}"
    CGO_ENABLED=1 GOOS="${goos}" GOARCH="${goarch}" ${cc:+CC="${cc}"} \
      go build -trimpath -tags "${BUILD_TAGS}" -ldflags "${LDFLAGS}" -o "${stage}/seagull-agent" ./cmd/agent
  )

  if [[ "${PACKAGE}" != "1" ]]; then
    mv "${stage}/seagull-agent" "${DIST_DIR}/seagull-agent_${goos}_${goarch}"
    rm -rf "${stage}"
    return
  fi

  install -m 0755 "${AGENT_ROOT}/packaging/install.sh" "${stage}/install.sh"
  install -m 0755 "${AGENT_ROOT}/packaging/uninstall.sh" "${stage}/uninstall.sh"
  install -m 0644 "${AGENT_ROOT}/packaging/seagull-agent.service" "${stage}/seagull-agent.service"
  install -m 0644 "${AGENT_ROOT}/packaging/seagull-agent.env.example" "${stage}/seagull-agent.env.example"
  install -m 0644 "${AGENT_ROOT}/packaging/README.md" "${stage}/README.md"
  install -d -m 0755 "${stage}/lib"
  install -m 0644 "${AGENT_ROOT}/packaging/lib/env-util.sh" "${stage}/lib/env-util.sh"
  chmod 0755 "${stage}/seagull-agent"

  cat > "${stage}/VERSION" <<EOF
version=${VERSION}
channel=${CHANNEL}
commit=${COMMIT}
build_date=${BUILD_DATE}
os=${goos}
arch=${goarch}
protocol_version=${PROTOCOL_VERSION}
static=${STATIC}
EOF

  tar -czf "${stage}.tar.gz" -C "${DIST_DIR}" "$(basename -- "${stage}")"
  rm -rf "${stage}"
}

for target in ${TARGETS}; do
  goos="${target%%/*}"
  goarch="${target##*/}"
  if [[ -z "${goos}" || -z "${goarch}" || "${goos}" == "${target}" ]]; then
    echo "[build] invalid target: ${target}" >&2
    exit 2
  fi
  build_target "${goos}" "${goarch}"
done

if [[ "${PACKAGE}" == "1" ]]; then
  (
    cd "${DIST_DIR}"
    sha256sum seagull-agent_"${VERSION}"_*.tar.gz > SHA256SUMS
  )
  echo "[build] artifacts in ${DIST_DIR}"
  cat "${DIST_DIR}/SHA256SUMS"
fi
