#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
BUILDINFO_PKG="github.com/dynasmon/Seagull-agent/internal/buildinfo"

VERSION="${SEAGULL_AGENT_VERSION:-}"
CHANNEL="${SEAGULL_AGENT_CHANNEL:-dev}"
DIST_DIR="${SEAGULL_AGENT_DIST_DIR:-${REPO_ROOT}/dist}"
TARGETS="${SEAGULL_AGENT_TARGETS:-}"
EXTRA_LDFLAGS="${SEAGULL_AGENT_EXTRA_LDFLAGS:-}"
STATIC="${SEAGULL_AGENT_STATIC:-0}"
PACKAGE=1
SBOM=1

usage() {
  cat <<'USAGE'
Usage: build.sh [options]

  --version V     Release version stamped into the binary (default: git describe, else 0.0.0-dev)
  --channel NAME  Release channel: stable, beta or dev (default: dev)
  --targets LIST  Space separated GOOS/GOARCH list (default: host platform)
  --dist DIR      Output directory (default: ./dist)
  --static        Link libpcap and libc statically (needs static libs in the build image)
  --binary-only   Build binaries without packages or checksums
  --no-sbom       Skip SBOM generation
  -h, --help      Show this help

The agent links libpcap through cgo, so the build host needs a C toolchain and
libpcap headers. Cross-architecture targets additionally need a cross compiler,
supplied as CC_<goarch> (for example CC_arm64=aarch64-linux-gnu-gcc).

Artifacts are written as seagull-agent_<version>_<os>_<arch>.tar.gz plus
SHA256SUMS and, unless disabled, a CycloneDX SBOM per target.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --channel) CHANNEL="$2"; shift 2 ;;
    --targets) TARGETS="$2"; shift 2 ;;
    --dist) DIST_DIR="$2"; shift 2 ;;
    --static) STATIC=1; shift ;;
    --binary-only) PACKAGE=0; SBOM=0; shift ;;
    --no-sbom) SBOM=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[build] unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

command -v go >/dev/null 2>&1 || { echo "[build] go toolchain not found" >&2; exit 1; }

HOST_OS="$(go env GOHOSTOS)"
HOST_ARCH="$(go env GOHOSTARCH)"
TARGETS="${TARGETS:-${HOST_OS}/${HOST_ARCH}}"

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
    git -C "${REPO_ROOT}" rev-parse --short=12 HEAD 2>/dev/null && return
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
PROTOCOL_VERSION="$(awk '/^\tVersion +=/ {print $3; exit}' "${REPO_ROOT}/protocol/version.go")"
EVENT_SCHEMA_VERSION="$(awk '/^\tEventSchemaVersion +=/ {print $3; exit}' "${REPO_ROOT}/protocol/version.go")"

BUILD_TAGS="netgo,osusergo"
LDFLAGS="-s -w"
LDFLAGS+=" -X ${BUILDINFO_PKG}.Version=${VERSION}"
LDFLAGS+=" -X ${BUILDINFO_PKG}.Commit=${COMMIT}"
LDFLAGS+=" -X ${BUILDINFO_PKG}.BuildDate=${BUILD_DATE}"
LDFLAGS+=" -X ${BUILDINFO_PKG}.Channel=${CHANNEL}"
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
}

write_manifest() {
  local stage="$1"
  ( cd "${stage}" && find . -type f ! -name MANIFEST.sha256 -print0 \
      | LC_ALL=C sort -z \
      | xargs -0 sha256sum > MANIFEST.sha256 )
  chmod 0644 "${stage}/MANIFEST.sha256"
}

build_target() {
  local goos="$1"
  local goarch="$2"
  local name="seagull-agent_${VERSION}_${goos}_${goarch}"
  local stage="${DIST_DIR}/${name}"
  local cc
  cc="$(resolve_cc "${goarch}")"

  if [[ "${goarch}" != "${HOST_ARCH}" && -z "${cc}" ]]; then
    echo "[build] ${goos}/${goarch} needs a cross compiler; set CC_${goarch}=<compiler>" >&2
    exit 1
  fi

  rm -rf "${stage}"
  install -d -m 0755 "${stage}"

  echo "[build] ${goos}/${goarch} version=${VERSION} channel=${CHANNEL} static=${STATIC}"
  (
    cd "${REPO_ROOT}"
    CGO_ENABLED=1 GOOS="${goos}" GOARCH="${goarch}" ${cc:+CC="${cc}"} \
      go build -trimpath -tags "${BUILD_TAGS}" -ldflags "${LDFLAGS}" -o "${stage}/seagull-agent" ./cmd/seagull-agent
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
os=${goos}
arch=${goarch}
protocol_version=${PROTOCOL_VERSION}
event_schema_version=${EVENT_SCHEMA_VERSION}
static=${STATIC}
EOF
  chmod 0644 "${stage}/VERSION"

  if [[ "${SBOM}" == "1" ]]; then
    go run "${REPO_ROOT}/build/sbom" \
      --binary "${stage}/seagull-agent" \
      --name seagull-agent \
      --version "${VERSION}" \
      --out "${DIST_DIR}/${name}.cdx.json"
  fi

  write_manifest "${stage}"
  tar -czf "${stage}.tar.gz" -C "${DIST_DIR}" "${name}"
  rm -rf "${stage}"
}

install -d -m 0755 "${DIST_DIR}"

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
  ( cd "${DIST_DIR}" && sha256sum seagull-agent_"${VERSION}"_*.tar.gz *.cdx.json 2>/dev/null > SHA256SUMS )
  echo "[build] artifacts in ${DIST_DIR}"
  cat "${DIST_DIR}/SHA256SUMS"
fi
