#!/usr/bin/env bash
set -euo pipefail

VERSION="0.11.0"

case "$(uname -m)" in
  x86_64|amd64)
    ASSET="linux.x86_64"
    CHECKSUM="b7af85e41cc99489dcc21d66c6d5f3685138f06d34651e6d34b42ec6d54fe6f6"
    ;;
  aarch64|arm64)
    ASSET="linux.aarch64"
    CHECKSUM="68a8133197a50beb8803f8d42f9908d1af1c5540d4bb05fdfca8c1fa47decefc"
    ;;
  *)
    printf 'unsupported shell lint architecture: %s\n' "$(uname -m)" >&2
    exit 1
    ;;
esac

CACHE_DIR="${SEAGULL_TOOL_CACHE:-${TMPDIR:-/tmp}/seagull-tools}/shellcheck-${VERSION}-${ASSET}"
BINARY="${CACHE_DIR}/shellcheck"

if [[ ! -x "${BINARY}" ]]; then
  WORK_DIR="$(mktemp -d)"
  trap 'rm -rf "${WORK_DIR}"' EXIT
  ARCHIVE="${WORK_DIR}/shellcheck.tar.gz"
  URL="https://github.com/koalaman/shellcheck/releases/download/v${VERSION}/shellcheck-v${VERSION}.${ASSET}.tar.gz"
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --output "${ARCHIVE}" "${URL}"
  printf '%s  %s\n' "${CHECKSUM}" "${ARCHIVE}" | sha256sum --check --status
  tar xzf "${ARCHIVE}" -C "${WORK_DIR}"
  install -d -m 0755 "${CACHE_DIR}"
  install -m 0755 "${WORK_DIR}/shellcheck-v${VERSION}/shellcheck" "${BINARY}"
fi

printf '%s' "${CACHE_DIR}"
