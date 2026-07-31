#!/usr/bin/env bash
set -euo pipefail

VERSION="8.30.1"

case "$(uname -m)" in
  x86_64|amd64)
    ASSET="linux_x64"
    CHECKSUM="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
    ;;
  aarch64|arm64)
    ASSET="linux_arm64"
    CHECKSUM="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"
    ;;
  *)
    printf 'unsupported scanner architecture: %s\n' "$(uname -m)" >&2
    exit 1
    ;;
esac

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT
ARCHIVE="${WORK_DIR}/gitleaks.tar.gz"
URL="https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}/gitleaks_${VERSION}_${ASSET}.tar.gz"

curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --output "${ARCHIVE}" "${URL}"
printf '%s  %s\n' "${CHECKSUM}" "${ARCHIVE}" | sha256sum --check
tar xzf "${ARCHIVE}" -C "${WORK_DIR}" gitleaks
"${WORK_DIR}/gitleaks" git --no-banner --no-color --redact --max-archive-depth 2 --timeout 300 --platform github --log-opts=--all .
"${WORK_DIR}/gitleaks" dir --no-banner --no-color --redact --max-archive-depth 2 --timeout 300 .
