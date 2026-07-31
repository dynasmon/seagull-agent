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

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT
ARCHIVE="${WORK_DIR}/shellcheck.tar.gz"
URL="https://github.com/koalaman/shellcheck/releases/download/v${VERSION}/shellcheck-v${VERSION}.${ASSET}.tar.gz"

curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --output "${ARCHIVE}" "${URL}"
printf '%s  %s\n' "${CHECKSUM}" "${ARCHIVE}" | sha256sum --check
tar xzf "${ARCHIVE}" -C "${WORK_DIR}"
SHELLCHECK="${WORK_DIR}/shellcheck-v${VERSION}/shellcheck"

"${SHELLCHECK}" --severity=warning --external-sources \
  build/build.sh \
  build/quality/lint-shell.sh \
  build/security/scan-secrets.sh \
  packaging/scripts/install.sh \
  packaging/scripts/upgrade.sh \
  packaging/scripts/rollback.sh \
  packaging/scripts/uninstall.sh \
  test/packaging/run.sh

"${SHELLCHECK}" --shell=bash --severity=warning --exclude=SC2034 packaging/scripts/lib/*.sh
