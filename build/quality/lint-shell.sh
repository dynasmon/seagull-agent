#!/usr/bin/env bash
set -euo pipefail

QUALITY_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SHELLCHECK="$(bash "${QUALITY_DIR}/shellcheck.sh")/shellcheck"

"${SHELLCHECK}" --severity=warning --external-sources \
  build/build.sh \
  build/quality/lint-shell.sh \
  build/quality/shellcheck.sh \
  build/security/scan-secrets.sh \
  packaging/scripts/install.sh \
  packaging/scripts/upgrade.sh \
  packaging/scripts/rollback.sh \
  packaging/scripts/uninstall.sh \
  test/packaging/run.sh

"${SHELLCHECK}" --shell=bash --severity=warning --exclude=SC2034 packaging/scripts/lib/*.sh
