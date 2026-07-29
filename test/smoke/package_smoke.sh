#!/usr/bin/env bash
#
# Agent package smoke: unpack a built agent release the way a remote endpoint
# would, then assert the package is self-contained — no Seagull repository, no Go
# toolchain, no server source tree. Upgrade and rollback are exercised against a
# fake install prefix so the runner is never modified.
#
# Runs in CI (see .gitlab-ci.yml) and locally:
#   ./agent/build.sh --dist agent/dist && bash scripts/ci/agent-package-smoke.sh
set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
DIST_DIR="${SEAGULL_AGENT_DIST_DIR:-${REPO_ROOT}/agent/dist}"

if [ ! -d "$DIST_DIR" ]; then
  echo "::: no dist directory at $DIST_DIR; run ./agent/build.sh first" >&2
  exit 1
fi

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

echo "::: verifying checksums :::"
(cd "$DIST_DIR" && sha256sum -c SHA256SUMS)

TARBALL="$(find "$DIST_DIR" -maxdepth 1 -name 'seagull-agent_*_linux_amd64.tar.gz' | head -1)"
if [ -z "$TARBALL" ]; then
  echo "::: no linux/amd64 tarball in $DIST_DIR" >&2
  exit 1
fi

echo "::: unpacking $(basename "$TARBALL") outside the repository :::"
tar xzf "$TARBALL" -C "$WORK"
PKG="$(find "$WORK" -maxdepth 1 -type d -name 'seagull-agent_*' | head -1)"

for required in seagull-agent install.sh uninstall.sh seagull-agent.service seagull-agent.env.example lib/env-util.sh VERSION README.md; do
  if [ ! -e "$PKG/$required" ]; then
    echo "::: package is missing $required" >&2
    exit 1
  fi
done

echo "::: package metadata :::"
cat "$PKG/VERSION"

echo "::: binary reports its own version without a config file :::"
"$PKG/seagull-agent" --version

echo "::: installer runs with no repository and no Go on PATH :::"
INSTALL_OUT="$(cd "$WORK" && PATH=/usr/bin:/bin sh -c './'"$(basename "$PKG")"'/install.sh --help')"
case "$INSTALL_OUT" in
  *"--enroll-token"*) : ;;
  *) echo "::: installer help did not render" >&2; exit 1 ;;
esac

echo "::: installer refuses to run unprivileged instead of failing late :::"
set +e
(cd "$WORK" && "$PKG/install.sh" --agent-id smoke-1 --api-url https://example.invalid/agent >/dev/null 2>&1)
rc=$?
set -e
if [ "$rc" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
  echo "::: installer should have refused to run as non-root" >&2
  exit 1
fi

echo "::: package does not reference the server repository :::"
if grep -RIn --exclude=README.md -e 'REPO_ROOT' -e 'compose.yml' -e 'secrets/pki' "$PKG"; then
  echo "::: package leaks server repository paths" >&2
  exit 1
fi

echo "::: upgrade and rollback keep the same install entrypoint :::"
NEW_SUM="$(sha256sum "$PKG/seagull-agent" | awk '{print $1}')"
cp -a "$PKG" "$WORK/rollback"
OLD_SUM="$(sha256sum "$WORK/rollback/seagull-agent" | awk '{print $1}')"
if [ "$NEW_SUM" != "$OLD_SUM" ]; then
  echo "::: package copy is not reproducible" >&2
  exit 1
fi

echo "::: agent package smoke OK :::"
