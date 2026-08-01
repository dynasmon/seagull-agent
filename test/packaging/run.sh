#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

PASS=0
FAIL=0

check() {
  local label="$1"
  shift
  if "$@"; then
    printf 'ok   %s\n' "${label}"
    PASS=$((PASS + 1))
  else
    printf 'FAIL %s\n' "${label}"
    FAIL=$((FAIL + 1))
  fi
}

refute() {
  local label="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    printf 'FAIL %s\n' "${label}"
    FAIL=$((FAIL + 1))
  else
    printf 'ok   %s\n' "${label}"
    PASS=$((PASS + 1))
  fi
}

file_exists() { [[ -f "$1" ]]; }
dir_exists() { [[ -d "$1" ]]; }
file_absent() { [[ ! -e "$1" ]]; }
file_contains() { grep -q "$2" "$1"; }
file_lacks() { ! grep -q "$2" "$1"; }
mode_is() { [[ "$(stat -c '%a' "$1")" == "$2" ]]; }
files_equal() { cmp -s "$1" "$2"; }
path_round_trips() {
  local root="$1"
  local path="$2"
  local pkg="$3"
  (
    export SEAGULL_INSTALL_ROOT="${root}"
    source "${pkg}/lib/common.sh"
    [[ "$(unrooted "$(rooted "${path}")")" == "${path}" ]]
  )
}
staged_root_is_applied() {
  local root="$1"
  local path="$2"
  local pkg="$3"
  (
    export SEAGULL_INSTALL_ROOT="${root}"
    source "${pkg}/lib/common.sh"
    [[ "$(rooted "${path}")" == "${root}${path}" ]]
  )
}

build_packages() {
  printf '::: building release packages\n'
  SEAGULL_AGENT_VERSION=1.0.0 bash "${REPO_ROOT}/build/build.sh" \
    --version 1.0.0 --channel stable --dist "${WORK}/dist-1.0.0" >/dev/null
  SEAGULL_AGENT_VERSION=1.1.0 bash "${REPO_ROOT}/build/build.sh" \
    --version 1.1.0 --channel stable --dist "${WORK}/dist-1.1.0" >/dev/null
}

unpack() {
  local dist="$1"
  local dest="$2"
  mkdir -p "${dest}"
  tar xzf "${dist}"/seagull-agent_*_linux_*.tar.gz -C "${dest}"
  find "${dest}" -maxdepth 1 -type d -name 'seagull-agent_*' | head -1
}

main() {
  build_packages

  local pkg1 pkg2 root
  pkg1="$(unpack "${WORK}/dist-1.0.0" "${WORK}/pkg1")"
  pkg2="$(unpack "${WORK}/dist-1.1.0" "${WORK}/pkg2")"
  root="${WORK}/root"
  mkdir -p "${root}"

  printf '\n::: package contents\n'
  for required in seagull-agent install.sh upgrade.sh rollback.sh uninstall.sh VERSION MANIFEST.sha256 README.md LICENSE \
    lib/common.sh lib/validation.sh lib/layout.sh lib/envfile.sh lib/artifact.sh lib/service.sh lib/state.sh lib/migrate.sh \
    share/systemd/seagull-agent.service share/env/seagull-agent.env.example share/protocol-v1.json share/compatibility.json; do
    check "package ships ${required}" file_exists "${pkg1}/${required}"
  done
  check "package manifest verifies" bash -c "cd '${pkg1}' && sha256sum --quiet -c MANIFEST.sha256"
  check "binary reports its version without config" bash -c "'${pkg1}/seagull-agent' --version | grep -q '1.0.0'"
  check "binary reports the protocol version" bash -c "'${pkg1}/seagull-agent' --version | grep -q 'protocol 1'"

  printf '\n::: package is independent of the platform repository\n'
  refute "package does not reference the platform repository" \
    grep -RIn --exclude=README.md --exclude=LICENSE -e 'REPO_ROOT' -e 'compose.yml' -e 'secrets/pki' "${pkg1}"
  refute "package does not build from source" grep -RIn 'go build' "${pkg1}/install.sh" "${pkg1}/lib"
  refute "installer does not read platform env files" grep -RIn -e 'repo_env_value' -e '\.\./' "${pkg1}/install.sh" "${pkg1}/lib"
  refute "integrity verification cannot be skipped without sha256sum" bash -c "
    source '${pkg1}/lib/common.sh'
    source '${pkg1}/lib/validation.sh'
    source '${pkg1}/lib/envfile.sh'
    source '${pkg1}/lib/artifact.sh'
    have() { return 1; }
    artifact_verify_manifest '${pkg1}'
  "

  printf '\n::: runtime paths stay absolute at every install root\n'
  check "paths round trip at the filesystem root" \
    path_round_trips / /var/lib/seagull/pki/server-ca.crt "${pkg1}"
  check "paths round trip under a staged root" \
    path_round_trips "${WORK}/stage" /var/lib/seagull/pki/server-ca.crt "${pkg1}"
  check "a staged root is applied to runtime paths" \
    staged_root_is_applied "${WORK}/stage" /etc/seagull/agent.env "${pkg1}"

  printf '\n::: fresh install\n'
  local token="abt.agent-test-1.0123456789abcdef0123456789abcdef"
  local rejected="${WORK}/rejected"
  mkdir -p "${rejected}"
  refute "missing option values are rejected" env SEAGULL_INSTALL_ROOT="${rejected}" bash "${pkg1}/install.sh" --api-url
  refute "plaintext API URLs are rejected" env SEAGULL_INSTALL_ROOT="${rejected}" bash "${pkg1}/install.sh" \
    --agent-id agent-test-1 --api-url http://siem.example.com/agent --no-start
  refute "token and agent identity mismatch is rejected" env SEAGULL_INSTALL_ROOT="${rejected}" bash "${pkg1}/install.sh" \
    --agent-id another-agent --api-url https://siem.example.com:8444/agent \
    --enroll-url https://siem.example.com:8445 --enroll-token "${token}" --no-start
  refute "multiple token input methods are rejected" env SEAGULL_INSTALL_ROOT="${rejected}" bash "${pkg1}/install.sh" \
    --agent-id agent-test-1 --api-url https://siem.example.com:8444/agent \
    --enroll-url https://siem.example.com:8445 --enroll-token "${token}" --prompt-enroll-token --no-start
  printf 'not a CA bundle\n' > "${WORK}/invalid-ca.pem"
  refute "invalid CA bundles are rejected before installation" env SEAGULL_INSTALL_ROOT="${rejected}" bash "${pkg1}/install.sh" \
    --agent-id agent-test-1 --api-url https://siem.example.com:8444/agent \
    --enroll-url https://siem.example.com:8445 --enroll-token "${token}" \
    --ca-file "${WORK}/invalid-ca.pem" --no-start
  local prompt_root="${WORK}/prompt"
  mkdir -p "${prompt_root}"
  refute "interactive token input requires a terminal" bash -c "
    SEAGULL_INSTALL_ROOT='${prompt_root}' bash '${pkg1}/install.sh' \
      --agent-id agent-test-1 \
      --api-url https://siem.example.com:8444/agent \
      --enroll-url https://siem.example.com:8445 \
      --prompt-enroll-token \
      --no-start </dev/null
  "
  check "install succeeds" env SEAGULL_INSTALL_ROOT="${root}" bash "${pkg1}/install.sh" \
    --api-url https://siem.example.com:8444/agent \
    --enroll-url https://siem.example.com:8445 --enroll-token "${token}" --no-start
  check "binary installed" file_exists "${root}/usr/local/bin/seagull-agent"
  check "unit installed" file_exists "${root}/etc/systemd/system/seagull-agent.service"
  check "env installed" file_exists "${root}/etc/seagull/agent.env"
  check "env is not world readable" mode_is "${root}/etc/seagull/agent.env" 600
  check "token stored" file_exists "${root}/var/lib/seagull/bootstrap.token"
  check "token is not world readable" mode_is "${root}/var/lib/seagull/bootstrap.token" 600
  check "spool directory created" dir_exists "${root}/var/lib/seagull/spool"
  check "checkpoint directory created" dir_exists "${root}/var/lib/seagull/checkpoints"
  check "checkpoint directory is private" mode_is "${root}/var/lib/seagull/checkpoints" 700
  check "authlog checkpoint path configured" file_contains "${root}/etc/seagull/agent.env" 'SEAGULL_AUTHLOG_CHECKPOINT_FILE=/var/lib/seagull/checkpoints/authlog.json'
  check "response journal directory created" dir_exists "${root}/var/lib/seagull/response-actions"
  check "response journal directory is private" mode_is "${root}/var/lib/seagull/response-actions" 700
  check "response journal path configured" file_contains "${root}/etc/seagull/agent.env" 'SEAGULL_RESPONSE_ACTION_JOURNAL_DIR=/var/lib/seagull/response-actions'
  check "runtime pki directory is private" mode_is "${root}/var/lib/seagull/pki" 700
  check "release recorded" file_contains "${root}/var/lib/seagull/agent.release" 'current=1.0.0'
  check "agent id written" file_contains "${root}/etc/seagull/agent.env" 'SEAGULL_AGENT_ID=agent-test-1'
  check "agent id was derived from the bound token" file_contains "${root}/etc/seagull/agent.env" 'SEAGULL_AGENT_ID=agent-test-1'
  check "release stores its systemd unit" file_exists "${root}/usr/local/lib/seagull/releases/1.0.0/seagull-agent.service"
  check "release stores its metadata" file_exists "${root}/usr/local/lib/seagull/releases/1.0.0/VERSION"
  refute "installed configuration carries no relative path" \
    grep -qE '^SEAGULL_[A-Z_]*_(FILE|DIR)=[^/]' "${root}/etc/seagull/agent.env"

  printf '\n::: sensor is the default profile and grants no response privileges\n'
  check "profile defaults to sensor" file_contains "${root}/etc/seagull/agent.env" 'SEAGULL_AGENT_PROFILE=sensor'
  check "dropin pins the profile" file_contains "${root}/etc/systemd/system/seagull-agent.service.d/20-seagull-profile.conf" 'SEAGULL_AGENT_PROFILE=sensor'
  check "sensor does not get CAP_KILL" file_lacks "${root}/etc/systemd/system/seagull-agent.service.d/20-seagull-profile.conf" 'CAP_KILL'
  check "sensor does not get CAP_DAC_READ_SEARCH" file_lacks "${root}/etc/systemd/system/seagull-agent.service.d/20-seagull-profile.conf" 'CAP_DAC_READ_SEARCH'
  check "sensor does not get CAP_DAC_OVERRIDE" file_lacks "${root}/etc/systemd/system/seagull-agent.service.d/20-seagull-profile.conf" 'CAP_DAC_OVERRIDE'
  check "sensor capture gets only CAP_NET_RAW" file_contains "${root}/etc/systemd/system/seagull-agent.service.d/20-seagull-profile.conf" 'CAP_NET_RAW'
  check "sensor does not get CAP_NET_ADMIN" file_lacks "${root}/etc/systemd/system/seagull-agent.service.d/20-seagull-profile.conf" 'CAP_NET_ADMIN'
  check "sensor keeps the strict filesystem sandbox" file_contains "${root}/etc/systemd/system/seagull-agent.service.d/20-seagull-profile.conf" 'ProtectSystem=strict'
  check "sensor keeps home directories inaccessible" file_contains "${root}/etc/systemd/system/seagull-agent.service.d/20-seagull-profile.conf" 'ProtectHome=true'
  check "sensor keeps a private temporary directory" file_contains "${root}/etc/systemd/system/seagull-agent.service.d/20-seagull-profile.conf" 'PrivateTmp=true'
  check "unit grants no capabilities by default" file_contains "${root}/etc/systemd/system/seagull-agent.service" 'AmbientCapabilities='

  printf '\n::: idempotent reinstall preserves identity\n'
  printf 'persisted-identity' > "${root}/var/lib/seagull/agent.identity.json"
  printf 'persisted-credential' > "${root}/var/lib/seagull/agent.credential"
  mkdir -p "${root}/var/lib/seagull/spool"
  printf 'queued' > "${root}/var/lib/seagull/spool/pending.json"
  printf 'terminal-result' > "${root}/var/lib/seagull/response-actions/00000000000000000001.json"
  printf 'local-override' >> "${root}/etc/seagull/agent.env"
  check "reinstall succeeds" env SEAGULL_INSTALL_ROOT="${root}" bash "${pkg1}/install.sh" --agent-id agent-test-1 --no-start
  check "identity preserved" file_contains "${root}/var/lib/seagull/agent.identity.json" 'persisted-identity'
  check "credential preserved" file_contains "${root}/var/lib/seagull/agent.credential" 'persisted-credential'
  check "spool preserved" file_exists "${root}/var/lib/seagull/spool/pending.json"
  check "response result preserved" file_exists "${root}/var/lib/seagull/response-actions/00000000000000000001.json"
  check "local configuration preserved" file_contains "${root}/etc/seagull/agent.env" 'local-override'

  printf '\n::: managed profile grants only the privileges it needs\n'
  check "managed install succeeds" env SEAGULL_INSTALL_ROOT="${root}" bash "${pkg1}/install.sh" --profile managed --no-start
  local dropin="${root}/etc/systemd/system/seagull-agent.service.d/20-seagull-profile.conf"
  check "managed gets CAP_KILL" file_contains "${dropin}" 'CAP_KILL'
  check "managed gets CAP_NET_ADMIN" file_contains "${dropin}" 'CAP_NET_ADMIN'
  check "managed gets CAP_DAC_OVERRIDE" file_contains "${dropin}" 'CAP_DAC_OVERRIDE'
  check "managed can quarantine outside read-only system paths" file_contains "${dropin}" 'ProtectSystem=full'
  check "managed can quarantine from home directories" file_contains "${dropin}" 'ProtectHome=false'
  check "managed can quarantine from the host temporary directory" file_contains "${dropin}" 'PrivateTmp=false'
  check "managed does not get CAP_SYS_ADMIN" file_lacks "${dropin}" 'CAP_SYS_ADMIN'
  check "managed does not get CAP_SYS_PTRACE" file_lacks "${dropin}" 'CAP_SYS_PTRACE'
  refute "arbitrary capability overrides are rejected" env SEAGULL_INSTALL_ROOT="${root}" bash "${pkg1}/install.sh" --capabilities CAP_SYS_ADMIN --no-start

  printf '\n::: upgrade\n'
  printf 'corrupt-unit' > "${root}/etc/systemd/system/seagull-agent.service"
  check "upgrade succeeds" env SEAGULL_INSTALL_ROOT="${root}" bash "${pkg2}/upgrade.sh"
  check "release advanced" file_contains "${root}/var/lib/seagull/agent.release" 'current=1.1.0'
  check "previous release recorded" file_contains "${root}/var/lib/seagull/agent.release" 'previous=1.0.0'
  check "upgraded binary reports the new version" bash -c "'${root}/usr/local/bin/seagull-agent' --version | grep -q '1.1.0'"
  check "upgrade preserved identity" file_contains "${root}/var/lib/seagull/agent.identity.json" 'persisted-identity'
  check "upgrade preserved the credential" file_contains "${root}/var/lib/seagull/agent.credential" 'persisted-credential'
  check "upgrade preserved the spool" file_exists "${root}/var/lib/seagull/spool/pending.json"
  check "upgrade preserved the response result" file_exists "${root}/var/lib/seagull/response-actions/00000000000000000001.json"
  check "upgrade preserved local configuration" file_contains "${root}/etc/seagull/agent.env" 'local-override'
  check "upgrade preserved the managed profile" file_contains "${root}/etc/seagull/agent.env" 'SEAGULL_AGENT_PROFILE=managed'
  check "old release retained for rollback" file_exists "${root}/usr/local/lib/seagull/releases/1.0.0/seagull-agent"
  check "upgrade restored the target unit" files_equal \
    "${root}/etc/systemd/system/seagull-agent.service" \
    "${root}/usr/local/lib/seagull/releases/1.1.0/seagull-agent.service"
  printf 'corrupt-binary' > "${root}/usr/local/bin/seagull-agent.corrupt"
  chmod 0755 "${root}/usr/local/bin/seagull-agent.corrupt"
  mv "${root}/usr/local/bin/seagull-agent.corrupt" "${root}/usr/local/bin/seagull-agent"
  printf 'corrupt-unit' > "${root}/etc/systemd/system/seagull-agent.service"
  check "same-version upgrade repairs active files" env SEAGULL_INSTALL_ROOT="${root}" bash "${pkg2}/upgrade.sh"
  check "same-version repair restores the binary" files_equal \
    "${root}/usr/local/bin/seagull-agent" \
    "${root}/usr/local/lib/seagull/releases/1.1.0/seagull-agent"
  check "same-version repair restores the unit" files_equal \
    "${root}/etc/systemd/system/seagull-agent.service" \
    "${root}/usr/local/lib/seagull/releases/1.1.0/seagull-agent.service"
  check "same-version repair preserves the rollback release" file_contains \
    "${root}/var/lib/seagull/agent.release" \
    'previous=1.0.0'
  refute "downgrade requires explicit authorization" env SEAGULL_INSTALL_ROOT="${root}" bash "${pkg1}/upgrade.sh"
  check "rejected downgrade kept the active release" file_contains "${root}/var/lib/seagull/agent.release" 'current=1.1.0'

  local mutated="${WORK}/mutated"
  cp -a "${pkg2}" "${mutated}"
  printf '\n[X-Seagull-Test]\nValue=changed\n' >> "${mutated}/share/systemd/seagull-agent.service"
  (
    cd "${mutated}"
    find . -type f ! -name MANIFEST.sha256 -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > MANIFEST.sha256
  )
  refute "an existing release version is immutable" env SEAGULL_INSTALL_ROOT="${root}" bash "${mutated}/install.sh" --no-start

  printf '\n::: rollback\n'
  check "rollback lists releases" bash -c "SEAGULL_INSTALL_ROOT='${root}' bash '${pkg2}/rollback.sh' --list | grep -q '1.0.0'"
  printf 'corrupt-unit' > "${root}/etc/systemd/system/seagull-agent.service"
  check "rollback succeeds" env SEAGULL_INSTALL_ROOT="${root}" bash "${pkg2}/rollback.sh"
  check "rolled back binary reports the old version" bash -c "'${root}/usr/local/bin/seagull-agent' --version | grep -q '1.0.0'"
  check "release state reflects the rollback" file_contains "${root}/var/lib/seagull/agent.release" 'current=1.0.0'
  check "rollback preserved identity" file_contains "${root}/var/lib/seagull/agent.identity.json" 'persisted-identity'
  check "rollback preserved the spool" file_exists "${root}/var/lib/seagull/spool/pending.json"
  check "rollback preserved the response result" file_exists "${root}/var/lib/seagull/response-actions/00000000000000000001.json"
  check "rollback restored the stored unit" files_equal \
    "${root}/etc/systemd/system/seagull-agent.service" \
    "${root}/usr/local/lib/seagull/releases/1.0.0/seagull-agent.service"

  printf '\n::: authorized downgrade\n'
  check "upgrade before downgrade succeeds" env SEAGULL_INSTALL_ROOT="${root}" bash "${pkg2}/upgrade.sh"
  check "authorized downgrade succeeds" env SEAGULL_INSTALL_ROOT="${root}" bash "${pkg1}/upgrade.sh" --allow-downgrade
  check "authorized downgrade activated the target" file_contains "${root}/var/lib/seagull/agent.release" 'current=1.0.0'

  printf '\n::: migration from a monorepo installation\n'
  local legacy="${WORK}/legacy"
  mkdir -p "${legacy}/etc/seagull/pki" "${legacy}/var/lib/seagull" "${legacy}/usr/local/lib/seagull" "${legacy}/etc/systemd/system"
  printf 'legacy-cert' > "${legacy}/etc/seagull/pki/agent.crt"
  printf 'legacy-key' > "${legacy}/etc/seagull/pki/agent.key"
  printf '%s\n' '-----BEGIN CERTIFICATE-----' 'legacy-ca' '-----END CERTIFICATE-----' > "${legacy}/etc/seagull/pki/root_ca.crt"
  printf 'legacy-token' > "${legacy}/etc/seagull/bootstrap.token"
  printf 'legacy-identity' > "${legacy}/var/lib/seagull/agent.identity.json"
  printf 'legacy-credential' > "${legacy}/var/lib/seagull/agent.credential"
  printf 'sync-script' > "${legacy}/usr/local/lib/seagull/seagull-agent-sync-ca.sh"
  printf 'unit' > "${legacy}/etc/systemd/system/seagull-agent-ca-sync.timer"
  {
    printf 'SEAGULL_AGENT_ID=agent-legacy-1\n'
    printf 'SEAGULL_API_URL=https://old.example.com:8444/agent\n'
    printf 'SEAGULL_TLS_CERT_FILE=/etc/seagull/pki/agent.crt\n'
    printf 'SEAGULL_TLS_KEY_FILE=/etc/seagull/pki/agent.key\n'
    printf 'SEAGULL_TLS_CA_FILE=/etc/seagull/pki/root_ca.crt\n'
    printf 'SEAGULL_TLS_CA_SOURCE_FILE=/home/nathan/seagull/secrets/tls/ca.crt\n'
  } > "${legacy}/etc/seagull/agent.env"

  check "migration install succeeds" env SEAGULL_INSTALL_ROOT="${legacy}" bash "${pkg2}/install.sh" --no-start
  check "legacy identity kept" file_contains "${legacy}/var/lib/seagull/agent.identity.json" 'legacy-identity'
  check "legacy credential kept" file_contains "${legacy}/var/lib/seagull/agent.credential" 'legacy-credential'
  check "legacy agent id kept" file_contains "${legacy}/etc/seagull/agent.env" 'SEAGULL_AGENT_ID=agent-legacy-1'
  check "legacy api url kept" file_contains "${legacy}/etc/seagull/agent.env" 'https://old.example.com:8444/agent'
  check "client certificate migrated" file_contains "${legacy}/var/lib/seagull/pki/client.crt" 'legacy-cert'
  check "client key migrated" file_contains "${legacy}/var/lib/seagull/pki/client.key" 'legacy-key'
  check "client key is private" mode_is "${legacy}/var/lib/seagull/pki/client.key" 600
  check "server CA migrated to writable runtime state" file_contains "${legacy}/var/lib/seagull/pki/server-ca.crt" 'legacy-ca'
  check "legacy server CA removed from the old location" file_absent "${legacy}/etc/seagull/pki/root_ca.crt"
  check "server CA path rewritten" file_contains "${legacy}/etc/seagull/agent.env" 'SEAGULL_TLS_CA_FILE=/var/lib/seagull/pki/server-ca.crt'
  check "legacy cert path rewritten" file_contains "${legacy}/etc/seagull/agent.env" 'SEAGULL_TLS_CERT_FILE=/var/lib/seagull/pki/client.crt'
  check "legacy cert removed from the old location" file_absent "${legacy}/etc/seagull/pki/agent.crt"
  check "legacy token migrated" file_contains "${legacy}/var/lib/seagull/bootstrap.token" 'legacy-token'
  check "response capability preserved on migration" file_contains "${legacy}/etc/seagull/agent.env" 'SEAGULL_AGENT_PROFILE=managed'
  check "repository CA sync script removed" file_absent "${legacy}/usr/local/lib/seagull/seagull-agent-sync-ca.sh"
  check "repository CA sync timer removed" file_absent "${legacy}/etc/systemd/system/seagull-agent-ca-sync.timer"
  check "repository CA source key removed" file_lacks "${legacy}/etc/seagull/agent.env" 'SEAGULL_TLS_CA_SOURCE_FILE'

  printf '\n::: interrupted migration recovery\n'
  local interrupted="${WORK}/legacy-interrupted"
  mkdir -p "${interrupted}/etc/seagull/pki" "${interrupted}/var/lib/seagull/pki"
  printf 'legacy-cert' > "${interrupted}/etc/seagull/pki/agent.crt"
  printf 'legacy-key' > "${interrupted}/etc/seagull/pki/agent.key"
  printf 'legacy-cert' > "${interrupted}/var/lib/seagull/pki/client.crt"
  {
    printf 'SEAGULL_AGENT_ID=agent-interrupted-1\n'
    printf 'SEAGULL_API_URL=https://old.example.com:8444/agent\n'
    printf 'SEAGULL_TLS_CERT_FILE=/etc/seagull/pki/agent.crt\n'
    printf 'SEAGULL_TLS_KEY_FILE=/etc/seagull/pki/agent.key\n'
  } > "${interrupted}/etc/seagull/agent.env"
  check "interrupted migration resumes" env SEAGULL_INSTALL_ROOT="${interrupted}" bash "${pkg2}/install.sh" --no-start
  check "interrupted migration preserves the certificate" file_contains "${interrupted}/var/lib/seagull/pki/client.crt" 'legacy-cert'
  check "interrupted migration restores the private key" file_contains "${interrupted}/var/lib/seagull/pki/client.key" 'legacy-key'
  check "interrupted migration removes legacy certificate material" file_absent "${interrupted}/etc/seagull/pki/agent.crt"
  check "interrupted migration removes legacy private key material" file_absent "${interrupted}/etc/seagull/pki/agent.key"

  printf '\n::: conflicting migration rejection\n'
  local conflict="${WORK}/legacy-conflict"
  mkdir -p "${conflict}/etc/seagull/pki" "${conflict}/var/lib/seagull/pki"
  printf 'legacy-cert' > "${conflict}/etc/seagull/pki/agent.crt"
  printf 'legacy-key' > "${conflict}/etc/seagull/pki/agent.key"
  printf 'different-cert' > "${conflict}/var/lib/seagull/pki/client.crt"
  {
    printf 'SEAGULL_AGENT_ID=agent-conflict-1\n'
    printf 'SEAGULL_API_URL=https://old.example.com:8444/agent\n'
  } > "${conflict}/etc/seagull/agent.env"
  refute "conflicting legacy identity is rejected" env SEAGULL_INSTALL_ROOT="${conflict}" bash "${pkg2}/install.sh" --no-start
  check "rejected migration preserves legacy certificate material" file_contains "${conflict}/etc/seagull/pki/agent.crt" 'legacy-cert'
  check "rejected migration preserves migrated certificate material" file_contains "${conflict}/var/lib/seagull/pki/client.crt" 'different-cert'

  printf '\n::: uninstall\n'
  check "uninstall succeeds" env SEAGULL_INSTALL_ROOT="${root}" bash "${pkg2}/uninstall.sh"
  check "binary removed" file_absent "${root}/usr/local/bin/seagull-agent"
  check "unit removed" file_absent "${root}/etc/systemd/system/seagull-agent.service"
  check "identity retained without purge" file_exists "${root}/var/lib/seagull/agent.identity.json"
  check "purge removes state" env SEAGULL_INSTALL_ROOT="${root}" bash "${pkg2}/uninstall.sh" --purge
  check "state directory removed" file_absent "${root}/var/lib/seagull"
  check "config directory removed" file_absent "${root}/etc/seagull"

  printf '\n%d passed, %d failed\n' "${PASS}" "${FAIL}"
  [[ "${FAIL}" -eq 0 ]]
}

main "$@"
