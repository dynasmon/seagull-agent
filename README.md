# Seagull Agent

Seagull Agent is the endpoint telemetry and managed-response component of the
Seagull security platform. This repository is the authoritative agent product:
it builds, tests, packages, installs, upgrades, rolls back, and releases without
a Seagull platform source checkout.

The agent maintains its own identity, private key, remote configuration,
delivery backlog, authentication-log checkpoint, and response-action journal. The
platform remains responsible for enrollment authorization, certificate
issuance, authentication, ingestion, analytics, fleet policy, and response
orchestration.

## Supported systems

Official releases are validated on:

| Operating system | Architectures |
|---|---|
| Debian 12 with systemd | `amd64`, `arm64` |
| Ubuntu 22.04 and 24.04 with systemd | `amd64`, `arm64` |

Release artifacts dynamically link to libpcap. Install `ca-certificates`,
systemd, and `libpcap0.8` on Debian 12 or Ubuntu 22.04. Ubuntu 24.04 uses
`libpcap0.8t64`. The target host does not need Go, Git, or either Seagull
repository.

## Verify a release

Set an explicit version and architecture. Never install an artifact from an
unversioned branch.

```bash
VERSION=1.2.3
ARCH=amd64
BASE="https://github.com/dynasmon/seagull-agent/releases/download/v${VERSION}"

curl --fail --location --remote-name "${BASE}/seagull-agent_${VERSION}_linux_${ARCH}.tar.gz"
curl --fail --location --remote-name "${BASE}/SHA256SUMS"
curl --fail --location --remote-name "${BASE}/SHA256SUMS.sig"
curl --fail --location --remote-name "${BASE}/SHA256SUMS.pem"

cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature SHA256SUMS.sig \
  --certificate-identity "https://github.com/dynasmon/seagull-agent/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  SHA256SUMS

sha256sum --ignore-missing --check SHA256SUMS
```

GitHub build provenance is attached to every released tarball and CycloneDX
SBOM. The package also contains `MANIFEST.sha256`, which the installer verifies
before changing the host.

## Install

Obtain a one-time, agent-bound enrollment token and the supported agent version
from Seagull fleet onboarding. The private key is generated locally during
enrollment and never leaves the endpoint.

```bash
tar xzf "seagull-agent_${VERSION}_linux_${ARCH}.tar.gz"
cd "seagull-agent_${VERSION}_linux_${ARCH}"

sudo ./install.sh \
  --api-url https://siem.example.com:8444/agent \
  --enroll-url https://siem.example.com:8445 \
  --agent-id endpoint-001 \
  --prompt-enroll-token \
  --ca-file ./server-ca.crt \
  --profile sensor
```

The installer is idempotent. Re-running the same release preserves identity,
credentials, certificates, local policy, remote configuration, queued
telemetry, and response results.

## Security profiles

`sensor` is the default. It collects and sends telemetry but never polls,
stages, or executes response actions. A remote configuration cannot elevate it.

`managed` is an explicit local opt-in. It enables audited response actions and
installs only the Linux capabilities required by the selected collectors and
profile. Shell execution remains disabled unless it is enabled locally with a
command allowlist.

Change profiles through a verified package installation:

```bash
sudo ./install.sh --profile managed
```

## Upgrade and rollback

Download and verify the target release, extract it, then run:

```bash
sudo ./upgrade.sh
```

An upgrade activates an immutable local release and preserves all runtime
state. It automatically restores the previous binary and systemd unit when the
new service fails its health validation. Downgrades require the explicit
`--allow-downgrade` option.

List and restore retained releases:

```bash
sudo ./rollback.sh --list
sudo ./rollback.sh --to 1.2.2
```

## Uninstall

The default uninstall keeps identity and queued data for a later reinstall.

```bash
sudo ./uninstall.sh
sudo ./uninstall.sh --purge
```

`--purge` permanently removes `/etc/seagull` and `/var/lib/seagull`, including
the endpoint identity, private key, credentials, telemetry backlog, and
response-action journal.

## Runtime state

| Path | Purpose |
|---|---|
| `/etc/seagull/agent.env` | Root-owned local configuration |
| `/var/lib/seagull/agent.identity.json` | Credential and renewal state |
| `/var/lib/seagull/pki/` | Endpoint key, certificate, and rotatable server CA |
| `/var/lib/seagull/agent.config.json` | Last accepted remote configuration |
| `/var/lib/seagull/spool/` | Durable telemetry batches and delivery counters |
| `/var/lib/seagull/checkpoints/` | Durable collector progress |
| `/var/lib/seagull/response-actions/` | Transactional managed-response journal |
| `/usr/local/lib/seagull/releases/` | Immutable installed releases |

The systemd unit uses a dedicated `seagull` account, a read-only host
filesystem, a bounded capability set, and writable access only to agent-owned
state and logs.

## Compatibility

The versioned contract is
[`protocol/schema/protocol-v1.json`](protocol/schema/protocol-v1.json), and the
independent release window is
[`protocol/schema/compatibility.json`](protocol/schema/compatibility.json).
Enrollment and heartbeat negotiate protocol and event schema ranges before
collectors start. Unsupported combinations fail explicitly and safely.

The agent retains a delivery batch until the server confirms complete durable
acceptance. Unknown optional response fields and capabilities are ignored;
unsupported protocol versions, stale configuration revisions, and locally
forbidden capabilities are rejected.

## Develop

Development requires Go 1.25 or newer, a C compiler, and libpcap headers.
Release CI uses Go 1.26.5.

```bash
sudo apt-get install gcc libpcap-dev
go mod download
make verify
make vulncheck
make package TARGETS=linux/amd64
```

`make verify` runs formatting checks, dependency verification, static analysis,
unit tests, race tests, contract tests, integration tests, and the complete
install, upgrade, rollback, migration, and uninstall suite.

## Security

Report vulnerabilities through the repository's private security advisory
workflow. Do not disclose credentials, enrollment tokens, private keys, or
endpoint state in a public issue. See [SECURITY.md](SECURITY.md).

Seagull Agent is licensed under GPL-3.0.
