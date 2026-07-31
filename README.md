# Seagull Agent

[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
[![Language](https://img.shields.io/badge/language-Go%201.25%2B-00ADD8.svg)](go.mod)
[![Platform](https://img.shields.io/badge/platform-Linux%20systemd-FCC624.svg)](packaging/systemd/seagull-agent.service)
[![Protocol](https://img.shields.io/badge/protocol-v1-00A6A6.svg)](protocol/schema/protocol-v1.json)
[![Platform repo](https://img.shields.io/badge/platform-Seagull-4B32C3.svg)](https://github.com/dynasmon/Seagull)

Seagull Agent is the endpoint telemetry and managed-response component of the
[Seagull](https://github.com/dynasmon/Seagull) security platform. This repository
is the authoritative agent product: it builds, tests, packages, installs,
upgrades, rolls back, and releases without a Seagull platform checkout.

The agent owns its identity, private key, remote configuration, delivery backlog,
collector checkpoints, and response-action journal. The platform owns enrollment
authorization, certificate issuance, authentication, ingestion, analytics, fleet
policy, and response orchestration.

## Agent capabilities

Collectors are selected with `SEAGULL_SOURCES`. Ten are available:
`authlog`, `proc`, `proc_exec`, `fim`, `scan`, `ddos`, `l7`, `lateral`,
`syscollector`, and `vuln`.

### Process and network activity

`proc` samples `/proc/net/tcp{,6}` into connection flows. `proc_exec` watches
process execution with executable hashing, parent lineage, and detection of
remote-fetch-to-shell and reverse-shell command patterns.

### Authentication monitoring

`authlog` tails `auth.log` or `secure` and emits SSH authentication outcomes and
`sudo` command events, with a durable checkpoint so a restart neither loses nor
duplicates records.

### File integrity monitoring

`fim` walks watched paths, hashes contents, and reports creations,
modifications, deletions, and renames. Changes to systemd units, cron entries,
and `authorized_keys` are classified as distinct persistence signals.

### Network protocol intelligence

`l7` extracts HTTP, DNS, and TLS metadata from captured traffic. `scan` detects
port-scan probes and summarizes campaigns. `lateral` identifies lateral-movement
connections in either PCAP or `/proc` mode.

### Denial-of-service detection

`ddos` maintains traffic windows with an EWMA baseline, port entropy, and source
cardinality estimation to score volumetric and application-layer floods under
backpressure.

### Inventory and vulnerability context

`syscollector` reports OS details and installed packages from dpkg, rpm, or apk.
`vuln` queries OSV in batches, scores findings with CVSS, infers ecosystems, and
correlates host exposure.

### Durable delivery

Batches are persisted before transmission and retained until the server confirms
durable acceptance. The spool enforces size, age, and item limits, applies
jittered backoff, accounts for loss, and survives restarts and prolonged server
outages. A protocol incompatibility or a rejected payload is never queued for
retry.

### Managed response

In the `managed` profile the agent polls for actions, stages them through a
transactional journal for idempotent execution, and reports results. It advertises
only the actions it can actually perform, and refuses anything outside its local
policy regardless of server intent.

## Supported systems

| Operating system | Architectures |
|---|---|
| Debian 12 with systemd | `amd64`, `arm64` |
| Ubuntu 22.04 and 24.04 with systemd | `amd64`, `arm64` |

Release binaries link dynamically to libpcap. Install `ca-certificates`,
systemd, and `libpcap0.8` — Ubuntu 24.04 uses `libpcap0.8t64`. The target host
needs neither Go, Git, nor either Seagull repository.

## Verify a release

Always install an explicit version. Never install from a branch.

```bash
VERSION=0.1.0
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

The signature is bound to this repository's release workflow at that exact tag,
so verification fails if either the artifact or its provenance is substituted.
Every release also carries a CycloneDX SBOM per architecture and GitHub build
provenance, and each package contains a `MANIFEST.sha256` that the installer
checks before touching the host.

## Install

Obtain a single-use, agent-bound enrollment token from Seagull fleet onboarding.
The private key is generated on the endpoint and never leaves it — the agent
sends only a certificate signing request.

```bash
tar xzf "seagull-agent_${VERSION}_linux_${ARCH}.tar.gz"
cd "seagull-agent_${VERSION}_linux_${ARCH}"

sudo ./install.sh \
  --agent-id endpoint-001 \
  --api-url https://siem.example.com:8444/agent \
  --enroll-url https://siem.example.com:8445 \
  --profile sensor \
  --prompt-enroll-token
```

```text
[seagull-agent] package integrity verified
[seagull-agent] created service group seagull
[seagull-agent] created service user seagull
[seagull-agent] profile sensor granted capabilities: CAP_NET_RAW
[seagull-agent] installed seagull-agent 0.1.0 (profile: sensor)
```

When onboarding reports that the platform's trust anchor is required, download it
and pass `--ca-file ./server-ca.crt`. Subsequent enrollment and renewal responses
rotate that anchor automatically.

The installer is idempotent: re-running the same release preserves identity,
credentials, certificates, local policy, remote configuration, queued telemetry,
and response results.

## Security profiles

`sensor` is the default. It collects and sends telemetry, and never polls,
stages, or executes response actions. Remote configuration cannot elevate it.

`managed` is an explicit local opt-in. It enables audited response actions and
grants only the Linux capabilities the selected collectors and profile require.
Program execution stays disabled unless it is enabled locally together with a
command allowlist.

Profiles change only through a verified package installation:

```bash
sudo ./install.sh --profile managed
```

## Upgrade and rollback

Verify and extract the target release, then:

```bash
sudo ./upgrade.sh
```

An upgrade activates an immutable local release and preserves all runtime state.
If the new service fails health validation, the previous binary and unit are
restored automatically. Downgrades require `--allow-downgrade`.

```bash
sudo ./rollback.sh --list
sudo ./rollback.sh --to 0.1.0
```

## Uninstall

```bash
sudo ./uninstall.sh          # keeps identity and queued data
sudo ./uninstall.sh --purge  # removes everything
```

`--purge` permanently deletes `/etc/seagull` and `/var/lib/seagull`, including
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

The systemd unit runs as a dedicated `seagull` account with a read-only host
filesystem, a bounded capability set, and write access only to agent-owned state.

## Compatibility

The versioned contract is
[`protocol/schema/protocol-v1.json`](protocol/schema/protocol-v1.json); the
independent release window is
[`protocol/schema/compatibility.json`](protocol/schema/compatibility.json).
Enrollment and heartbeat negotiate the protocol and event-schema ranges before
collectors start, and unsupported combinations fail explicitly rather than
degrading silently.

Unknown optional response fields and unrecognized capabilities are ignored.
Unsupported protocol versions, stale configuration revisions, and locally
forbidden capabilities are rejected. A server upgrade never requires upgrading
every agent, and an agent security update never requires redeploying the server.

## Build and test

Requires Go 1.25 or newer, a C compiler, and libpcap headers. libpcap makes cgo
mandatory — the agent cannot be built with `CGO_ENABLED=0`. Release CI uses Go
1.26.5.

```bash
sudo apt-get install gcc libpcap-dev
make verify
make vulncheck
make package TARGETS=linux/amd64
```

`make verify` runs formatting, dependency verification, shell and workflow lint,
static analysis, unit tests, race tests, contract tests, integration tests, and
the full install, upgrade, rollback, migration, and uninstall suite against a
staged root.

## Security

Report vulnerabilities through this repository's private vulnerability reporting
in the Security tab. Include the affected version, deployment profile,
reproduction steps, and impact. Never attach credentials, enrollment tokens,
private keys, or endpoint state to a public issue.

## License

Seagull Agent is licensed under the [GNU General Public License v3.0](LICENSE).
