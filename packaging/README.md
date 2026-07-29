# Seagull Agent

Standalone install package for the Seagull endpoint and network agent. Everything
needed to install, enroll, upgrade and remove the agent is in this directory — the
Seagull server repository is not required on the target host, and neither are Go,
libpcap headers or a build toolchain.

## Package contents

| File | Purpose |
| --- | --- |
| `seagull-agent` | Static agent binary for one OS/architecture |
| `install.sh` | Installs the binary, systemd unit, environment file and enrollment material |
| `uninstall.sh` | Stops and removes the service; keeps identity unless `--purge` |
| `seagull-agent.service` | systemd unit (hardened, no inbound listener) |
| `seagull-agent.env.example` | Environment template written to `/etc/seagull/agent.env` on first install |
| `lib/env-util.sh` | Helpers used by the installer to edit the environment file idempotently |
| `VERSION` | Version, channel, commit, build date and wire protocol version |

Verify the download before installing:

```
sha256sum -c SHA256SUMS --ignore-missing
```

The only runtime dependency is libpcap, used for passive capture
(`apt install libpcap0.8`, `dnf install libpcap`, `apk add libpcap`). Packages
built with `--static` have no external dependency at all. The installer checks
this before touching the system and stops with the missing library named.

## Install and enroll

Mint an enrollment token on the server (Agents view or
`POST /api/agents/{agent_id}/bootstrap-token`), then run on the endpoint:

```
sudo ./install.sh \
  --agent-id web-01 \
  --api-url https://siem.example.com:8444/agent \
  --enroll-url https://siem.example.com:8445 \
  --ca-file ./server-ca.crt \
  --enroll-token abt.web-01.<secret>
```

The agent generates its own private key on the host, sends only a certificate
signing request, and receives a client certificate bound to its agent id. The
private key never leaves the endpoint and is never transmitted to the server.

`--ca-file` is only needed when the server uses a private certificate authority;
omit it to use the system trust store. `--tls-server-name` overrides the expected
certificate name when the URL host differs from the certificate subject.

The enrollment token is single-use and short-lived. It is consumed at first
contact and replaced by a long-lived credential plus a client certificate, both
stored under `/var/lib/seagull` with owner-only permissions.

## Security profiles

`--profile sensor` (default) collects telemetry only. The server refuses to queue
response actions for sensor agents and the agent refuses to execute them, so a
sensor install cannot be used to run commands on the endpoint.

`--profile managed` additionally allows server-dispatched response actions
(process kill, outbound IP block, file quarantine, triage collection). The profile
is recorded server-side at enrollment; an agent can drop to a more restrictive
profile on its own, but promoting it requires an administrator.

## Runtime layout

| Path | Contents |
| --- | --- |
| `/usr/local/bin/seagull-agent` | Binary |
| `/etc/seagull/agent.env` | Configuration (mode 0600) |
| `/etc/seagull/pki/root_ca.crt` | Trusted server CA, when supplied |
| `/var/lib/seagull/pki/` | Agent private key and client certificate |
| `/var/lib/seagull/agent.identity.json` | Credential and renewal-token state |
| `/var/lib/seagull/spool/` | Telemetry spooled while the server is unreachable |
| `/var/lib/seagull/quarantine/` | Files quarantined by response actions |

The agent opens no inbound port. All traffic is outbound to the two server URLs.

## Upgrade and rollback

Install a newer package over the existing one; the environment file, identity
state, certificate and spool are preserved:

```
sudo ./install.sh --binary ./seagull-agent
```

Rollback is the same operation with an older package. Agent and server releases
move independently within the supported wire protocol window: the server reports
its accepted range and rejects an agent outside it with HTTP 426, which is visible
in the agent log as `agent_protocol_unsupported`.

## Durability

When the server is unreachable, event, inventory and vulnerability batches are
written to the spool directory and replayed on reconnect. Each batch carries a
stable identifier, so a replayed batch is recognised by the server and is not
ingested twice. Retention is bounded by `SEAGULL_AGENT_SPOOL_MAX_BYTES` and
`SEAGULL_AGENT_SPOOL_MAX_AGE`; the oldest batches are dropped first when a limit is
reached.

## Operations

```
systemctl status seagull-agent
journalctl -u seagull-agent -f
seagull-agent --version
```

## Removal

```
sudo ./uninstall.sh            # keeps identity and configuration
sudo ./uninstall.sh --purge    # also removes /etc/seagull and /var/lib/seagull
```
