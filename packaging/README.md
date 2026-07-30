# Seagull agent package

This directory is the installed layout of a Seagull agent release. It is
self-contained: it needs no Seagull platform checkout, no Go toolchain and no
network access beyond the Seagull server itself.

## Contents

| Path | Purpose |
|---|---|
| `seagull-agent` | The agent binary |
| `install.sh` | Fresh install or reconfiguration, idempotent |
| `upgrade.sh` | Replace the running release, preserving identity, with automatic rollback |
| `rollback.sh` | Return to a previously installed release |
| `uninstall.sh` | Remove the service, optionally purging state |
| `VERSION` | Release, channel, commit, target and protocol metadata |
| `MANIFEST.sha256` | Per-file integrity manifest, verified before install |
| `share/systemd/` | The systemd unit |
| `share/env/` | The configuration template |
| `share/protocol-v1.json` | The agent/server contract this release implements |
| `lib/` | Installer libraries |

## Install

    sudo ./install.sh \
      --agent-id my-host-1 \
      --api-url https://siem.example.com:8444/agent \
      --enroll-url https://siem.example.com:8445 \
      --profile sensor \
      --enroll-token abt.my-host-1.xxxxx \
      --ca-file ./server-ca.crt

`--profile sensor` is the default and collects telemetry only. `--profile
managed` additionally allows server-dispatched response actions and is the only
profile that receives privileged Linux capabilities.

## Upgrade and rollback

    sudo ./upgrade.sh
    sudo ./rollback.sh --list
    sudo ./rollback.sh --to 1.2.3

Releases are kept under `/usr/local/lib/seagull/releases`. Identity,
credentials, spooled telemetry and `/etc/seagull/agent.env` are never touched by
an upgrade or a rollback.

## Uninstall

    sudo ./uninstall.sh            # keeps identity and configuration
    sudo ./uninstall.sh --purge    # also removes /etc/seagull and /var/lib/seagull

## Files owned by an installation

| Path | Contents |
|---|---|
| `/usr/local/bin/seagull-agent` | Active binary |
| `/usr/local/lib/seagull/releases/<version>/` | Installed releases |
| `/etc/seagull/agent.env` | Configuration, mode 0600 |
| `/etc/seagull/pki/root_ca.crt` | Server trust anchor |
| `/var/lib/seagull/agent.identity.json` | Credential and renewal tokens, mode 0600 |
| `/var/lib/seagull/pki/client.{crt,key}` | Endpoint-owned client certificate and key |
| `/var/lib/seagull/spool/` | Durable telemetry backlog |
| `/var/lib/seagull/bootstrap.token` | One-time enrollment token, consumed on first enroll |
| `/var/lib/seagull/agent.release` | Active and previous release |

The private key is generated on the endpoint and never leaves it. The server
only ever sees a certificate signing request.
