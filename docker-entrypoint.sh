#!/bin/sh
set -eu

CREDENTIAL_FILE="${SEAGULL_AGENT_CREDENTIAL_FILE:-/var/lib/seagull/agent.credential}"
mkdir -p "$(dirname "$CREDENTIAL_FILE")"

copy_file() {
  src="$1"
  dst="$2"
  mode="$3"

  if [ -z "$src" ]; then
    return 0
  fi

  if [ ! -r "$src" ]; then
    echo "[entrypoint] unreadable file: $src" >&2
    exit 1
  fi

  install -m "$mode" "$src" "$dst"
}

copy_file "${SEAGULL_AGENT_CREDENTIAL_SOURCE_FILE:-}" "$CREDENTIAL_FILE" 0600

exec /usr/local/bin/seagull-agent
