#!/bin/sh
set -eu

STAGE_DIR="${NETWATCH_TLS_STAGE_DIR:-/var/lib/netwatch/pki}"
mkdir -p "$STAGE_DIR"

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

copy_file "${NETWATCH_TLS_CA_SOURCE_FILE:-}"   "$STAGE_DIR/server-ca.crt" 0644
copy_file "${NETWATCH_TLS_CERT_SOURCE_FILE:-}" "$STAGE_DIR/tls.crt"       0644
copy_file "${NETWATCH_TLS_KEY_SOURCE_FILE:-}"  "$STAGE_DIR/tls.key"       0600

if [ -f "$STAGE_DIR/server-ca.crt" ]; then
  export NETWATCH_TLS_CA_FILE="$STAGE_DIR/server-ca.crt"
fi
if [ -f "$STAGE_DIR/tls.crt" ]; then
  export NETWATCH_TLS_CERT_FILE="$STAGE_DIR/tls.crt"
fi
if [ -f "$STAGE_DIR/tls.key" ]; then
  export NETWATCH_TLS_KEY_FILE="$STAGE_DIR/tls.key"
fi

exec /usr/local/bin/netwatch-agent