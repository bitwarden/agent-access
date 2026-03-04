#!/bin/sh
set -e

cleanup() {
    kill "$AP_PROXY_PID" "$CADDY_PID" 2>/dev/null || true
    wait "$AP_PROXY_PID" "$CADDY_PID" 2>/dev/null || true
}
trap cleanup EXIT
trap 'cleanup; exit 0' TERM INT

ap-proxy &
AP_PROXY_PID=$!

caddy run --config /etc/caddy/Caddyfile --adapter caddyfile &
CADDY_PID=$!

while kill -0 "$AP_PROXY_PID" 2>/dev/null && kill -0 "$CADDY_PID" 2>/dev/null; do
    sleep 1
done

exit 1
