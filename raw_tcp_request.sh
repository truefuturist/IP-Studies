#!/usr/bin/env bash
# Raw HTTP/1.0 GET via bash /dev/tcp built-in — no external tools required.
# Usage: ./raw_tcp_request.sh [host] [path]

HOST="${1:-ifconfig.me}"
PATH_="${2:-/}"
PORT=80

exec 3<>"/dev/tcp/${HOST}/${PORT}"
printf "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: bash/dev-tcp\r\n\r\n" "$PATH_" "$HOST" >&3
cat <&3
exec 3>&-
