#!/usr/bin/env bash
# SSN project - test target: four TLS servers, one TLS version each.
#   4430 -> TLS 1.0 only  (should be blocked by the firewall)
#   4431 -> TLS 1.1 only  (should be blocked)
#   4432 -> TLS 1.2 only  (should pass)
#   4433 -> TLS 1.3 only  (should pass)
# Usage: ./oldtls.sh start | stop | status
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
CERT="$DIR/oldtls-cert.pem"
KEY="$DIR/oldtls-key.pem"
declare -A PORTS=([4430]=tls1 [4431]=tls1_1 [4432]=tls1_2 [4433]=tls1_3)

status() {
  ss -ltn | grep -E ':443[0-3] ' || echo "no servers running"
}

start() {
  if [[ ! -f "$CERT" ]]; then
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CERT" \
      -days 30 -subj "/CN=oldtls.test" 2>/dev/null
  fi
  for port in "${!PORTS[@]}"; do
    nohup openssl s_server -accept "$port" -cert "$CERT" -key "$KEY" \
      -"${PORTS[$port]}" -cipher 'DEFAULT:@SECLEVEL=0' -www >/dev/null 2>&1 &
  done
  sleep 1
  status
}

stop() {
  pkill -f 'openssl s_server -accept 443[0-3]' || true
  echo "stopped"
}

case "${1:-}" in
  start)  start ;;
  stop)   stop ;;
  status) status ;;
  *) echo "Usage: $0 start|stop|status"; exit 1 ;;
esac
