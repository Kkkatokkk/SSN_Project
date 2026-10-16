#!/usr/bin/env bash
# SSN project - test scenarios, run on the client.
# S2 (unsolicited incoming connection) is run separately on the gateway.
# Usage: ./scenarios_client.sh [target_ip]
TARGET="${1:-10.200.0.2}"
RELAY="193.23.244.244"   # Tor directory authority, present in tor.rules

echo "== S1: normal HTTPS (should pass) =="
curl -s -o /dev/null --max-time 10 -w 'example.com: HTTP %{http_code}\n' https://example.com || echo "example.com: FAILED"

echo "== S3: TLS versions on the test target (1.0/1.1 blocked, 1.2/1.3 pass) =="
for t in "4430 1.0" "4431 1.1" "4432 1.2" "4433 1.3"; do
  set -- $t
  printf 'port %s, TLS %s: ' "$1" "$2"
  curl -sk --max-time 5 --tlsv$2 --tls-max $2 --ciphers 'DEFAULT:@SECLEVEL=0' \
    -o /dev/null -w 'HTTP %{http_code}\n' "https://$TARGET:$1/" || echo "no answer (blocked?)"
done

echo "== S4: connection attempt to a Tor relay ($RELAY) =="
if nc -z -w 5 "$RELAY" 443; then echo "CONNECTED - not blocked"; else echo "no connection (check eve.json for a drop)"; fi

echo "== S5: TLS handshake time to example.com, 20 runs =="
for i in $(seq 1 20); do
  curl -s -o /dev/null --max-time 10 -w '%{time_appconnect}\n' https://example.com
done | awk '{s+=$1; n++; print} END {if (n) printf "avg = %.6f s (%d runs)\n", s/n, n}'
