#!/usr/bin/env bash
# SSN project - test target behind the gateway.
# Creates a network namespace "target" connected to the gateway with a veth pair.
# For the client it looks like an external server: its traffic goes through the
# forward chain, nftables and Suricata. Inside the namespace oldtls.sh starts
# TLS 1.0/1.1/1.2/1.3 servers on ports 4430-4433.
#   gateway side: veth-gw 10.200.0.1/24    target side: veth-tg 10.200.0.2/24
# Usage (on the gateway): sudo ./target_netns.sh up | down
set -euo pipefail
NS=target
GW_IF=veth-gw
NS_IF=veth-tg
GW_ADDR=10.200.0.1
NS_ADDR=10.200.0.2
DIR="$(cd "$(dirname "$0")" && pwd)"

up() {
  ip netns add "$NS"
  ip link add "$GW_IF" type veth peer name "$NS_IF"
  ip link set "$NS_IF" netns "$NS"
  ip addr add "$GW_ADDR/24" dev "$GW_IF"
  ip link set "$GW_IF" up
  ip netns exec "$NS" ip addr add "$NS_ADDR/24" dev "$NS_IF"
  ip netns exec "$NS" ip link set "$NS_IF" up
  ip netns exec "$NS" ip link set lo up
  ip netns exec "$NS" ip route add default via "$GW_ADDR"
  ip netns exec "$NS" "$DIR/oldtls.sh" start
}

down() {
  ip netns exec "$NS" "$DIR/oldtls.sh" stop 2>/dev/null || true
  ip netns del "$NS" 2>/dev/null || true
  ip link del "$GW_IF" 2>/dev/null || true
  echo "target removed"
}

case "${1:-}" in
  up)   up ;;
  down) down ;;
  *) echo "Usage: sudo $0 up|down"; exit 1 ;;
esac
