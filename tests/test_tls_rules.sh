#!/usr/bin/env bash
# Replays the TLS test pcaps through Suricata with only our custom rules.
# Expected: one alert for TLS 1.0, one for TLS 1.1, nothing for TLS 1.2 and 1.3.
# Run from any folder on a machine with Suricata 8.0.7 and jq.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=$(mktemp -d)
for v in tls1 tls1_1 tls1_2 tls1_3; do
  mkdir -p "$OUT/$v"
  sudo suricata -r "tests/pcap/$v.pcap" -S suricata/custom.rules -k none -l "$OUT/$v" >/dev/null 2>&1
  echo "== $v =="
  sudo jq -r 'select(.event_type=="alert") | "  ALERT: " + .alert.signature' "$OUT/$v/eve.json" | sort | uniq -c
done
