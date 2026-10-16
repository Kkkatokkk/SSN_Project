#!/usr/bin/env python3
"""Generate Suricata rules that detect connections to public Tor relays.

The relay list is merged from several sources, because each list alone is
incomplete:
  - a public GitHub mirror of the Tor relay list (downloaded every run);
  - extra local files given as arguments (for example dan.me.uk or the IPs
    extracted from the ET Open Tor rules), one IP per line.
The official Tor Project service (Onionoo) is not reachable from our network.

Usage: python3 tor_rules.py [extra_list.txt ...]
"""
import ipaddress
import re
import sys
import urllib.request
from datetime import datetime, timezone

URL_SOURCES = [
    "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-nodes.lst",
]
GROUP_SIZE = 100
SID_START = 1001000
OUT_RULES = "tor.rules"
OUT_LIST = "tor-relays.txt"
IPV4_RE = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s*$")


def parse_ipv4(text):
    ips = set()
    for line in text.splitlines():
        m = IPV4_RE.match(line)
        if not m:
            continue
        try:
            ip = ipaddress.ip_address(m.group(1))
        except ValueError:
            continue
        if ip.version == 4:
            ips.add(ip)
    return ips


def main():
    sources = {}
    for url in URL_SOURCES:
        with urllib.request.urlopen(url, timeout=30) as resp:
            sources[url] = parse_ipv4(resp.read().decode())
    for path in sys.argv[1:]:
        with open(path) as f:
            sources[path] = parse_ipv4(f.read())

    all_ips = sorted(set().union(*sources.values()))
    if not all_ips:
        sys.exit("No IPv4 addresses found - check the sources")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    groups = [all_ips[i:i + GROUP_SIZE] for i in range(0, len(all_ips), GROUP_SIZE)]

    with open(OUT_RULES, "w") as f:
        f.write(f"# SSN project - Tor relay detection (generated {now})\n")
        for name, ips in sources.items():
            f.write(f"# Source: {name} ({len(ips)} IPv4)\n")
        f.write(f"# Total: {len(all_ips)} unique IPv4 relays in {len(groups)} rules\n")
        for n, group in enumerate(groups, start=1):
            iplist = ",".join(str(ip) for ip in group)
            f.write(
                f"alert tcp $HOME_NET any -> [{iplist}] any "
                f'(msg:"SSN Tor relay connection attempt group {n}"; '
                f"flow:to_server; flags:S; "
                f"threshold:type limit, track by_src, seconds 60, count 1; "
                f"classtype:policy-violation; sid:{SID_START + n}; rev:2;)\n"
            )

    with open(OUT_LIST, "w") as f:
        f.write(f"# Tor relays, generated {now}, {len(sources)} sources\n")
        f.writelines(f"{ip}\n" for ip in all_ips)

    for name, ips in sources.items():
        print(f"{len(ips):6d} IPv4 from {name}")
    print(f"{len(all_ips):6d} unique IPv4 relays -> {len(groups)} rules in {OUT_RULES}")


if __name__ == "__main__":
    main()
