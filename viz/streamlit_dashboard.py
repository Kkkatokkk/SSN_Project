#!/usr/bin/env python3
"""SSN project - firewall dashboard.

Shows Suricata alerts (old TLS, Tor) and TLS versions from eve.json, and
nftables drops from the kernel log. Refreshes itself every few seconds.

Run:
  streamlit run dashboard.py -- --eve /var/log/suricata/eve.json --nft journal
  --nft can be a file with `journalctl -k -o json` lines, or "journal" to read
  the live kernel log. Without --nft only the Suricata part is shown.
"""
import argparse
import json
import re
import subprocess
import time

import pandas as pd
import streamlit as st

NFT_RE = re.compile(
    r"(NFT-[A-Z]+-DROP):.*?SRC=(\S+) DST=(\S+).*?PROTO=(\S+)(?:.*?DPT=(\d+))?"
)


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--eve", default="/var/log/suricata/eve.json")
    p.add_argument("--nft", default=None)
    return p.parse_args()


def tls_name(version):
    """Suricata writes versions differently (TLSv1, TLS 1.1...), make them equal."""
    m = re.search(r"(\d)(?:\.(\d))?", str(version))
    if not m:
        return str(version)
    prefix = "SSL" if str(version).upper().startswith("SSL") else "TLS"
    return f"{prefix} {m.group(1)}.{m.group(2) or '0'}"


def rule_type(signature):
    if "Old TLS" in signature:
        return "Old TLS"
    if "Tor" in signature:
        return "Tor"
    return "Other"


def load_eve(path):
    alerts, tls = [], []
    try:
        with open(path) as f:
            for line in f:
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if e.get("event_type") == "alert":
                    a = e.get("alert", {})
                    alerts.append({
                        "time": e.get("timestamp"),
                        "rule": a.get("signature", ""),
                        "action": a.get("action", ""),
                        "src_ip": e.get("src_ip"),
                        "dest_ip": e.get("dest_ip"),
                        "dest_port": e.get("dest_port"),
                    })
                elif e.get("event_type") == "tls":
                    t = e.get("tls", {})
                    tls.append({
                        "time": e.get("timestamp"),
                        "version": tls_name(t.get("version", "unknown")),
                        "sni": t.get("sni", ""),
                    })
    except FileNotFoundError:
        st.error(f"eve.json not found: {path}")
    alerts = pd.DataFrame(alerts, columns=["time", "rule", "action", "src_ip", "dest_ip", "dest_port"])
    tls = pd.DataFrame(tls, columns=["time", "version", "sni"])
    for df in (alerts, tls):
        df["time"] = pd.to_datetime(df["time"], utc=True, errors="coerce")
    alerts["type"] = alerts["rule"].map(rule_type)
    return alerts, tls


def load_nft(source):
    if source is None:
        return None
    if source == "journal":
        text = subprocess.run(
            ["journalctl", "-k", "-o", "json", "--since", "today"],
            capture_output=True, text=True,
        ).stdout
    else:
        try:
            with open(source) as f:
                text = f.read()
        except FileNotFoundError:
            st.error(f"nftables log not found: {source}")
            return None
    rows = []
    for line in text.splitlines():
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        msg = e.get("MESSAGE")
        if not isinstance(msg, str):
            continue
        m = NFT_RE.search(msg)
        if not m:
            continue
        rows.append({
            "time": pd.to_datetime(int(e.get("__REALTIME_TIMESTAMP", 0)), unit="us", utc=True),
            "prefix": m.group(1),
            "src": m.group(2),
            "dst": m.group(3),
            "proto": m.group(4),
            "dport": m.group(5) or "-",
        })
    return pd.DataFrame(rows, columns=["time", "prefix", "src", "dst", "proto", "dport"])


args = parse_args()
st.set_page_config(page_title="SSN Firewall Dashboard", layout="wide")
st.title("Stateful firewall with application-aware rules")

auto = st.sidebar.checkbox("Auto-refresh", value=True)
interval = st.sidebar.slider("Refresh every (seconds)", 2, 60, 5)
st.sidebar.caption(f"eve.json: {args.eve}")
st.sidebar.caption(f"nftables log: {args.nft or 'not used'}")

alerts, tls = load_eve(args.eve)
nft = load_nft(args.nft)

k1, k2, k3, k4 = st.columns(4)
k1.metric("Suricata alerts", len(alerts))
k2.metric("Blocked by Suricata", int((alerts["action"] == "blocked").sum()))
k3.metric("TLS connections seen", len(tls))
k4.metric("nftables drops", "-" if nft is None else len(nft))

c1, c2 = st.columns(2)
with c1:
    st.subheader("Alerts by rule type")
    if alerts.empty:
        st.info("No alerts yet")
    else:
        st.bar_chart(alerts["type"].value_counts())
with c2:
    st.subheader("TLS versions seen by Suricata")
    if tls.empty:
        st.info("No TLS events yet")
    else:
        st.bar_chart(tls["version"].value_counts().sort_index())

st.subheader("Alerts over time (per minute)")
if alerts.empty:
    st.info("No alerts yet")
else:
    timeline = (
        alerts.dropna(subset=["time"])
        .groupby([pd.Grouper(key="time", freq="1min"), "type"])
        .size()
        .unstack(fill_value=0)
    )
    st.line_chart(timeline)

c3, c4 = st.columns(2)
with c3:
    st.subheader("Top destinations in alerts")
    if alerts.empty:
        st.info("No alerts yet")
    else:
        top = (
            alerts.groupby(["dest_ip", "dest_port", "type"])
            .size()
            .reset_index(name="alerts")
            .sort_values("alerts", ascending=False)
            .head(10)
        )
        st.dataframe(top, hide_index=True, use_container_width=True)
with c4:
    st.subheader("nftables drops")
    if nft is None:
        st.info("nftables log not connected (--nft)")
    elif nft.empty:
        st.info("No drops yet")
    else:
        st.bar_chart(nft.groupby(["prefix", "dport"]).size().unstack(fill_value=0))

st.subheader("Latest alerts")
if alerts.empty:
    st.info("No alerts yet")
else:
    st.dataframe(
        alerts.sort_values("time", ascending=False).head(20),
        hide_index=True, use_container_width=True,
    )

if auto:
    time.sleep(interval)
    st.rerun()
