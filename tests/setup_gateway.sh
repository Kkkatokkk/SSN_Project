#!/bin/bash
# Настройка gateway для проекта SSN.
# Запуск: sudo bash tests/setup_gateway.sh

set -e

# ── Параметры (подставь свои) ─────────────────────────────
IFACE="ens33"                # интерфейс gateway
NFT_CONF="/etc/nftables.conf"  # путь к ruleset
# ──────────────────────────────────────────────────────────

echo "[1/3] Включаю пересылку пакетов (ip_forward)..."
sysctl -w net.ipv4.ip_forward=1

echo "[2/3] Выключаю ICMP redirects (чтобы клиент не обходил шлюз)..."
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf."$IFACE".send_redirects=0

echo "[3/3] Загружаю правила nftables из $NFT_CONF..."
if [ -f "$NFT_CONF" ]; then
    nft -f "$NFT_CONF"
else
    echo "  ⚠️  Файл $NFT_CONF не найден — пропускаю."
fi

echo
echo "── Проверка ──"
echo "ip_forward: $(sysctl -n net.ipv4.ip_forward)"
echo "send_redirects ($IFACE): $(sysctl -n net.ipv4.conf.$IFACE.send_redirects)"
echo "Правила nftables:"
nft list ruleset | head -20

echo
echo "✅ Gateway настроен."
