#!/bin/bash
# Настройка client для проекта SSN.
# Запуск: sudo bash tests/setup_client.sh

set -e

# ── Параметры (подставь свои) ─────────────────────────────
GW_IP="192.168.25.136"   # IP gateway
# ──────────────────────────────────────────────────────────

echo "[1/2] Выключаю accept_redirects..."
sysctl -w net.ipv4.conf.all.accept_redirects=0

echo "[2/2] Ставлю маршрут по умолчанию через gateway ($GW_IP)..."
ip route replace default via "$GW_IP"

echo
echo "── Проверка ──"
echo "accept_redirects: $(sysctl -n net.ipv4.conf.all.accept_redirects)"
echo "Маршрут по умолчанию:"
ip route | grep '^default'

echo
echo "✅ Client настроен."
