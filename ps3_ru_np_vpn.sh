#!/system/bin/sh
# ps3_ru_np_vpn.sh — обвязка DNAT + маркировки + DNS-прокси
# Запуск:  su -c 'sh /data/data/com.termux/files/home/ps3_ru_np_vpn.sh'

# ===== ЖЁСТКО ЗАШИТЫЕ TERMUX-ПУТИ =====
# (su сбрасывает $HOME и $PATH, поэтому нельзя использовать ~ и относительные пути)
TERMUX_PREFIX=/data/data/com.termux/files/usr
TERMUX_HOME=/data/data/com.termux/files/home
export PATH="$TERMUX_PREFIX/bin:/system/bin:/system/xbin:$PATH"

PROXY="$TERMUX_HOME/ps3_dns_proxy.py"
PYTHON="$TERMUX_PREFIX/bin/python3"

# ===== КОНФИГУРАЦИЯ =====
PS3_IP=10.138.154.77
LISTEN_PORT=5353
MARK=0x200
TUN=tun0
CHAIN=PS3_RU_NP_TUN

log() { echo "[*] $*"; }
err() { echo "[!] $*" >&2; }

cleanup() {
    log "Очистка правил..."
    while iptables -t nat -D PREROUTING -s $PS3_IP -p udp --dport 53 \
        -j DNAT --to-destination 127.0.0.1:$LISTEN_PORT 2>/dev/null; do :; done
    while iptables -t nat -D PREROUTING -s $PS3_IP -p tcp --dport 53 \
        -j DNAT --to-destination 127.0.0.1:$LISTEN_PORT 2>/dev/null; do :; done
    while ip rule del priority 15000 2>/dev/null; do :; done
    iptables -t mangle -D PREROUTING -s $PS3_IP -j $CHAIN 2>/dev/null
    iptables -t mangle -F $CHAIN 2>/dev/null
    iptables -t mangle -X $CHAIN 2>/dev/null
}
trap cleanup EXIT INT TERM

# ===== ПРОВЕРКИ =====
[ "$(id -u)" -ne 0 ] && { err "нужен root (запускайте через su -c)"; exit 1; }
[ ! -f "$PROXY" ]    && { err "нет файла $PROXY"; exit 1; }
[ ! -x "$PYTHON" ]   && { err "нет $PYTHON — выполните: pkg install python"; exit 1; }

cleanup

log "Цепочка $CHAIN и правило маршрутизации..."
iptables -t mangle -N $CHAIN
iptables -t mangle -A PREROUTING -s $PS3_IP -j $CHAIN
ip rule add fwmark $MARK lookup $TUN priority 15000

log "Запуск DNS-прокси: $PYTHON $PROXY"
"$PYTHON" "$PROXY" &
PROXY_PID=$!

sleep 1
if ! kill -0 $PROXY_PID 2>/dev/null; then
    err "прокси упал при старте — смотрите вывод выше"
    exit 1
fi

log "DNAT: DNS PS3 → 127.0.0.1:$LISTEN_PORT (UDP+TCP)"
iptables -t nat -A PREROUTING -s $PS3_IP -p udp --dport 53 \
    -j DNAT --to-destination 127.0.0.1:$LISTEN_PORT
iptables -t nat -A PREROUTING -s $PS3_IP -p tcp --dport 53 \
    -j DNAT --to-destination 127.0.0.1:$LISTEN_PORT

log "Готово. Ctrl+C — остановка и очистка."
wait $PROXY_PID