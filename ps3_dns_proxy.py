#!/data/data/com.termux/files/usr/bin/python3
"""
ps3_dns_proxy.py — DNS-прокси для маршрутизации *.ru.np.communication.playstation.net через tun0

Схема:
  PS3 → 8.8.8.8:53 ─[iptables DNAT]→ 127.0.0.1:5353
                                         │
                            прокси резолвит через upstream
                                         │
                            парсит A-записи ответа
                                         │
                            iptables MARK + ip route replace
                                         │
                            только теперь → ответ PS3
"""

import socket
import struct
import subprocess
import sys
import threading

# ===== КОНФИГУРАЦИЯ =====
PS3_IP       = '10.138.154.77'                       # IP PS3 в wlan2
LISTEN_ADDR  = '127.0.0.1'
LISTEN_PORT  = 5353
UPSTREAM     = ('8.8.8.8', 53)
UPSTREAM_SRC = None    # None = kernel default (через wlan0, тот же uplink что и wlan2).
                       # Можно явно: '192.168.1.113' (wlan0) или '10.10.14.1' (tun0).
SUFFIXES     = (b'ru.np.communication.playstation.net',)
MARK         = '0x200'
TUN_TABLE    = 'tun0'
CHAIN        = 'PS3_RU_NP_TUN'
VERBOSE      = True

# ===== DNS-ПАРСЕР =====
def parse_qname(msg, off=12):
    """Возвращает (domain_bytes, next_offset). Поддерживает pointer (для skip)."""
    parts = []
    try:
        while off < len(msg):
            l = msg[off]
            if l == 0:
                return b'.'.join(parts), off + 1
            if l & 0xC0:                     # compression pointer
                return b'.'.join(parts), off + 2
            parts.append(msg[off+1:off+1+l])
            off += 1 + l
    except (IndexError, ValueError):
        pass
    return b'.'.join(parts), off

def iter_answers(msg):
    """Генератор (name, rtype, rdata) по всем Answer Records."""
    try:
        qd = struct.unpack('!H', msg[4:6])[0]
        an = struct.unpack('!H', msg[6:8])[0]
    except struct.error:
        return
    off = 12
    for _ in range(qd):
        _, off = parse_qname(msg, off)
        off += 4                              # QTYPE + QCLASS
    for _ in range(an):
        _, off = parse_qname(msg, off)
        if off + 10 > len(msg):
            return
        rtype, _, _, rdlen = struct.unpack('!HHIH', msg[off:off+10])
        off += 10
        rdata = msg[off:off+rdlen]
        off += rdlen
        yield rtype, rdata

def extract_a_records(msg):
    """Все IPv4 из A-записей ответа (включая всю CNAME-цепочку)."""
    return [
        '.'.join(map(str, rdata))
        for rtype, rdata in iter_answers(msg)
        if rtype == 1 and len(rdata) == 4
    ]

def is_target(domain_bytes):
    d = domain_bytes.lower()
    return any(d.endswith(s) for s in SUFFIXES)

# ===== МАРКИРОВКА (потокобезопасная) =====
_marked = set()
_mark_lock = threading.Lock()

def mark_ip(ip):
    with _mark_lock:
        if ip in _marked:
            return
        r = subprocess.run(
            ['iptables', '-t', 'mangle', '-C', CHAIN, '-d', ip,
             '-j', 'MARK', '--set-mark', MARK],
            capture_output=True,
        )
        if r.returncode != 0:
            subprocess.run(
                ['iptables', '-t', 'mangle', '-A', CHAIN, '-d', ip,
                 '-j', 'MARK', '--set-mark', MARK],
                check=True,
            )
            subprocess.run(
                ['ip', 'route', 'replace', ip, 'dev', TUN_TABLE, 'table', TUN_TABLE],
                check=False,
            )
        _marked.add(ip)
        if VERBOSE:
            print(f'[+] {ip} -> {TUN_TABLE}', flush=True)

# ===== UPSTREAM =====
def resolve(data):
    """Отправляет DNS-запрос upstream, возвращает сырой ответ или None."""
    up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if UPSTREAM_SRC:
            try:
                up.bind((UPSTREAM_SRC, 0))
            except OSError as e:
                print(f'[!] bind {UPSTREAM_SRC}: {e}', file=sys.stderr)
        up.settimeout(3.0)
        up.sendto(data, UPSTREAM)
        return up.recvfrom(4096)[0]
    except socket.timeout:
        return None
    finally:
        up.close()

# ===== UDP =====
def udp_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_ADDR, LISTEN_PORT))
    print(f'[*] UDP listening {LISTEN_ADDR}:{LISTEN_PORT}', flush=True)
    while True:
        try:
            data, addr = srv.recvfrom(4096)
        except OSError:
            continue

        def _work(d=data, a=addr):
            try:
                qname, _ = parse_qname(d)
                resp = resolve(d)
                if resp is None:
                    print(f'[!] timeout {qname!r}', file=sys.stderr)
                    return
                if is_target(qname):
                    ips = extract_a_records(resp)
                    if VERBOSE:
                        print(f'[*] {qname.decode(errors="replace")} -> {ips}', flush=True)
                    for ip in ips:
                        try:
                            mark_ip(ip)
                        except Exception as e:
                            print(f'[!] mark {ip}: {e}', file=sys.stderr)
                srv.sendto(resp, a)
            except Exception as e:
                print(f'[!] udp worker: {e}', file=sys.stderr)

        threading.Thread(target=_work, daemon=True).start()

# ===== TCP =====
def _recv_n(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

def tcp_handler(conn, addr):
    try:
        conn.settimeout(5.0)
        while True:
            hdr = _recv_n(conn, 2)
            if not hdr:
                return
            mlen = struct.unpack('!H', hdr)[0]
            data = _recv_n(conn, mlen)
            if not data:
                return
            qname, _ = parse_qname(data)

            up = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                if UPSTREAM_SRC:
                    try:
                        up.bind((UPSTREAM_SRC, 0))
                    except OSError:
                        pass
                up.settimeout(3.0)
                up.connect(UPSTREAM)
                up.sendall(struct.pack('!H', len(data)) + data)
                rhdr = _recv_n(up, 2)
                if not rhdr:
                    return
                rlen = struct.unpack('!H', rhdr)[0]
                resp = _recv_n(up, rlen)
                if not resp:
                    return
            except socket.timeout:
                print(f'[!] TCP timeout {qname!r}', file=sys.stderr)
                return
            finally:
                up.close()

            if is_target(qname):
                for ip in extract_a_records(resp):
                    try:
                        mark_ip(ip)
                    except Exception as e:
                        print(f'[!] mark {ip}: {e}', file=sys.stderr)

            conn.sendall(struct.pack('!H', len(resp)) + resp)
    except Exception as e:
        print(f'[!] tcp handler: {e}', file=sys.stderr)
    finally:
        try:
            conn.close()
        except Exception:
            pass

def tcp_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_ADDR, LISTEN_PORT))
    srv.listen(16)
    print(f'[*] TCP listening {LISTEN_ADDR}:{LISTEN_PORT}', flush=True)
    while True:
        try:
            conn, addr = srv.accept()
        except OSError:
            continue
        threading.Thread(target=tcp_handler, args=(conn, addr), daemon=True).start()

# ===== MAIN =====
def main():
    print(f'[*] PS3 DNS proxy. suffix={SUFFIXES} mark={MARK} tun={TUN_TABLE}', flush=True)
    threading.Thread(target=tcp_server, daemon=True).start()
    try:
        udp_server()
    except KeyboardInterrupt:
        print('\n[*] shutdown', flush=True)

if __name__ == '__main__':
    main()