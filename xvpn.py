#!/usr/bin/env python3
"""
xvpn — Xray-клиент для Termux с раздачей на точку доступа и маршрутизацией по доменам.

Скрипт рассчитан на ROOT: прозрачный прокси через iptables. Клиенты точки доступа
ничего не настраивают — весь их TCP + DNS автоматически идёт через Xray, а Xray
по доменам решает: напрямую или через VPN.

Быстрые режимы:
  xvpn only google.com youtube.com   # ТОЛЬКО эти домены через VPN, всё остальное напрямую
  xvpn except yandex.ru sber.ru      # ВСЁ через VPN, кроме этих доменов напрямую
  xvpn only | xvpn except            # без доменов: вернуться к сохранённому списку
  xvpn full                          # полный режим: ВСЁ через VPN (списки не стираются)
  xvpn toggle                        # переключатель: полный режим <-> «только эти домены через VPN»
  (если Xray запущен, режим применяется сразу, перезапуск вручную не нужен)

Точная настройка:
  xvpn direct add yandex.ru geosite:category-ru geoip:ru   # напрямую
  xvpn proxy  add youtube.com geosite:openai               # через VPN
  xvpn block  add doubleclick.net                          # блокировать
  xvpn default proxy|direct   # что делать с тем, чего нет в списках

Устройства и DNS (PS3, приставки и т.п.):
  xvpn clients                    # кто подключён к точке доступа (IP + MAC)
  xvpn exclude add <MAC>          # устройство вообще мимо VPN: свой DNS, никаких перехватов
  xvpn dns set 151.241.100.80 8.8.4.4   # ВСЕ клиенты используют эти DNS (основной → вторичный)
  xvpn dns on|off                 # on: перехват DNS в Xray, off: DNS клиентов не трогаем (по умолчанию)
  xvpn ports auto|all|80,443      # какие TCP-порты заворачивать в Xray
  xvpn doctor                     # проверка root/iptables/интерфейса на этом телефоне

Запуск:
  xvpn start              # root, прозрачный режим на точке доступа
  xvpn start --self       # + ещё и трафик самого телефона (приложения Termux/root uid)
  xvpn start --noroot     # запасной вариант без root: SOCKS5/HTTP прокси, вручную в клиентах
"""
import os, sys, re, json, shutil, socket, platform, signal, time, zipfile, ipaddress, threading
import subprocess, urllib.request, urllib.parse

HOME = os.path.expanduser("~/.xvpn")
BIN = f"{HOME}/xray"
GEO = HOME
CFG = f"{HOME}/config.json"
SETTINGS = f"{HOME}/settings.json"
STATE = f"{HOME}/state.json"
PID = f"{HOME}/xray.pid"
DNSPID = f"{HOME}/dnsfwd.pid"
LOG = f"{HOME}/xray.log"
LISTS = {n: f"{HOME}/{n}.txt" for n in ("direct", "proxy", "block")}

DEFAULTS = {
    "link": "",
    "default": "proxy",      # proxy: всё через VPN, кроме direct.txt; direct: всё напрямую, кроме proxy.txt
    # нестандартные порты: 10808/10809 заняты v2rayNG и подобными, UDP 5353 — mDNS Android
    "socks_port": 20808,
    "http_port": 20809,
    "redir_port": 22345,
    "dns_port": 25353,
    "listen_lan": True,      # слушать на 0.0.0.0 (нужно для раздачи на точку доступа)
    "direct_dns": "77.88.8.8",
    "proxy_dns": "1.1.1.1",
    "iface": "",
    "dns_hijack": False,     # перехватывать DNS клиентов точки доступа (по умолчанию НЕТ: у клиентов свой DNS)
    "full": False,           # полный режим: всё через VPN, список direct игнорируется (но не удаляется)
    "dns_servers": [],       # принудительные DNS для всех клиентов: [основной, вторичный]; пусто = выкл
    "exclude": [],           # устройства (IP/сеть/MAC), которые вообще не трогаем (PS3 и т.п.)
    "redir_ports": "auto",   # какие TCP-порты заворачивать в Xray: auto | all | 80,443,...
    "tune": True,            # тонкая настройка буферов Xray (на arm64 дефолт 4 КБ душит скорость)
}

PRIVATE = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
           "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4"]

LIST_HEADER = "# По одному правилу в строке. Примеры: example.com | full:www.example.com | keyword:abc | geosite:category-ru | geoip:ru | 1.2.3.0/24\n"


# ---------------------------------------------------------------- утилиты
def die(msg):
    print(f"✗ {msg}")
    sys.exit(1)


def ensure_dirs():
    os.makedirs(HOME, exist_ok=True)
    for p in LISTS.values():
        if not os.path.exists(p):
            with open(p, "w") as f:
                f.write(LIST_HEADER)


def load_settings():
    ensure_dirs()
    s = dict(DEFAULTS)
    if os.path.exists(SETTINGS):
        with open(SETTINGS) as f:
            saved = json.load(f)
        # миграция: старые порты по умолчанию были заняты на многих телефонах
        old = {"socks_port": 10808, "http_port": 10809, "redir_port": 12345, "dns_port": 5353}
        for k, v in old.items():
            if saved.get(k) == v:
                saved.pop(k)
        s.update(saved)
    if s["dns_servers"]:
        s["dns_hijack"] = False   # принудительные DNS и перехват в Xray взаимоисключающи
    return s


def port_free(port, proto):
    kind = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
    sk = socket.socket(socket.AF_INET, kind)
    try:
        sk.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False
    finally:
        sk.close()


def pick_ports(s, root_mode):
    """Если порт занят — берём следующий свободный (в настройках не сохраняется)."""
    need = [("socks_port", "tcp"), ("http_port", "tcp")]
    if root_mode:
        need.append(("redir_port", "tcp"))
        if s["dns_hijack"]:
            need.append(("dns_port", "udp"))
    taken = set()  # порты, уже выданные другим inbound-ам этого запуска
    for key, proto in need:
        orig = s[key]
        while (s[key] in taken or not port_free(s[key], proto)) and s[key] < orig + 50:
            s[key] += 1
        taken.add(s[key])
        if s[key] != orig:
            print(f"! {proto.upper()}-порт {orig} занят, использую {s[key]}")
        if not port_free(s[key], proto):
            die(f"Не нашёл свободный порт рядом с {orig}")
    if root_mode and s["dns_servers"]:
        # переадресатору DNS нужен один и тот же порт и для UDP, и для TCP
        def free_both(p):
            return p not in taken and port_free(p, "udp") and port_free(p, "tcp")
        orig = s["dns_port"]
        while not free_both(s["dns_port"]) and s["dns_port"] < orig + 50:
            s["dns_port"] += 1
        if s["dns_port"] != orig:
            print(f"! DNS-порт {orig} занят, использую {s['dns_port']}")
        if not free_both(s["dns_port"]):
            die(f"Не нашёл свободный порт для DNS рядом с {orig}")


def save_settings(s):
    with open(SETTINGS, "w") as f:
        json.dump(s, f, indent=2, ensure_ascii=False)


def read_list(name):
    out = []
    with open(LISTS[name]) as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                out.append(line)
    return out


def write_list(name, items):
    with open(LISTS[name], "w") as f:
        f.write(LIST_HEADER)
        for i in items:
            f.write(i + "\n")


def sh(cmd, root=False, check=False):
    full = ["su", "-c", cmd] if root else ["sh", "-c", cmd]
    r = subprocess.run(full, capture_output=True, text=True)
    if check and r.returncode != 0:
        die(f"Команда не удалась: {cmd}\n{r.stderr.strip()}")
    return (r.stdout or "") + (r.stderr or "") if not check else r.stdout


def have_root():
    try:
        r = subprocess.run(["su", "-c", "id -u"], capture_output=True, text=True, timeout=30)
        return r.stdout.strip() == "0"
    except Exception:
        return False


def download(url, dest):
    print(f"  ↓ {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "xvpn-termux"})
    with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)


# ---------------------------------------------------------------- правила
RULE_PREFIX = re.compile(r"^(geosite|geoip|domain|full|keyword|regexp|ext|ext-domain|ext-ip):")


def is_ip_rule(e):
    if e.startswith(("geoip:", "ext-ip:")):
        return True
    try:
        ipaddress.ip_network(e, strict=False)
        return True
    except ValueError:
        return False


def norm(entry):
    e = entry.strip().lower()
    e = re.sub(r"^https?://", "", e)
    e = e.split("/")[0] if not is_ip_rule(e) and not RULE_PREFIX.match(e) else e
    e = e.lstrip("*.")
    if RULE_PREFIX.match(e) or is_ip_rule(e):
        return e
    return "domain:" + e


def split_rules(entries):
    domains, ips = [], []
    for e in entries:
        n = norm(e)
        (ips if is_ip_rule(n) else domains).append(n)
    return domains, ips


# ---------------------------------------------------------------- vless-ссылка
def resolve(host):
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    infos = socket.getaddrinfo(host, None, socket.AF_INET)
    return infos[0][4][0]


def parse_vless(link):
    u = urllib.parse.urlparse(link.strip())
    if u.scheme != "vless":
        die("Нужна ссылка вида vless://...")
    q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
    host, port, uuid = u.hostname, u.port or 443, urllib.parse.unquote(u.username or "")
    if not host or not uuid:
        die("В ссылке нет адреса или UUID")

    net = q.get("type", "tcp")
    if net == "splithttp":
        net = "xhttp"
    sec = q.get("security", "none")
    stream = {"network": net, "security": sec}

    sni = q.get("sni") or q.get("host") or host
    fp = q.get("fp") or "chrome"
    if sec == "tls":
        tls = {"serverName": sni, "fingerprint": fp}
        if q.get("alpn"):
            tls["alpn"] = q["alpn"].split(",")
        if q.get("allowInsecure") in ("1", "true"):
            tls["allowInsecure"] = True
        stream["tlsSettings"] = tls
    elif sec == "reality":
        stream["realitySettings"] = {
            "serverName": sni, "fingerprint": fp,
            "publicKey": q.get("pbk", ""), "shortId": q.get("sid", ""),
            "spiderX": q.get("spx", ""),
        }

    path = urllib.parse.unquote(q.get("path", "/")) or "/"
    if net == "xhttp":
        x = {"path": path, "mode": q.get("mode", "auto")}
        x["host"] = q.get("host", "") or (host if sec == "tls" else "")
        if not x["host"]:
            del x["host"]
        if q.get("extra"):
            try:
                x["extra"] = json.loads(q["extra"])
            except ValueError:
                print("! параметр extra в ссылке не разобран, пропускаю")
        stream["xhttpSettings"] = x
    elif net == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": q.get("host", host)}}
    elif net == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": path, "host": q.get("host", host)}
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": q.get("serviceName", ""),
                                  "multiMode": q.get("mode") == "multi"}

    user = {"id": uuid, "encryption": q.get("encryption", "none")}
    if q.get("flow"):
        user["flow"] = q["flow"]

    return {
        "tag": "proxy",
        "protocol": "vless",
        # домен резолвим здесь (системным резолвером Termux), SNI/Host остаются доменом
        "settings": {"vnext": [{"address": resolve(host), "port": port, "users": [user]}]},
        "streamSettings": stream,
        "_name": urllib.parse.unquote(u.fragment),
    }


# ---------------------------------------------------------------- конфиг xray
def build_config(s, root_mode):
    if not s["link"]:
        die("Сначала задай ссылку: xvpn set 'vless://...'")
    proxy_out = parse_vless(s["link"])
    proxy_out.pop("_name", None)

    d_dom, d_ip = ([], []) if s.get("full") else split_rules(read_list("direct"))
    p_dom, p_ip = split_rules(read_list("proxy"))
    b_dom, b_ip = split_rules(read_list("block"))
    proxy_default = s["default"] == "proxy"

    sniff = {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}
    listen = "0.0.0.0" if s["listen_lan"] else "127.0.0.1"
    inbounds = [
        {"tag": "socks", "listen": listen, "port": s["socks_port"], "protocol": "socks",
         "settings": {"udp": True, "auth": "noauth"}, "sniffing": sniff},
        {"tag": "http", "listen": listen, "port": s["http_port"], "protocol": "http",
         "settings": {}, "sniffing": sniff},
    ]
    if root_mode:
        inbounds += [
            {"tag": "redir", "listen": "0.0.0.0", "port": s["redir_port"], "protocol": "dokodemo-door",
             "settings": {"network": "tcp", "followRedirect": True},
             "streamSettings": {"sockopt": {"tproxy": "redirect"}},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls"], "routeOnly": True}},
        ]
        if s["dns_hijack"]:
            inbounds.append(
                {"tag": "dns-in", "listen": "0.0.0.0", "port": s["dns_port"], "protocol": "dokodemo-door",
                 "settings": {"address": s["proxy_dns"], "port": 53, "network": "udp"}})

    direct_out = {"tag": "direct", "protocol": "freedom", "settings": {}}
    block_out = {"tag": "block", "protocol": "blackhole", "settings": {}}
    dns_out = {"tag": "dns-out", "protocol": "dns"}
    # первый outbound = маршрут по умолчанию
    outbounds = ([proxy_out, direct_out] if proxy_default else [direct_out, proxy_out]) + [block_out, dns_out]

    rules = []
    if root_mode and s["dns_hijack"]:
        rules.append({"type": "field", "inboundTag": ["dns-in"], "outboundTag": "dns-out"})
    rules.append({"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"})
    rules.append({"type": "field", "ip": [s["direct_dns"]], "outboundTag": "direct"})
    rules.append({"type": "field", "ip": [s["proxy_dns"]], "outboundTag": "proxy"})
    if b_dom:
        rules.append({"type": "field", "domain": b_dom, "outboundTag": "block"})
    if b_ip:
        rules.append({"type": "field", "ip": b_ip, "outboundTag": "block"})
    # явные списки приоритетнее: сначала proxy, потом direct (конфликт → через VPN)
    if p_dom:
        rules.append({"type": "field", "domain": p_dom, "outboundTag": "proxy"})
    if p_ip:
        rules.append({"type": "field", "ip": p_ip, "outboundTag": "proxy"})
    if d_dom:
        rules.append({"type": "field", "domain": d_dom, "outboundTag": "direct"})
    if d_ip:
        rules.append({"type": "field", "ip": d_ip, "outboundTag": "direct"})

    servers = []
    if proxy_default:
        if d_dom:
            servers.append({"address": s["direct_dns"], "domains": d_dom})
        servers.append(s["proxy_dns"])
    else:
        if p_dom:
            servers.append({"address": s["proxy_dns"], "domains": p_dom})
        servers.append(s["direct_dns"])

    # IPIfNonMatch заставляет Xray резолвить домены ради IP-правил — лишние DNS-запросы.
    # Если IP/geoip-правил в списках нет, берём быстрый AsIs.
    need_ip = bool(d_ip or p_ip or b_ip)
    cfg = {
        "log": {"loglevel": "warning"},
        "dns": {"servers": servers, "queryStrategy": "UseIPv4"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "IPIfNonMatch" if need_ip else "AsIs", "rules": rules},
    }
    if s.get("tune"):
        cfg["policy"] = {"levels": {"0": {"handshake": 4, "connIdle": 300, "uplinkOnly": 2,
                                          "downlinkOnly": 5, "bufferSize": 256}}}
    return cfg


# ---------------------------------------------------------------- iptables (root)
UPLINK = re.compile(r"^(lo|rmnet|ccmni|tun|v4-|dummy|p2p|ifb|sit|ip6)")


def list_ifaces():
    out = sh("ip -o -4 addr show", root=True)
    res = []
    for line in out.splitlines():
        p = line.split()
        if len(p) > 3:
            res.append((p[1], p[3]))
    return res


def detect_iface():
    ifs = list_ifaces()
    for n, _ in ifs:
        if re.match(r"^(ap\d|swlan\d|softap\d|wlan[1-9]|rndis\d|ncm\d|bt-pan)", n):
            return n
    # на MediaTek точка доступа часто живёт на wlan0/ap0 с адресом вида 192.168.x.1
    for n, addr in ifs:
        ip = addr.split("/")[0]
        if not UPLINK.match(n) and ip.endswith(".1") and ip.startswith(("192.168.", "10.", "172.")):
            return n
    return ""


def mac_ok(x):
    return re.fullmatch(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", x) is not None


def src_match(x):
    return f"-m mac --mac-source {x}" if mac_ok(x) else f"-s {x}"


def redir_cmd(chain, s):
    """Правило заворота TCP в Xray. В режиме «только эти домены» достаточно 80/443 —
    остальной TCP (игры, почта, торренты) идёт мимо Xray и не грузит слабый процессор."""
    ports = s["redir_ports"]
    if ports == "auto":
        ports = "80,443" if s["default"] == "direct" else "all"
    if ports == "all":
        return f"iptables -t nat -A {chain} -p tcp -j REDIRECT --to-ports {s['redir_port']}"
    return (f"iptables -t nat -A {chain} -p tcp -m multiport --dports {ports} "
            f"-j REDIRECT --to-ports {s['redir_port']}")


def ipt_setup(iface, s):
    cmds = [
        "iptables -t nat -N XVPN 2>/dev/null", "iptables -t nat -F XVPN",
        "iptables -N XVPN_FWD 2>/dev/null", "iptables -F XVPN_FWD",
    ]
    # исключённые устройства (PS3 и т.п.) не трогаем вообще: ни TCP, ни DNS, ни QUIC
    for x in s["exclude"]:
        cmds.append(f"iptables -t nat -A XVPN {src_match(x)} -j RETURN")
        cmds.append(f"iptables -A XVPN_FWD {src_match(x)} -j RETURN")
    if s["dns_servers"]:
        # принудительный DNS: любые запросы клиентов на :53 (даже на прописанные вручную серверы)
        # уходят в локальный переадресатор, который спрашивает основной, затем вторичный
        cmds.append(f"iptables -t nat -A XVPN -p udp --dport 53 -j REDIRECT --to-ports {s['dns_port']}")
        cmds.append(f"iptables -t nat -A XVPN -p tcp --dport 53 -j REDIRECT --to-ports {s['dns_port']}")
    elif s["dns_hijack"]:
        cmds.append(f"iptables -t nat -A XVPN -p udp --dport 53 -j REDIRECT --to-ports {s['dns_port']}")
    cmds += [f"iptables -t nat -A XVPN -d {n} -j RETURN" for n in PRIVATE]
    cmds += [
        redir_cmd("XVPN", s),
        f"iptables -t nat -I PREROUTING -i {iface} -j XVPN",
        # QUIC не проксируем — браузеры откатятся на TCP (иначе UDP/443 уйдёт мимо VPN)
        "iptables -A XVPN_FWD -p udp --dport 443 -j REJECT",
        f"iptables -I FORWARD -i {iface} -j XVPN_FWD",
        # IPv6 с точки доступа в обход VPN не пускаем
        f"ip6tables -I FORWARD -i {iface} -j REJECT 2>/dev/null",
    ]
    sh(" ; ".join(cmds), root=True)


def ipt_cleanup(iface):
    if not iface:
        return
    cmds = [
        f"iptables -t nat -D PREROUTING -i {iface} -j XVPN 2>/dev/null",
        "iptables -t nat -F XVPN 2>/dev/null",
        "iptables -t nat -X XVPN 2>/dev/null",
        f"iptables -D FORWARD -i {iface} -j XVPN_FWD 2>/dev/null",
        "iptables -F XVPN_FWD 2>/dev/null",
        "iptables -X XVPN_FWD 2>/dev/null",
        # правило из прошлых версий скрипта
        f"iptables -D FORWARD -i {iface} -p udp --dport 443 -j REJECT 2>/dev/null",
        f"ip6tables -D FORWARD -i {iface} -j REJECT 2>/dev/null",
    ]
    sh(" ; ".join(cmds), root=True)


# ---------------------------------------------------------------- процесс
def read_pid(path=PID):
    try:
        with open(path) as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)
        return pid
    except Exception:
        return None


def load_state():
    try:
        with open(STATE) as f:
            return json.load(f)
    except Exception:
        return {}


def env():
    e = dict(os.environ)
    e["XRAY_LOCATION_ASSET"] = GEO
    return e


def lan_addresses():
    out = sh("ip -o -4 addr show") or ""
    res = []
    for line in out.splitlines():
        p = line.split()
        if len(p) > 3 and p[1] != "lo":
            res.append((p[1], p[3].split("/")[0]))
    return res


# ---------------------------------------------------------------- команды
def cmd_install(_a):
    ensure_dirs()
    sh("pkg install -y curl iproute2 2>/dev/null")
    m = platform.machine().lower()
    arch = {"aarch64": "arm64-v8a", "arm64": "arm64-v8a", "armv7l": "arm32-v7a", "armv8l": "arm32-v7a",
            "x86_64": "64", "i686": "32"}.get(m)
    if not arch:
        die(f"Неизвестная архитектура: {m}")
    z = f"{HOME}/xray.zip"
    download(f"https://github.com/XTLS/Xray-core/releases/latest/download/Xray-android-{arch}.zip", z)
    with zipfile.ZipFile(z) as zf:
        for name in ("xray", "geoip.dat", "geosite.dat"):
            if name in zf.namelist():
                zf.extract(name, HOME)
    os.remove(z)
    os.chmod(BIN, 0o755)
    # команда xvpn в PATH
    prefix = os.environ.get("PREFIX", "/data/data/com.termux/files/usr")
    dst = f"{prefix}/bin/xvpn"
    try:
        shutil.copy(os.path.abspath(__file__), dst)
        os.chmod(dst, 0o755)
        print(f"✓ Команда установлена: xvpn")
    except Exception as ex:
        print(f"! Не удалось скопировать в {dst}: {ex}")
    print(sh(f"{BIN} version").splitlines()[0])
    print("✓ Готово. Дальше: xvpn set 'vless://...'")


def cmd_geo(_a):
    base = "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download"
    for n in ("geosite.dat", "geoip.dat"):
        try:
            download(f"{base}/{n}", f"{GEO}/{n}.new")
            os.replace(f"{GEO}/{n}.new", f"{GEO}/{n}")
        except Exception as ex:
            print(f"! {n}: {ex}")
    print("✓ geo-базы обновлены (есть geosite:ru-blocked, geoip:ru и т.д.). Применить: xvpn restart")


def cmd_set(a):
    if not a:
        die("Использование: xvpn set 'vless://...'")
    s = load_settings()
    o = parse_vless(a[0])
    s["link"] = a[0]
    save_settings(s)
    st = o["streamSettings"]
    print(f"✓ Ссылка сохранена: {o['_name'] or 'без имени'} "
          f"[{st['network']}+{st['security']}] {o['settings']['vnext'][0]['address']}:{o['settings']['vnext'][0]['port']}")


def cmd_default(a):
    if a not in (["proxy"], ["direct"]):
        die("Использование: xvpn default proxy|direct")
    s = load_settings()
    s["default"], s["full"] = a[0], False
    save_settings(s)
    txt = "через VPN (кроме списка direct)" if a[0] == "proxy" else "напрямую (кроме списка proxy)"
    print(f"✓ Всё остальное идёт {txt}")


def cmd_list_edit(kind, a):
    ensure_dirs()
    if not a or a[0] == "list":
        items = read_list(kind)
        print(f"[{kind}] {len(items)} правил(а):")
        for i in items:
            print("  ", i)
        return
    op, vals = a[0], a[1:]
    items = read_list(kind)
    if op == "add":
        for v in vals:
            if v not in items:
                items.append(v)
        write_list(kind, items)
    elif op in ("del", "rm"):
        write_list(kind, [i for i in items if i not in vals])
    elif op == "edit":
        os.system(f"{os.environ.get('EDITOR', 'nano')} {LISTS[kind]}")
    elif op == "clear":
        write_list(kind, [])
    else:
        die(f"Использование: xvpn {kind} add|del|list|edit|clear [правила]")
    print(f"✓ {kind}: {len(read_list(kind))} правил. Применить: xvpn restart")


def cmd_start(a):
    s = load_settings()
    if not os.path.exists(BIN):
        die("Xray не установлен: xvpn install")
    root_mode = "--noroot" not in a
    iface = s["iface"]
    if "--iface" in a:
        iface = a[a.index("--iface") + 1] if a.index("--iface") + 1 < len(a) else ""
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", iface):
            die("После --iface нужно имя интерфейса, например: --iface wlan1")

    if read_pid():
        cmd_stop([])
    # убрать «осиротевшие» процессы Xray от прошлых запусков (pid-файл мог потеряться)
    sh("pkill -f '[.]xvpn/xray run' 2>/dev/null; pkill -f '[_]dnsfwd' 2>/dev/null")
    time.sleep(0.5)
    pick_ports(s, root_mode)

    cfg = build_config(s, root_mode)
    with open(CFG, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    t = subprocess.run([BIN, "run", "-test", "-c", CFG], env=env(), capture_output=True, text=True)
    if t.returncode != 0:
        die("Xray не принял конфиг:\n" + (t.stdout + t.stderr).strip())

    if root_mode:
        if not have_root():
            die("Root недоступен (su не сработал). Выдай Termux root в Magisk/KernelSU "
                "или запусти запасной режим: xvpn start --noroot")
        iface = iface or detect_iface()
        if not iface:
            die("Не нашёл интерфейс точки доступа. Включи точку доступа и укажи: xvpn start --iface wlan1\n"
                "(посмотреть имена: su -c 'ip -o -4 addr')")

    sh("command -v termux-wake-lock >/dev/null && termux-wake-lock")
    logf = open(LOG, "ab")
    p = subprocess.Popen([BIN, "run", "-c", CFG], stdout=logf, stderr=logf, env=env(), start_new_session=True)
    with open(PID, "w") as f:
        f.write(str(p.pid))
    time.sleep(1.5)
    if p.poll() is not None:
        os.remove(PID)
        die("Xray упал при старте:\n" + sh(f"tail -n 15 {LOG}"))

    if root_mode and s["dns_servers"]:
        fl = open(LOG, "ab")
        fp = subprocess.Popen([sys.executable, os.path.realpath(sys.argv[0]), "_dnsfwd",
                               str(s["dns_port"]), *s["dns_servers"]],
                              stdout=fl, stderr=fl, start_new_session=True)
        with open(DNSPID, "w") as f:
            f.write(str(fp.pid))
        time.sleep(0.8)
        if fp.poll() is not None:
            cmd_stop([])
            die("DNS-переадресатор упал при старте:\n" + sh(f"tail -n 15 {LOG}"))

    self_mode = root_mode and "--self" in a
    if root_mode:
        ipt_cleanup(iface)       # на случай осиротевших правил от прошлого запуска
        ipt_self_cleanup()
        ipt_setup(iface, s)
        if self_mode:
            ipt_self_setup(s)
    with open(STATE, "w") as f:
        json.dump({"root": root_mode, "iface": iface if root_mode else "", "self": self_mode,
                   "socks_port": s["socks_port"], "http_port": s["http_port"]}, f)

    print(f"✓ Xray запущен (pid {p.pid})")
    print_mode(s)
    if root_mode:
        print(f"✓ Прозрачный прокси включён на интерфейсе {iface}: клиенты точки доступа ничего не настраивают.")
        if self_mode:
            print("✓ Трафик самого телефона тоже заворачивается (кроме самого Xray).")
        if s["dns_servers"]:
            print(f"  DNS клиентов: принудительно {' → '.join(s['dns_servers'])} (основной → вторичный)")
        else:
            print(f"  DNS клиентов: {'перехватывается Xray' if s['dns_hijack'] else 'не трогаю — у каждого устройства свой DNS'}")
        ex = s["exclude"]
        print(f"  Мимо VPN полностью: {', '.join(ex) if ex else 'никто'}  (xvpn clients / xvpn exclude add <MAC|IP>)")
    else:
        ips = ", ".join(f"{ip} ({n})" for n, ip in lan_addresses()) or "см. `ip addr` / настройки точки доступа"
        print("  Запасной режим без root. Прокси для клиентов точки доступа (вручную в Wi-Fi → прокси):")
        print(f"    SOCKS5: <IP телефона>:{s['socks_port']}    HTTP: <IP телефона>:{s['http_port']}")  # порты уже подобраны
        print(f"    Адреса телефона: {ips}")


def cmd_exclude(a):
    s = load_settings()
    if not a or a[0] == "list":
        print("Мимо VPN полностью (ни TCP, ни DNS, ни QUIC не трогаем):")
        for x in s["exclude"]:
            print("  ", x)
        if not s["exclude"]:
            print("   (никого)")
        return
    op, vals = a[0], a[1:]
    if op == "add":
        for v in vals:
            if mac_ok(v):
                v = v.lower()
            else:
                try:
                    ipaddress.ip_network(v, strict=False)
                except ValueError:
                    die(f"Не похоже ни на IP/сеть, ни на MAC: {v}")
            if v not in s["exclude"]:
                s["exclude"].append(v)
    elif op in ("del", "rm"):
        drop = {v.lower() for v in vals} | set(vals)
        s["exclude"] = [x for x in s["exclude"] if x not in drop]
    elif op == "clear":
        s["exclude"] = []
    else:
        die("Использование: xvpn exclude add|del|list|clear <MAC или IP>")
    save_settings(s)
    print(f"✓ Исключено устройств: {len(s['exclude'])}. Применить: xvpn restart")


def cmd_clients(_a):
    s = load_settings()
    st = load_state()
    iface = st.get("iface") or s["iface"] or detect_iface()
    if not iface:
        die("Не нашёл интерфейс точки доступа. Включи её и повтори (или xvpn start --iface X)")
    out = sh(f"ip neigh show dev {iface}", root=True)
    n = 0
    print(f"Устройства на {iface}:")
    for line in out.splitlines():
        p = line.split()
        if "lladdr" in p and p[-1] != "FAILED":
            ip, mac = p[0], p[p.index("lladdr") + 1].lower()
            mark = "  (мимо VPN)" if ip in s["exclude"] or mac in s["exclude"] else ""
            print(f"  {ip:<16} {mac}  {p[-1]}{mark}")
            n += 1
    if not n:
        print("  никого не видно — подключи устройство и сделай с него любой запрос")
    else:
        print("Исключить (например PS3):  xvpn exclude add <MAC>   — MAC надёжнее IP, IP по DHCP меняется")


def _recv_exact(c, n):
    buf = b""
    while len(buf) < n:
        chunk = c.recv(n - len(buf))
        if not chunk:
            raise OSError("соединение закрыто")
        buf += chunk
    return buf


def _dns_udp_ask(pkt, servers, timeout):
    """Спрашиваем серверы по очереди: следующий — если нет ответа за timeout или пришёл SERVFAIL."""
    last = None
    for srv in servers:
        sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sk.settimeout(timeout)
            sk.sendto(pkt, (srv, 53))
            data, _ = sk.recvfrom(65535)
        except OSError:
            continue
        finally:
            sk.close()
        if len(data) >= 4 and (data[3] & 0x0F) == 2:   # RCODE=SERVFAIL
            last = data
            continue
        return data
    return last


def _dns_tcp_ask(pkt, servers, timeout):
    for srv in servers:
        try:
            with socket.create_connection((srv, 53), timeout=timeout) as c:
                c.settimeout(timeout)
                c.sendall(len(pkt).to_bytes(2, "big") + pkt)
                n = int.from_bytes(_recv_exact(c, 2), "big")
                return _recv_exact(c, n)
        except OSError:
            continue
    return None


def run_dnsfwd(port, servers, timeout=2.0):
    """Крошечный DNS-переадресатор (UDP+TCP): основной сервер, при молчании/SERVFAIL — вторичный."""
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("0.0.0.0", port))
    t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    t.bind(("0.0.0.0", port))
    t.listen(64)

    def udp_job(pkt, addr):
        ans = _dns_udp_ask(pkt, servers, timeout)
        if ans:
            try:
                u.sendto(ans, addr)
            except OSError:
                pass

    def tcp_job(c):
        try:
            c.settimeout(5)
            n = int.from_bytes(_recv_exact(c, 2), "big")
            ans = _dns_tcp_ask(_recv_exact(c, n), servers, timeout)
            if ans:
                c.sendall(len(ans).to_bytes(2, "big") + ans)
        except OSError:
            pass
        finally:
            c.close()

    def tcp_loop():
        while True:
            try:
                c, _ = t.accept()
            except OSError:
                continue
            threading.Thread(target=tcp_job, args=(c,), daemon=True).start()

    threading.Thread(target=tcp_loop, daemon=True).start()
    print(f"dnsfwd: слушаю :{port}, серверы {servers}", flush=True)
    while True:
        try:
            pkt, addr = u.recvfrom(65535)
        except OSError:
            continue
        threading.Thread(target=udp_job, args=(pkt, addr), daemon=True).start()


def cmd_dnsfwd(a):   # служебная команда, запускается из `start`
    run_dnsfwd(int(a[0]), a[1:])


def cmd_dns(a):
    s = load_settings()
    if a and a[0] == "set":
        servers = a[1:]
        if not 1 <= len(servers) <= 2:
            die("Использование: xvpn dns set <основной> [вторичный]   например: xvpn dns set 151.241.100.80 8.8.4.4")
        for x in servers:
            try:
                if ipaddress.ip_address(x).version != 4:
                    raise ValueError
            except ValueError:
                die(f"Нужен IPv4-адрес DNS-сервера, а не «{x}»")
        s["dns_servers"], s["dns_hijack"] = servers, False
        save_settings(s)
        sec = f", вторичный {servers[1]}" if len(servers) > 1 else ""
        print(f"✓ Все клиенты точки доступа (кроме исключённых) будут использовать DNS: основной {servers[0]}{sec}.")
        print("  Работает и для устройств с вручную прописанным DNS. Вторичный спрашивается, если основной "
              "молчит 2 с или вернул SERVFAIL. Применить: xvpn restart")
        print("  Чтобы не обходили: на Android-клиентах выключи «Частный DNS» (DoT), в браузерах — DoH.")
    elif a == ["on"]:
        s["dns_hijack"], s["dns_servers"] = True, []
        save_settings(s)
        print("✓ DNS клиентов перехватывается Xray (серверы direct_dns/proxy_dns из настроек). "
              "Применить: xvpn restart")
    elif a == ["off"]:
        s["dns_hijack"], s["dns_servers"] = False, []
        save_settings(s)
        print("✓ DNS клиентов не трогаем: каждое устройство использует свой DNS. Домены для маршрутизации "
              "берутся из SNI (HTTPS). Применить: xvpn restart")
    elif a in ([], ["show"]):
        if s["dns_servers"]:
            print(f"DNS клиентов: принудительно {' → '.join(s['dns_servers'])} (основной → вторичный)")
        else:
            print(f"DNS клиентов: {'перехват Xray' if s['dns_hijack'] else 'не трогаем'}")
    else:
        die("Использование: xvpn dns set <основной> [вторичный] | on | off | show")


def cmd_ports(a):
    if len(a) != 1 or not (a[0] in ("auto", "all") or re.fullmatch(r"\d{1,5}(,\d{1,5}){0,13}", a[0])):
        die("Использование: xvpn ports auto|all|80,443,5222   (какие TCP-порты заворачивать в Xray)")
    s = load_settings()
    s["redir_ports"] = a[0]
    save_settings(s)
    print(f"✓ Порты: {a[0]}. auto = 80,443 в режиме «only» и все в режиме «except». Применить: xvpn restart")


def cmd_doctor(_a):
    s = load_settings()

    def ok(c, text, hint=""):
        print(("✓ " if c else "✗ ") + text + ("" if c or not hint else f"\n    → {hint}"))

    m = platform.machine()
    ok(m in ("aarch64", "arm64", "armv7l", "armv8l"), f"Архитектура: {m}", "нужен ARM-телефон")
    ok(os.path.exists(BIN), "Xray установлен", "xvpn install")
    ok(bool(s["link"]), "vless-ссылка задана", "xvpn set 'vless://...'")
    print(f"  Android {sh('getprop ro.build.version.release').strip()}, ядро {sh('uname -r').strip()}")
    r = have_root()
    ok(r, "Root (su)", "выдай Termux root в Magisk/KernelSU; без него только xvpn start --noroot")
    if not r:
        return
    caps = sh("cat /proc/net/ip_tables_matches /proc/net/ip_tables_targets 2>/dev/null", root=True).split()
    if not caps:
        print("! Не удалось прочитать список модулей iptables — проверка ниже неточна, просто попробуй xvpn start")
    else:
        ok("REDIRECT" in caps, "iptables: REDIRECT (прозрачный прокси)",
           "в ядре нет nat/REDIRECT — root-режим не заработает")
        ok("multiport" in caps, "iptables: multiport (режим 80,443)", "xvpn ports all")
        ok("mac" in caps, "iptables: mac (исключение по MAC)", "исключай устройства по IP, не по MAC")
        ok("owner" in caps, "iptables: owner (флаг --self)", "не используй --self")
    iface = detect_iface()
    ok(bool(iface), f"Интерфейс точки доступа: {iface or 'не найден'}",
       "включи точку доступа и запусти снова; список: su -c 'ip -o -4 addr', затем xvpn start --iface X")
    print(f"  Интерфейсы: {', '.join(f'{n} {a}' for n, a in list_ifaces()) or '—'}")


def print_mode(s):
    p, d = read_list("proxy"), read_list("direct")
    if s["default"] == "proxy" and s.get("full"):
        print("  Режим: ПОЛНЫЙ — весь трафик через VPN "
              f"(сохранены списки: proxy={len(p)}, direct={len(d)}; вернуть: xvpn only / xvpn except)")
    elif s["default"] == "direct":
        print(f"  Режим: всё НАПРЯМУЮ, через VPN только: {', '.join(p) if p else '(список proxy пуст)'}")
    else:
        print(f"  Режим: всё ЧЕРЕЗ VPN, напрямую только: {', '.join(d) if d else '(список direct пуст)'}")


def apply_now():
    """Если Xray запущен — сразу перезапускаем, чтобы режим вступил в силу."""
    if read_pid():
        print("↻ Применяю...")
        cmd_restart([])
    else:
        print("  Xray не запущен — режим применится при xvpn start")


def cmd_only(a):
    """only <домены> — заменить список proxy и включить режим; `only` без аргументов — вернуться
    к сохранённому списку."""
    s = load_settings()
    if a:
        old = read_list("proxy")
        write_list("proxy", list(dict.fromkeys(a)))
        if old and set(old) != set(a):
            print(f"  Список proxy заменён (было: {', '.join(old)}). Добавлять без замены: xvpn proxy add <домен>")
    elif not read_list("proxy"):
        die("Список proxy пуст. Укажи домены: xvpn only google.com youtube.com")
    s["default"], s["full"] = "direct", False
    save_settings(s)
    print("✓ Режим «всё напрямую, через VPN только домены из списка proxy»")
    print_mode(s)
    apply_now()


def cmd_except(a):
    """except <домены> — заменить список direct и включить режим; `except` без аргументов —
    вернуться к сохранённому списку."""
    s = load_settings()
    if a:
        old = read_list("direct")
        write_list("direct", list(dict.fromkeys(a)))
        if old and set(old) != set(a):
            print(f"  Список direct заменён (было: {', '.join(old)}). Добавлять без замены: xvpn direct add <домен>")
    elif not read_list("direct"):
        die("Список direct пуст. Укажи домены: xvpn except yandex.ru sber.ru")
    s["default"], s["full"] = "proxy", False
    save_settings(s)
    print("✓ Режим «всё через VPN, кроме доменов из списка direct»")
    print_mode(s)
    apply_now()


def cmd_full(_a):
    """Полный режим: весь трафик через VPN. Списки direct/proxy не трогаем — они вернутся по only/except."""
    s = load_settings()
    s["default"], s["full"] = "proxy", True
    save_settings(s)
    print("✓ Полный режим: весь трафик через VPN. Списки сохранены (вернуть: xvpn only / xvpn except)")
    apply_now()


def cmd_toggle(_a):
    """Быстрое переключение: полный режим <-> «всё напрямую, кроме доменов из списка proxy»."""
    s = load_settings()
    if s["default"] == "proxy" and s["full"]:
        if not read_list("proxy"):
            die("Список proxy пуст — переключаться не на что. Сначала: xvpn only google.com ...")
        cmd_only([])
    else:
        cmd_full([])


def cmd_mode(_a):
    print_mode(load_settings())


def ipt_self_setup(s):
    """Заворачивает трафик самого телефона (OUTPUT) в Xray; сам Xray исключается по uid."""
    uid = os.getuid()
    cmds = [
        "iptables -t nat -N XVPN_SELF 2>/dev/null",
        "iptables -t nat -F XVPN_SELF",
        f"iptables -t nat -A XVPN_SELF -m owner --uid-owner {uid} -j RETURN",
        "iptables -t nat -A XVPN_SELF -o lo -j RETURN",
    ]
    cmds += [f"iptables -t nat -A XVPN_SELF -d {n} -j RETURN" for n in PRIVATE]
    cmds += [
        redir_cmd("XVPN_SELF", s),
        "iptables -t nat -I OUTPUT -j XVPN_SELF",
    ]
    sh(" ; ".join(cmds), root=True)


def ipt_self_cleanup():
    sh(" ; ".join([
        "iptables -t nat -D OUTPUT -j XVPN_SELF 2>/dev/null",
        "iptables -t nat -F XVPN_SELF 2>/dev/null",
        "iptables -t nat -X XVPN_SELF 2>/dev/null",
    ]), root=True)


def cmd_stop(_a):
    st = load_state()
    pid = read_pid()
    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.5)
        except Exception:
            pass
    if os.path.exists(PID):
        os.remove(PID)
    dpid = read_pid(DNSPID)
    if dpid:
        try:
            os.kill(dpid, signal.SIGTERM)
        except Exception:
            pass
    if os.path.exists(DNSPID):
        os.remove(DNSPID)
    if st.get("root"):
        ipt_cleanup(st.get("iface"))
        ipt_self_cleanup()
    sh("command -v termux-wake-unlock >/dev/null && termux-wake-unlock")
    print("✓ Остановлено")


def cmd_restart(_a):
    st = load_state()
    args = []
    if st and not st.get("root"):
        args = ["--noroot"]
    else:
        if st.get("iface"):
            args += ["--iface", st["iface"]]
        if st.get("self"):
            args.append("--self")
    cmd_stop([])
    cmd_start(args)


def cmd_status(_a):
    s = load_settings()
    st = load_state()
    pid = read_pid()
    print(f"Xray: {'работает, pid ' + str(pid) if pid else 'остановлен'}"
          f"{' (root-режим, ' + st.get('iface', '') + ')' if pid and st.get('root') else ''}")
    print_mode(s)
    if s["dns_servers"]:
        print(f"DNS клиентов: принудительно {' → '.join(s['dns_servers'])}"
              f" (переадресатор {'работает' if read_pid(DNSPID) else 'не запущен'})")
    else:
        print(f"DNS клиентов: {'перехват Xray' if s['dns_hijack'] else 'не трогаем'}")
    print(f"Правила: direct={len(read_list('direct'))}, proxy={len(read_list('proxy'))}, block={len(read_list('block'))}")
    print(f"Ссылка: {'задана' if s['link'] else 'не задана'}")


def cmd_check(_a):
    s = load_settings()
    port = load_state().get("socks_port", s["socks_port"])
    for label, args in (("через VPN", ["--socks5-hostname", f"127.0.0.1:{port}"]), ("напрямую", [])):
        r = subprocess.run(["curl", "-s", "-m", "10", *args, "https://ifconfig.me"], capture_output=True, text=True)
        print(f"IP {label}: {r.stdout.strip() or 'нет ответа'}")


def cmd_log(_a):
    os.system(f"tail -n 40 {LOG}")


def usage():
    print(__doc__)
    print("Команды: install | set <vless://> | only [домены] | except [домены] | full | toggle | mode |"
          " default proxy|direct |"
          " direct|proxy|block add|del|list|edit | clients | exclude add|del|list <MAC|IP> | dns set <осн> [вторичный]|on|off|show |"
          " ports auto|all|80,443 | start [--self] [--iface X] [--noroot] |"
          " stop | restart | status | check | doctor | log | geo")


def main():
    argv = sys.argv[1:]
    if not argv:
        return usage()
    c, a = argv[0], argv[1:]
    table = {"install": cmd_install, "geo": cmd_geo, "set": cmd_set, "default": cmd_default,
             "only": cmd_only, "except": cmd_except, "mode": cmd_mode,
             "full": cmd_full, "toggle": cmd_toggle,
             "exclude": cmd_exclude, "clients": cmd_clients, "dns": cmd_dns, "ports": cmd_ports,
             "doctor": cmd_doctor, "_dnsfwd": cmd_dnsfwd,
             "start": cmd_start, "stop": cmd_stop, "restart": cmd_restart,
             "status": cmd_status, "check": cmd_check, "log": cmd_log}
    if c in LISTS:
        return cmd_list_edit(c, a)
    if c in table:
        return table[c](a)
    usage()


if __name__ == "__main__":
    main()
