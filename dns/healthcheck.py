#!/usr/bin/env python3
"""
Health-check демон для CoreDNS + веб-админка.

1. Раз в interval секунд параллельно стучится HTTP GET во все бэкенды каждой
   записи из config/records.json. Живой = за timeout секунд ответил кодом
   200-399 (редиректы проходятся) и, если задан "expect", в теле есть эта строка.
2. Пишет zone-файл: в каждой записи только включённые и живые IP. Если живых
   нет, отдаёт все включённые (fail-open). Выключенные в админке не отдаёт никогда.
   Файл пишется атомарно (tmp + rename) с новым SOA serial, CoreDNS перечитывает
   его сам по `reload` в Corefile.
3. Поднимает админку на ADMIN_PORT с Basic-auth (ADMIN_USER / ADMIN_PASSWORD).
   Сохранение конфига в админке применяется сразу и рассылается на остальные
   DNS-ноды из "nameservers".

Конфиг перечитывается на каждом цикле, так что правка руками тоже подхватится.

Всё окружение задаётся переменными (значения по умолчанию в скобках):
  NODE_IP          IP этой ноды, на нём слушает админка; обязателен для синхронизации
  DNS_ZONE         зона, которую обслуживает CoreDNS на этой ноде; конфиг с другой зоной не примется
  ADMIN_USER       логин админки (admin)
  ADMIN_PASSWORD   пароль админки; без него админка не запускается
  ADMIN_PORT       порт админки, одинаковый на всех DNS-нодах (9053)
  HC_CONFIG        путь к records.json (/app/config/records.json)
  HC_ZONES_DIR     куда писать zone-файл (/zones)
  HC_ADMIN_HTML    страница админки (/app/admin.html)
  HC_WORKERS       сколько проверок идёт параллельно (32)
  HC_PEER_TIMEOUT  таймаут синхронизации с другой DNS-нодой, секунд (5)
"""

import base64
import copy
import hmac
import ipaddress
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONFIG = os.environ.get("HC_CONFIG", "/app/config/records.json")
ZONES_DIR = os.environ.get("HC_ZONES_DIR", "/zones")
ADMIN_HTML = os.environ.get("HC_ADMIN_HTML", "/app/admin.html")
ADMIN_PORT = int(os.environ.get("ADMIN_PORT", "9053"))
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
NODE_IP = os.environ.get("NODE_IP", "")
DNS_ZONE = os.environ.get("DNS_ZONE", "").strip().lower().rstrip(".")
HC_WORKERS = int(os.environ.get("HC_WORKERS", "32"))
HC_PEER_TIMEOUT = float(os.environ.get("HC_PEER_TIMEOUT", "5"))

# без системных прокси: проверяем ноды напрямую
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

LOCK = threading.Lock()
WAKE = threading.Event()
STATE = {
    "config": None,          # последний валидный конфиг
    "config_error": None,    # текст ошибки, если файл на диске битый
    "checks": {},            # "name|ip" -> результат проверки
    "answers": {},           # name -> IP, которые сейчас в DNS
    "modes": {},             # name -> ok / fail-open / empty
    "serial": 0,
    "last_cycle": None,
    "last_sync": None,       # результат последней рассылки на другие DNS
}


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ------------------------------------------------------------------ конфиг

NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")
NS_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")


def _ipv4(value, where: str) -> str:
    try:
        return str(ipaddress.IPv4Address(str(value).strip()))
    except ValueError:
        raise ValueError(f"{where}: '{value}' не похож на IPv4-адрес")


def _num(cfg, key, lo, hi, default, cast=float):
    v = cfg.get(key, default)
    try:
        v = cast(v)
    except (TypeError, ValueError):
        raise ValueError(f"{key}: должно быть число")
    if not lo <= v <= hi:
        raise ValueError(f"{key}: допустимо от {lo} до {hi}")
    return v


def validate(raw: dict) -> dict:
    """Проверяет конфиг и приводит к одному виду. Бросает ValueError с понятным текстом."""
    if not isinstance(raw, dict):
        raise ValueError("конфиг должен быть JSON-объектом")
    zone = str(raw.get("zone", "")).strip().lower().rstrip(".")
    if not zone or not NAME_RE.match(zone):
        raise ValueError("zone: пустое или кривое имя зоны")
    if DNS_ZONE and zone != DNS_ZONE:
        raise ValueError(f"zone: в конфиге {zone}, а эта нода обслуживает {DNS_ZONE} (DNS_ZONE)")

    cfg = {
        "zone": zone,
        "ttl": _num(raw, "ttl", 1, 3600, 10, int),
        "interval": _num(raw, "interval", 1, 60, 3),
        "timeout": _num(raw, "timeout", 0.5, 30, 2),
        "nameservers": {},
        "labels": {},
        "records": {},
    }

    ns = raw.get("nameservers") or {}
    if not isinstance(ns, dict) or not ns:
        raise ValueError("nameservers: нужен хотя бы один DNS-сервер")
    for name, ip in ns.items():
        name = str(name).strip().lower()
        if not NS_RE.match(name):
            raise ValueError(f"nameservers: кривое имя '{name}'")
        cfg["nameservers"][name] = _ipv4(ip, f"nameservers.{name}")

    labels = raw.get("labels") or {}
    if not isinstance(labels, dict):
        raise ValueError("labels: должен быть объект IP -> подпись")
    for ip, label in labels.items():
        label = str(label).strip()[:40]
        if label:
            cfg["labels"][_ipv4(ip, "labels")] = label

    recs = raw.get("records") or {}
    if not isinstance(recs, dict):
        raise ValueError("records: должен быть объект")
    for name, rec in recs.items():
        name = str(name).strip().lower().rstrip(".")
        if not NAME_RE.match(name) or not (name == zone or name.endswith("." + zone)):
            raise ValueError(f"запись '{name}': имя должно быть {zone} или *.{zone}")
        if name.split(".")[0] in cfg["nameservers"] and name != zone:
            raise ValueError(f"запись '{name}': имя занято DNS-сервером")
        if not isinstance(rec, dict):
            raise ValueError(f"запись '{name}': должна быть объектом")
        if rec.get("port") in (None, ""):
            raise ValueError(f"запись '{name}': не указан порт")
        try:
            port = _num(rec, "port", 1, 65535, None, int)
        except ValueError as e:
            raise ValueError(f"запись '{name}': {e}")
        path = str(rec.get("path") or "/").strip()
        if not path.startswith("/") or " " in path:
            raise ValueError(f"запись '{name}': путь должен начинаться с / и быть без пробелов")
        expect = str(rec.get("expect") or "")
        ips, seen = [], set()
        for item in rec.get("ips") or []:
            if isinstance(item, str):
                item = {"ip": item, "enabled": True}
            if not isinstance(item, dict):
                raise ValueError(f"запись '{name}': кривой элемент в ips")
            ip = _ipv4(item.get("ip"), f"запись '{name}'")
            if ip in seen:
                raise ValueError(f"запись '{name}': IP {ip} указан дважды")
            seen.add(ip)
            ips.append({"ip": ip, "enabled": bool(item.get("enabled", True))})
        cfg["records"][name] = {"port": port, "path": path, "expect": expect, "ips": ips}
    return cfg


def read_config() -> dict:
    with open(CONFIG, encoding="utf-8") as f:
        return validate(json.load(f))


def write_config(cfg: dict) -> None:
    tmp = CONFIG + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, CONFIG)


# ------------------------------------------------------------------ проверки

def check_one(ip: str, port: int, path: str, timeout: float, expect: str) -> dict:
    url = f"http://{ip}:{port}{path}"
    t0 = time.monotonic()
    res = {"ok": False, "code": None, "ms": None, "error": None, "at": time.time()}
    try:
        with OPENER.open(url, timeout=timeout) as resp:
            res["code"] = resp.status
            if not 200 <= resp.status < 400:
                res["error"] = f"HTTP {resp.status}"
            elif expect:
                body = resp.read(65536).decode("utf-8", "replace")
                if expect in body:
                    res["ok"] = True
                else:
                    res["error"] = "в ответе нет expect (чужое приложение?)"
            else:
                res["ok"] = True
    except urllib.error.HTTPError as e:
        res["code"] = e.code
        res["error"] = f"HTTP {e.code}"
    except Exception as e:
        reason = getattr(e, "reason", e)
        res["error"] = f"{type(reason).__name__}: {reason}"[:160]
    res["ms"] = round((time.monotonic() - t0) * 1000)
    return res


def run_checks(cfg: dict, pool: ThreadPoolExecutor) -> dict:
    jobs = {}
    for name, rec in cfg["records"].items():
        for item in rec["ips"]:
            jobs[f"{name}|{item['ip']}"] = pool.submit(
                check_one, item["ip"], rec["port"], rec["path"], cfg["timeout"], rec["expect"]
            )
    return {k: f.result() for k, f in jobs.items()}


def compute_answers(cfg: dict, checks: dict):
    answers, modes, alive_map = {}, {}, {}
    for name, rec in cfg["records"].items():
        enabled = [x["ip"] for x in rec["ips"] if x["enabled"]]
        alive = [ip for ip in enabled if checks.get(f"{name}|{ip}", {}).get("ok")]
        alive_map[name] = alive
        if alive:
            answers[name], modes[name] = alive, "ok"
        elif enabled:
            answers[name], modes[name] = enabled, "fail-open"
        else:
            answers[name], modes[name] = [], "empty"
    return answers, modes, alive_map


# ------------------------------------------------------------------ зона

def render_zone(cfg: dict, answers: dict, serial: int) -> str:
    zone = cfg["zone"] + "."
    ttl = cfg["ttl"]
    ns_names = list(cfg["nameservers"])
    out = [f"{zone} 3600 IN SOA {ns_names[0]}.{zone} admin.{zone} {serial} 7200 3600 1209600 {ttl}"]
    out += [f"{zone} 3600 IN NS {ns}.{zone}" for ns in ns_names]
    out += [f"{ns}.{zone} 3600 IN A {ip}" for ns, ip in cfg["nameservers"].items()]
    for name, ips in answers.items():
        out += [f"{name}. {ttl} IN A {ip}" for ip in ips]
    return "\n".join(out) + "\n"


def zone_path(cfg: dict) -> str:
    return os.path.join(ZONES_DIR, cfg["zone"] + ".zone")


def write_zone(cfg: dict, text: str) -> None:
    path = zone_path(cfg)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


# ------------------------------------------------------------------ синхронизация

def _auth_header() -> str:
    token = base64.b64encode(f"{ADMIN_USER}:{ADMIN_PASSWORD}".encode()).decode()
    return f"Basic {token}"


def push_to_peers(cfg: dict) -> dict:
    """Отправляет конфиг на остальные DNS-ноды. Возвращает {ip: 'ok' | текст ошибки}."""
    peers = [ip for ip in cfg["nameservers"].values() if ip != NODE_IP]
    body = json.dumps(cfg, ensure_ascii=False).encode()

    def one(ip):
        req = urllib.request.Request(
            f"http://{ip}:{ADMIN_PORT}/api/config", data=body, method="PUT",
            headers={"Content-Type": "application/json", "Authorization": _auth_header(),
                     "X-Sync-From": NODE_IP or "unknown"},
        )
        try:
            with OPENER.open(req, timeout=HC_PEER_TIMEOUT) as resp:
                return "ok" if resp.status == 200 else f"HTTP {resp.status}"
        except urllib.error.HTTPError as e:
            detail = e.read(300).decode("utf-8", "replace")
            return f"HTTP {e.code}: {detail}"
        except Exception as e:
            return f"{type(e).__name__}: {getattr(e, 'reason', e)}"

    if not peers:
        return {}
    with ThreadPoolExecutor(max_workers=len(peers)) as pool:
        return dict(zip(peers, pool.map(one, peers)))


# ------------------------------------------------------------------ веб-админка

class Admin(BaseHTTPRequestHandler):
    server_version = "dns-admin"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code: int, body, ctype="application/json; charset=utf-8"):
        if not isinstance(body, (bytes, bytearray)):
            body = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _authed(self) -> bool:
        expected = _auth_header()
        got = self.headers.get("Authorization", "")
        if ADMIN_PASSWORD and hmac.compare_digest(got.encode(), expected.encode()):
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="dns-admin", charset="UTF-8"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 1_000_000:
            raise ValueError("слишком большой запрос")
        return json.loads(self.rfile.read(n) or b"null")

    def do_GET(self):
        if not self._authed():
            return
        if self.path in ("/", "/index.html"):
            with open(ADMIN_HTML, "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if self.path == "/api/state":
            with LOCK:
                snap = copy.deepcopy(STATE)
            snap["node"] = NODE_IP
            snap["now"] = time.time()
            return self._send(200, snap)
        self._send(404, {"error": "нет такого адреса"})

    def do_PUT(self):
        if not self._authed():
            return
        if self.path != "/api/config":
            return self._send(404, {"error": "нет такого адреса"})
        try:
            new = validate(self._body())
        except (ValueError, json.JSONDecodeError) as e:
            return self._send(400, {"error": str(e)})
        with LOCK:
            cur = STATE["config"]
        if cur and new["zone"] != cur["zone"]:
            return self._send(400, {"error": "zone менять нельзя: на неё завязан Corefile"})
        write_config(new)
        from_peer = self.headers.get("X-Sync-From")
        log(f"config saved ({'from ' + from_peer if from_peer else 'via admin'})")
        peers = {} if from_peer else push_to_peers(new)
        if not from_peer:
            with LOCK:
                STATE["last_sync"] = {"at": time.time(), "peers": peers}
        WAKE.set()
        self._send(200, {"ok": True, "peers": peers})

    def do_POST(self):
        if not self._authed():
            return
        if self.path == "/api/sync":
            with LOCK:
                cfg = STATE["config"]
            if not cfg:
                return self._send(409, {"error": "нет валидного конфига"})
            peers = push_to_peers(cfg)
            with LOCK:
                STATE["last_sync"] = {"at": time.time(), "peers": peers}
            return self._send(200, {"ok": True, "peers": peers})
        if self.path == "/api/check":
            WAKE.set()
            return self._send(200, {"ok": True})
        self._send(404, {"error": "нет такого адреса"})


def start_admin() -> None:
    if not ADMIN_PASSWORD:
        log("ADMIN_PASSWORD не задан: админка выключена")
        return
    srv = ThreadingHTTPServer((NODE_IP or "0.0.0.0", ADMIN_PORT), Admin)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    log(f"admin: http://{NODE_IP or '0.0.0.0'}:{ADMIN_PORT}/")


# ------------------------------------------------------------------ основной цикл

def main() -> None:
    os.makedirs(os.path.dirname(CONFIG), exist_ok=True)
    start_admin()
    pool = ThreadPoolExecutor(max_workers=HC_WORKERS)
    serial = int(time.time())
    last_zone_state, last_alive, cfg = None, {}, None

    while True:
        WAKE.clear()
        try:
            cfg = read_config()
            err = None
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            if cfg is None:
                log(f"config error, жду исправления: {err}")
                with LOCK:
                    STATE["config_error"] = err
                WAKE.wait(3)
                continue

        if not os.path.exists(zone_path(cfg)):
            # первая зона со всеми включёнными IP, чтобы CoreDNS было что читать сразу
            first = {n: [x["ip"] for x in r["ips"] if x["enabled"]] for n, r in cfg["records"].items()}
            write_zone(cfg, render_zone(cfg, first, serial))
            log(f"initial zone written: {zone_path(cfg)}")

        checks = run_checks(cfg, pool)
        answers, modes, alive = compute_answers(cfg, checks)

        zone_state = json.dumps({"a": answers, "ttl": cfg["ttl"], "ns": cfg["nameservers"]}, sort_keys=True)
        if zone_state != last_zone_state:
            serial = max(serial + 1, int(time.time()))
            write_zone(cfg, render_zone(cfg, answers, serial))
            last_zone_state = zone_state
            log(f"zone written serial={serial}")
        for name in cfg["records"]:
            if alive.get(name) != last_alive.get(name):
                all_ips = [x["ip"] for x in cfg["records"][name]["ips"]]
                off = [x["ip"] for x in cfg["records"][name]["ips"] if not x["enabled"]]
                dead = sorted(set(all_ips) - set(alive[name]) - set(off))
                log(f"zone changed {name}: alive={alive[name]} dead={dead} off={off} mode={modes[name]}")
                if modes[name] == "fail-open":
                    log(f"WARNING {name}: все включённые бэкенды лежат, отдаю их все (fail-open)")
        last_alive = alive

        with LOCK:
            STATE.update(config=cfg, config_error=err, checks=checks, answers=answers,
                         modes=modes, serial=serial, last_cycle=time.time())
        WAKE.wait(cfg["interval"])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
