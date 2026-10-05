"""
WhoAmI: страница с информацией о клиенте и сервере.
Без БД, только stdlib + FastAPI.

Эндпоинты:
  GET /         HTML-страница
  GET /api      то же самое в JSON
  GET /ip       только IP клиента (text/plain), удобно для curl
  GET /health   healthcheck
"""

import html
import ipaddress
import os
import platform
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import fastapi
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

APP_TITLE = os.getenv("APP_TITLE", "WhoAmI")
# Доверять ли заголовкам X-Forwarded-For / X-Real-IP (если сервис за nginx/traefik)
TRUST_PROXY = os.getenv("TRUST_PROXY", "true").lower() in ("1", "true", "yes")
# Скрывать значения этих заголовков на странице
SENSITIVE_HEADERS = {"authorization", "cookie", "proxy-authorization", "x-api-key"}

START_TIME = time.time()
app = FastAPI(title=APP_TITLE, docs_url="/docs", redoc_url=None)


# ---------------------------------------------------------------- клиент

def _ip_kind(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "неизвестно"
    if addr.is_loopback:
        return "loopback"
    if addr.is_private:
        return "частный"
    if addr.is_reserved or addr.is_link_local:
        return "служебный"
    return "публичный"


def client_info(request: Request) -> dict:
    peer_ip = request.client.host if request.client else None
    peer_port = request.client.port if request.client else None
    h = request.headers

    forwarded_chain = [p.strip() for p in h.get("x-forwarded-for", "").split(",") if p.strip()]
    real_ip = peer_ip
    if TRUST_PROXY:
        if forwarded_chain:
            real_ip = forwarded_chain[0]
        elif h.get("x-real-ip"):
            real_ip = h["x-real-ip"].strip()

    headers = {
        k: ("***скрыто***" if k.lower() in SENSITIVE_HEADERS else v)
        for k, v in sorted(h.items())
    }

    return {
        "ip": real_ip,
        "ip_version": _ip_version(real_ip),
        "ip_type": _ip_kind(real_ip) if real_ip else None,
        "peer_ip": peer_ip,
        "peer_port": peer_port,
        "forwarded_for": forwarded_chain,
        "reverse_dns": _reverse_dns(real_ip),
        "method": request.method,
        "url": str(request.url),
        "scheme": h.get("x-forwarded-proto", request.url.scheme),
        "host": h.get("host"),
        "http_version": request.scope.get("http_version"),
        "user_agent": h.get("user-agent"),
        "accept_language": h.get("accept-language"),
        "referer": h.get("referer"),
        "query_params": dict(request.query_params),
        "cookies_count": len(request.cookies),
        "headers": headers,
    }


def _ip_version(ip: str | None):
    try:
        return ipaddress.ip_address(ip).version if ip else None
    except ValueError:
        return None


_DNS_POOL = ThreadPoolExecutor(max_workers=4)


def _reverse_dns(ip: str | None, timeout: float = 1.0):
    """PTR-запись с жёстким таймаутом (gethostbyaddr сам таймаут не поддерживает)."""
    if not ip:
        return None
    try:
        return _DNS_POOL.submit(lambda: socket.gethostbyaddr(ip)[0]).result(timeout=timeout)
    except Exception:
        return None


# ---------------------------------------------------------------- сервер

def _read(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None


def _primary_ip() -> str | None:
    """IP интерфейса, через который идёт исходящий трафик (пакеты не отправляются)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
    except OSError:
        return None


def _all_ips() -> list[str]:
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(info[4][0])
    except OSError:
        pass
    p = _primary_ip()
    if p:
        ips.add(p)
    return sorted(ips)


def _meminfo() -> dict | None:
    raw = _read("/proc/meminfo")
    if not raw:
        return None
    data = {}
    for line in raw.splitlines():
        key, _, val = line.partition(":")
        if key in ("MemTotal", "MemAvailable"):
            data[key] = int(val.split()[0]) * 1024
    if "MemTotal" not in data:
        return None
    total = data["MemTotal"]
    avail = data.get("MemAvailable", 0)
    return {"total": _human(total), "available": _human(avail),
            "used_percent": round((total - avail) / total * 100, 1)}


def _cgroup_memory_limit() -> str | None:
    raw = _read("/sys/fs/cgroup/memory.max") or _read("/sys/fs/cgroup/memory/memory.limit_in_bytes")
    if not raw:
        return None
    raw = raw.strip()
    if raw == "max" or int(raw) > 1 << 60:
        return "без лимита"
    return _human(int(raw))


def _human(n: float) -> str:
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} ПБ"


def _duration(sec: float) -> str:
    sec = int(sec)
    d, sec = divmod(sec, 86400)
    h, sec = divmod(sec, 3600)
    m, s = divmod(sec, 60)
    return (f"{d}д " if d else "") + f"{h:02}:{m:02}:{s:02}"


def _os_name() -> str:
    raw = _read("/etc/os-release")
    if raw:
        for line in raw.splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip('"')
    return f"{platform.system()} {platform.release()}"


def _in_container() -> bool:
    if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"):
        return True
    cg = _read("/proc/1/cgroup") or ""
    return any(x in cg for x in ("docker", "kubepods", "containerd", "lxc"))


def server_info() -> dict:
    now = datetime.now().astimezone()
    sys_uptime = _read("/proc/uptime")
    try:
        load = [round(x, 2) for x in os.getloadavg()]
    except (OSError, AttributeError):
        load = None
    disk = None
    try:
        st = os.statvfs("/")
        total, free = st.f_blocks * st.f_frsize, st.f_bavail * st.f_frsize
        disk = {"total": _human(total), "free": _human(free),
                "used_percent": round((total - free) / total * 100, 1)}
    except (OSError, AttributeError):
        pass

    return {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "primary_ip": _primary_ip(),
        "all_ips": _all_ips(),
        "os": _os_name(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "in_container": _in_container(),
        "cpu_count": os.cpu_count(),
        "load_avg": load,
        "memory": _meminfo(),
        "container_memory_limit": _cgroup_memory_limit(),
        "disk_root": disk,
        "server_time": now.isoformat(timespec="seconds"),
        "utc_time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "timezone": str(now.tzinfo),
        "system_uptime": _duration(float(sys_uptime.split()[0])) if sys_uptime else None,
        "app_uptime": _duration(time.time() - START_TIME),
        "pid": os.getpid(),
        "python": sys.version.split()[0],
        "fastapi": fastapi.__version__,
    }


# ---------------------------------------------------------------- HTML

LABELS = {
    "ip": "IP-адрес", "ip_version": "Версия IP", "ip_type": "Тип адреса",
    "peer_ip": "IP соединения (peer)", "peer_port": "Порт клиента",
    "forwarded_for": "X-Forwarded-For", "reverse_dns": "Обратный DNS",
    "method": "Метод", "url": "URL", "scheme": "Протокол", "host": "Host",
    "http_version": "HTTP", "user_agent": "User-Agent",
    "accept_language": "Языки", "referer": "Referer",
    "query_params": "Query-параметры", "cookies_count": "Cookies (шт.)",
    "hostname": "Hostname", "fqdn": "FQDN", "primary_ip": "Основной IP",
    "all_ips": "Все IP", "os": "ОС", "kernel": "Ядро", "arch": "Архитектура",
    "in_container": "В контейнере", "cpu_count": "CPU (ядер)",
    "load_avg": "Load average (1/5/15)", "memory": "Память",
    "container_memory_limit": "Лимит памяти контейнера", "disk_root": "Диск /",
    "server_time": "Время сервера", "utc_time": "UTC", "timezone": "Часовой пояс",
    "system_uptime": "Аптайм системы", "app_uptime": "Аптайм приложения",
    "pid": "PID", "python": "Python", "fastapi": "FastAPI",
}


def _fmt(v) -> str:
    if v is None or v == [] or v == {}:
        return '<span class="muted">нет</span>'
    if isinstance(v, bool):
        return "да" if v else "нет"
    if isinstance(v, list):
        return ", ".join(html.escape(str(x)) for x in v)
    if isinstance(v, dict):
        return "<br>".join(f"<b>{html.escape(str(k))}</b>: {html.escape(str(x))}" for k, x in v.items())
    return html.escape(str(v))


def _table(data: dict, skip=()) -> str:
    rows = "".join(
        f"<tr><th>{LABELS.get(k, html.escape(k))}</th><td>{_fmt(v)}</td></tr>"
        for k, v in data.items() if k not in skip
    )
    return f"<table>{rows}</table>"


PAGE = """<!doctype html>
<html lang="ru"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  :root {{ --bg:#f5f7fa; --card:#fff; --text:#1f2933; --muted:#7b8794; --accent:#2563eb; --line:#e4e7eb; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--text);
         font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }}
  main {{ max-width:1100px; margin:0 auto; padding:24px 16px; }}
  h1 {{ margin:0 0 4px; font-size:24px; }}
  .hero {{ background:var(--card); border:1px solid var(--line); border-radius:12px;
           padding:20px; margin-bottom:20px; }}
  .ip {{ font:600 32px/1.2 ui-monospace,Consolas,monospace; color:var(--accent); word-break:break-all; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(340px,1fr)); gap:20px; }}
  section {{ background:var(--card); border:1px solid var(--line); border-radius:12px; padding:16px 20px; }}
  h2 {{ font-size:17px; margin:0 0 10px; }}
  table {{ width:100%; border-collapse:collapse; }}
  th, td {{ text-align:left; vertical-align:top; padding:6px 0; border-bottom:1px solid var(--line); }}
  th {{ width:42%; color:var(--muted); font-weight:500; padding-right:12px; }}
  td {{ word-break:break-word; font-family:ui-monospace,Consolas,monospace; font-size:13px; }}
  tr:last-child th, tr:last-child td {{ border-bottom:none; }}
  .muted {{ color:var(--muted); }}
  .full {{ grid-column:1/-1; }}
  footer {{ margin-top:20px; color:var(--muted); font-size:13px; }}
  a {{ color:var(--accent); }}
</style></head>
<body><main>
  <div class="hero">
    <h1>{title}</h1>
    <div class="muted">Ваш IP-адрес</div>
    <div class="ip">{ip}</div>
    <div class="muted">{ip_type}{rdns}</div>
  </div>
  <div class="grid">
    <section><h2>Клиент (запрос)</h2>{client}</section>
    <section><h2>Клиент (браузер)</h2><table id="browser"></table></section>
    <section><h2>Сервер</h2>{server}</section>
    <section><h2>HTTP-заголовки</h2>{headers}</section>
  </div>
  <footer>JSON: <a href="/api">/api</a> · только IP: <a href="/ip">/ip</a> · Swagger: <a href="/docs">/docs</a></footer>
</main>
<script>
  const nav = navigator, scr = screen;
  const rows = {{
    "Часовой пояс": Intl.DateTimeFormat().resolvedOptions().timeZone,
    "Локальное время": new Date().toLocaleString(),
    "Язык": nav.language,
    "Платформа": nav.userAgentData?.platform || nav.platform,
    "Экран": scr.width + "×" + scr.height + " @" + devicePixelRatio + "x",
    "Окно": innerWidth + "×" + innerHeight,
    "Глубина цвета": scr.colorDepth + " бит",
    "Ядер CPU": nav.hardwareConcurrency,
    "Память устройства": nav.deviceMemory ? nav.deviceMemory + " ГБ" : null,
    "Cookies разрешены": nav.cookieEnabled ? "да" : "нет",
    "Do Not Track": nav.doNotTrack,
    "Тип сети": nav.connection?.effectiveType,
    "Сенсорный экран": nav.maxTouchPoints > 0 ? "да" : "нет",
    "Тёмная тема в ОС": matchMedia("(prefers-color-scheme: dark)").matches ? "да" : "нет",
  }};
  const t = document.getElementById("browser");
  for (const [k, v] of Object.entries(rows)) {{
    const tr = t.insertRow();
    const th = document.createElement("th"); th.textContent = k; tr.appendChild(th);
    const td = tr.insertCell();
    if (v === undefined || v === null || v === "") {{ td.innerHTML = '<span class="muted">нет</span>'; }}
    else td.textContent = v;
  }}
</script>
</body></html>"""


# ---------------------------------------------------------------- роуты

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    c = client_info(request)
    s = server_info()
    rdns = f" · {html.escape(c['reverse_dns'])}" if c["reverse_dns"] else ""
    return PAGE.format(
        title=html.escape(APP_TITLE),
        ip=html.escape(c["ip"] or "неизвестно"),
        ip_type=html.escape(f"IPv{c['ip_version']}, {c['ip_type']}" if c["ip_version"] else ""),
        rdns=rdns,
        client=_table(c, skip=("headers",)),
        server=_table(s),
        headers=_table(c["headers"]),
    )


@app.get("/api")
def api(request: Request):
    return JSONResponse({"client": client_info(request), "server": server_info()})


@app.get("/ip", response_class=PlainTextResponse)
def ip(request: Request):
    return (client_info(request)["ip"] or "") + "\n"


@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
