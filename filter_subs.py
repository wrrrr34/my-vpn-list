#!/usr/bin/env python3
"""Fetch public VLESS/Trojan/Hysteria2 subscriptions, drop junk + blocked countries, dedupe, write a clean one.

Always drops: Russia, Belarus, Iran, China (and similar places where YouTube/AI are blocked or useless for our goals).
Keeps only servers that pass a basic TCP+TLS check when possible.
"""
import argparse
import base64
import json
import re
import socket
import ssl
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, unquote, urlsplit

SOURCES = [
    [
        "https://raw.githubusercontent.com/Subzio/subzio/main/ALL.txt",
        "https://cdn.jsdelivr.net/gh/Subzio/subzio@main/ALL.txt",
    ],
    [
        "https://raw.githubusercontent.com/Subzio/subzio/main/HYSTERIA2.txt",
        "https://cdn.jsdelivr.net/gh/Subzio/subzio@main/HYSTERIA2.txt",
    ],
    [
        "https://raw.githubusercontent.com/3inker/v2ray-subscription/main/all_not_ru.txt",
        "https://cdn.jsdelivr.net/gh/3inker/v2ray-subscription@main/all_not_ru.txt",
    ],
    [
        "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
        "https://cdn.jsdelivr.net/gh/whoahaow/rjsxrd@main/githubmirror/bypass/bypass-all.txt",
    ],
]

MAX_SERVERS = 120
TCP_TIMEOUT = 3.5

BAD_SUBSTR = (
    "workers.dev", "pages.dev", "railway.app", "onappjet.com",
    "cloudflare-ech", "trycloudflare", "herokuapp", "vercel.app",
    "cfargotunnel",
)

BAD_COUNTRIES = {"RU", "BY", "IR", "CN", "KP", "SY", "CU"}
BAD_TLD = (".ir", ".ru", ".su", ".by", ".cn")


def fetch(mirrors):
    for url in mirrors:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=25) as r:
                data = r.read().decode("utf-8", "replace")
            return data
        except Exception as e:
            print(f"[warn] {url}: {e}", file=sys.stderr)
    return ""


def maybe_b64(text):
    t = text.strip()
    if "://" in t or t.startswith("#"):
        return text
    try:
        return base64.b64decode(t + "=" * (-len(t) % 4)).decode("utf-8", "replace")
    except Exception:
        return text


def country(name):
    flag = re.findall(r"[\U0001F1E6-\U0001F1FF]{2}", name or "")
    if flag:
        return "".join(chr(ord(c) - 0x1F1E6 + 65) for c in flag[0])
    n = (name or "").lower()
    if any(x in n for x in ("russia", "russian", "москва", "рф", "ru ", "-ru", "ru-")):
        return "RU"
    if any(x in n for x in ("iran", "tehran", "иран")):
        return "IR"
    if any(x in n for x in ("china", "beijing", "shanghai", "cn ", "-cn")):
        return "CN"
    return "XX"


def parse(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if not (line.startswith("vless://") or line.startswith("trojan://") or line.startswith("hysteria2://") or line.startswith("hy2://")):
        return None
    if line.startswith("hy2://"):
        line = "hysteria2://" + line[6:]
    sp = urlsplit(line)
    if not sp.hostname:
        return None
    port = sp.port
    if not port:
        if line.startswith("hysteria2://"):
            port = 443
        else:
            return None
    q = {k: v[0] for k, v in parse_qs(sp.query).items()}
    return {
        "raw": line,
        "scheme": sp.scheme,
        "user": sp.username or "",
        "host": sp.hostname.lower(),
        "port": port,
        "q": q,
        "name": unquote(sp.fragment or ""),
    }


def bad_reason(p, allow_tls=True):
    q = p["q"]
    scheme = p["scheme"]

    if scheme in ("hysteria2", "hy2"):
        pass
    else:
        sec = q.get("security", "")
        if sec == "reality":
            if not q.get("pbk"):
                return "reality-no-pbk"
        elif sec == "tls" and allow_tls:
            pass
        elif scheme == "trojan":
            pass
        else:
            return "no-reality-or-tls"

    if q.get("encryption", "none") not in ("none", ""):
        return "vless-encryption"
    if "ech" in q:
        return "ech-param"
    if "fm" in q or "fragment" in q:
        return "fragment-param"
    if "anycast" in (p["name"] or "").lower():
        return "name-anycast"

    fields = " ".join([p["host"], q.get("sni", ""), q.get("host", ""), p["name"] or ""]).lower()
    if any(s in fields for s in BAD_SUBSTR):
        return "junk-host"

    if any(p["host"].endswith(t) for t in BAD_TLD):
        return "bad-server-tld"

    for f in (q.get("sni", "").lower(), q.get("host", "").lower()):
        if f.endswith(".ir") or f.endswith(".cn"):
            return "bad-sni"

    cc = country(p["name"])
    if cc in BAD_COUNTRIES:
        return f"flag-{cc}"

    return None


def key(p):
    q = p["q"]
    return (p["scheme"], p["user"], p["host"], p["port"], q.get("pbk"),
            q.get("type"), q.get("serviceName") or q.get("path") or q.get("obfs"))


def check_server(p):
    if p["scheme"] in ("hysteria2", "hy2"):
        return True
    q = p["q"]
    sni = q.get("sni") or q.get("host") or p["host"]
    try:
        raw = socket.create_connection((p["host"], p["port"]), timeout=TCP_TIMEOUT)
    except Exception:
        return False
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw.settimeout(TCP_TIMEOUT)
        with ctx.wrap_socket(raw, server_hostname=sni):
            return True
    except Exception:
        return False
    finally:
        try:
            raw.close()
        except Exception:
            pass


def geo_filter(items):
    ips = {}
    for p in items:
        try:
            ips[p["host"]] = socket.gethostbyname(p["host"])
        except Exception:
            pass
    uniq = sorted(set(ips.values()))
    cc = {}
    for i in range(0, len(uniq), 100):
        chunk = uniq[i:i + 100]
        body = json.dumps([{"query": ip, "fields": "query,countryCode,status"} for ip in chunk]).encode()
        req = urllib.request.Request("http://ip-api.com/batch", data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                res = json.load(r)
        except Exception as e:
            print(f"[warn] geoip failed: {e}", file=sys.stderr)
            return items
        for row in res:
            if row.get("status") == "success":
                cc[row["query"]] = row.get("countryCode")
        if i + 100 < len(uniq):
            time.sleep(4)
    good = []
    dropped = 0
    for p in items:
        ip = ips.get(p["host"])
        if ip and cc.get(ip) in BAD_COUNTRIES:
            dropped += 1
            continue
        good.append(p)
    if dropped:
        print(f"[info] geoip dropped {dropped} servers from bad countries")
    return good


def write_sub(path, items):
    out = [
        "# profile-title: Clean No-RU (auto)",
        "# profile-update-interval: 2",
        "# profile-web-page-url: https://github.com/wrrrr34/my-vpn-list",
    ]
    for i, p in enumerate(items, 1):
        t = p["q"].get("type", p["scheme"])
        sec = p["q"].get("security", p["scheme"])
        out.append(f"{p['raw']}#{i:02d}-{country(p['name'])}-{sec}-{t}")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input")
    ap.add_argument("--output", default="subscription.txt")
    ap.add_argument("--reality-only", action="store_true")
    ap.add_argument("--no-check", action="store_true")
    a = ap.parse_args()

    texts = []
    if a.input:
        texts.append(open(a.input, encoding="utf-8").read())
    else:
        texts = [fetch(m) for m in SOURCES]

    seen, items = set(), []
    reasons = {}
    total = 0
    for t in texts:
        for line in maybe_b64(t).splitlines():
            p = parse(line)
            if not p:
                continue
            total += 1
            why = bad_reason(p, allow_tls=not a.reality_only)
            if why:
                reasons[why] = reasons.get(why, 0) + 1
                continue
            k = key(p)
            if k in seen:
                reasons["duplicate"] = reasons.get("duplicate", 0) + 1
                continue
            seen.add(k)
            raw = p["raw"].split("#")[0]
            raw = re.sub(r"([?&])fp=[^&#]*", r"\1fp=chrome", raw)
            raw = raw.replace("type=raw", "type=tcp")
            if p["scheme"] in ("vless", "trojan") and "fp=" not in raw:
                raw += ("&" if "?" in raw else "?") + "fp=chrome"
            p["raw"] = raw
            items.append(p)

    items = geo_filter(items)

    kept_pre = len(items)
    if not a.no_check:
        with ThreadPoolExecutor(40) as ex:
            ok = list(ex.map(check_server, items))
        good = [p for p, k in zip(items, ok) if k]
        if len(good) >= 8:
            reasons["dead-check"] = len(items) - len(good)
            items = good
        else:
            print("[warn] live check left too few servers, keeping previous set")

    def sort_key(p):
        scheme = p["scheme"]
        sec = p["q"].get("security", "")
        if scheme in ("hysteria2", "hy2"):
            return (0,)
        if sec == "reality":
            return (1,)
        if scheme == "trojan":
            return (2,)
        return (3,)

    items.sort(key=sort_key)

    print(f"parsed={total} after_filter={kept_pre} alive_kept={len(items)}")
    print("dropped:", dict(sorted(reasons.items(), key=lambda x: -x[1])))
    if not items:
        sys.exit(1)
    write_sub(a.output, items[:MAX_SERVERS])
    print(f"wrote {min(len(items), MAX_SERVERS)} servers -> {a.output}")


if __name__ == "__main__":
    main()
