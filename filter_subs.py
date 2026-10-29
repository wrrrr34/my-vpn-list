#!/usr/bin/env python3
"""Fetch public VLESS/Trojan subscriptions, drop junk, dedupe, write a clean one.

Usage:
  python filter_subs.py                  # fetch SOURCES, write subscription.txt
  python filter_subs.py --input a.txt    # test on a local file instead of fetching
  python filter_subs.py --reality-only   # keep ONLY Reality servers (default also keeps TLS ws/grpc/xhttp)
  python filter_subs.py --no-alive       # skip the TCP liveness check

The TCP check runs from wherever the script runs (e.g. a GitHub runner), so it only
proves the server is up, NOT that YouTube works through it from your Megafon.
"""
import argparse
import base64
import re
import socket
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, unquote, urlsplit

# Each source = list of mirrors, tried in order.
SOURCES = [
    [
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
        "https://cdn.jsdelivr.net/gh/igareck/vpn-configs-for-russia@main/BLACK_VLESS_RUS_mobile.txt",
    ],
    [
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
        "https://cdn.jsdelivr.net/gh/igareck/vpn-configs-for-russia@main/BLACK_VLESS_RUS.txt",
    ],
]

MAX_SERVERS = 40
TCP_TIMEOUT = 4

# Substrings in host/sni/host-header/name that mark "good ping, no real exit" or junk.
BAD_SUBSTR = (
    "fastly", "workers.dev", "pages.dev", "railway.app", "onappjet.com",
    "anycast", "cloudflare-ech", "trycloudflare", "herokuapp", "vercel.app",
)
BAD_TLD = (".ir", ".ru", ".su", ".by")  # Iran-targeted junk, and RU/BY exits (no YouTube)


def fetch(mirrors):
    for url in mirrors:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = r.read().decode("utf-8", "replace")
            return data
        except Exception as e:  # try next mirror
            print(f"[warn] {url}: {e}", file=sys.stderr)
    return ""


def maybe_b64(text):
    t = text.strip()
    if "://" in t:
        return text
    try:
        return base64.b64decode(t + "=" * (-len(t) % 4)).decode("utf-8", "replace")
    except Exception:
        return text


def country(name):
    # two regional-indicator chars = flag emoji
    flag = re.findall(r"[\U0001F1E6-\U0001F1FF]{2}", name)
    if flag:
        return "".join(chr(ord(c) - 0x1F1E6 + 65) for c in flag[0])
    return "XX"


def parse(line):
    line = line.strip()
    if not (line.startswith("vless://") or line.startswith("trojan://")):
        return None
    sp = urlsplit(line)
    if not sp.hostname or not sp.port:
        return None
    q = {k: v[0] for k, v in parse_qs(sp.query).items()}
    return {
        "raw": line,
        "scheme": sp.scheme,
        "user": sp.username or "",
        "host": sp.hostname.lower(),
        "port": sp.port,
        "q": q,
        "name": unquote(sp.fragment),
    }


def is_bad(p, allow_tls):
    q = p["q"]
    sec = q.get("security", "")
    if sec == "reality":
        if not q.get("pbk"):
            return True
    elif sec == "tls" and allow_tls:
        pass
    else:
        return True  # none / empty / tls (when not allowed)
    fields = " ".join([p["host"], q.get("sni", ""), q.get("host", ""), p["name"]]).lower()
    if any(s in fields for s in BAD_SUBSTR):
        return True
    for f in (p["host"], q.get("sni", "").lower(), q.get("host", "").lower()):
        if f and any(f.endswith(t) for t in BAD_TLD):
            return True
    if country(p["name"]) in ("RU", "BY", "IR"):
        return True
    return False


def key(p):
    q = p["q"]
    return (p["scheme"], p["user"], p["host"], p["port"], q.get("sni"), q.get("pbk"),
            q.get("sid"), q.get("type"), q.get("serviceName") or q.get("path"))


def tcp_alive(p):
    try:
        with socket.create_connection((p["host"], p["port"]), timeout=TCP_TIMEOUT):
            return True
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input")
    ap.add_argument("--output", default="subscription.txt")
    ap.add_argument("--reality-only", action="store_true")
    ap.add_argument("--no-alive", action="store_true")
    a = ap.parse_args()

    texts = []
    if a.input:
        texts.append(open(a.input, encoding="utf-8").read())
    else:
        texts = [fetch(m) for m in SOURCES]

    seen, items = set(), []
    total = 0
    for t in texts:
        for line in maybe_b64(t).splitlines():
            p = parse(line)
            if not p:
                continue
            total += 1
            if is_bad(p, not a.reality_only):
                continue
            k = key(p)
            if k in seen:
                continue  # same server, different fingerprint variant
            seen.add(k)
            p["raw"] = re.sub(r"([?&])fp=[^&#]*", r"\1fp=chrome", p["raw"].split("#")[0])
            items.append(p)

    kept_pre = len(items)
    if not a.no_alive:
        with ThreadPoolExecutor(32) as ex:
            alive = list(ex.map(tcp_alive, items))
        items = [p for p, ok in zip(items, alive) if ok]

    items = items[:MAX_SERVERS]
    print(f"parsed={total} after_filter={kept_pre} alive_kept={len(items)}")
    if not items:
        sys.exit(1)  # don't overwrite a good file with an empty one in CI
    out = [
        "# profile-title: Custom clean (auto)",
        "# profile-update-interval: 6",
    ]
    for i, p in enumerate(items, 1):
        t = p["q"].get("type", "tcp")
        out.append(f"{p['raw']}#{i:02d}-{country(p['name'])}-{p['q'].get('security')}-{t}")
    with open(a.output, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
