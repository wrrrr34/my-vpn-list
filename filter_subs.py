#!/usr/bin/env python3
"""Fetch public VLESS/Trojan subscriptions, drop junk, dedupe, write a clean one.

Usage:
  python filter_subs.py                  # fetch SOURCES, write subscription.txt
  python filter_subs.py --input a.txt    # test on a local file instead of fetching
  python filter_subs.py --reality-only   # keep ONLY Reality servers (default also keeps TLS ws/grpc/xhttp)
  python filter_subs.py --no-check       # skip the TCP+TLS handshake check (on by default)
  python filter_subs.py --drop-ru        # drop servers in Russia (kept by default: RU entry IPs are how whitelist-bypass relays work)

The TCP check runs from wherever the script runs (e.g. a GitHub runner), so it only
proves the server is up, NOT that YouTube works through it from your Megafon.
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

# Each source = list of mirrors, tried in order.
SOURCES = [
    [
        "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
        "https://cdn.jsdelivr.net/gh/whoahaow/rjsxrd@main/githubmirror/bypass/bypass-all.txt",
    ],
]

MAX_SERVERS = 150
TCP_TIMEOUT = 4

# Substrings in host/sni/host-header/name that mark "good ping, no real exit" or junk.
BAD_SUBSTR = (
    "workers.dev", "pages.dev", "railway.app", "onappjet.com",
    "cloudflare-ech", "trycloudflare", "herokuapp", "vercel.app",
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


def bad_reason(p, allow_tls, drop_fastly=False, drop_ru=False):
    """Return a short reason string if the server should be dropped, else None."""
    q = p["q"]
    sec = q.get("security", "")
    if sec == "reality":
        if not q.get("pbk"):
            return "reality-no-pbk"
    elif sec == "tls" and allow_tls:
        pass
    else:
        return "no-reality-or-tls"
    # Things the sing-box core inside Hiddify cannot run; one bad outbound can break the whole profile.
    if q.get("encryption", "none") not in ("none", ""):
        return "vless-encryption"
    if "ech" in q:
        return "ech-param"
    if "fm" in q:
        return "fragment-param"
    if "anycast" in p["name"].lower():
        return "name-anycast"
    fields = " ".join([p["host"], q.get("sni", ""), q.get("host", "")]).lower()
    if any(s in fields for s in BAD_SUBSTR):
        return "junk-host"
    if drop_fastly and "fastly" in fields:
        return "fastly"
    # server address: drop .ir and RU/BY/SU (a RU exit cannot open YouTube)
    tlds = BAD_TLD if drop_ru else (".ir",)
    if any(p["host"].endswith(t) for t in tlds):
        return "bad-server-tld"
    # SNI / Host header may legitimately be a .ru site (Reality masks as one); drop only .ir
    for f in (q.get("sni", "").lower(), q.get("host", "").lower()):
        if f.endswith(".ir"):
            return "iran-sni"
    if country(p["name"]) in (("RU", "BY", "IR") if drop_ru else ("IR",)):
        return "flag-filter"
    return None


def key(p):
    q = p["q"]
    # sni is NOT part of the key: same host+port+user = same server
    return (p["scheme"], p["user"], p["host"], p["port"], q.get("pbk"),
            q.get("type"), q.get("serviceName") or q.get("path"))


def check_server(p):
    """True if TCP connects AND a TLS handshake with the declared SNI completes.
    Catches dead servers. Cannot see Russian blocking (the runner is abroad)."""
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


def ru_hosts(items):
    """Hosts whose IP geolocates to Russia (ip-api.com, free, HTTP). Empty set on any failure."""
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
            return set()
        for row in res:
            if row.get("status") == "success":
                cc[row["query"]] = row.get("countryCode")
        if i + 100 < len(uniq):
            time.sleep(5)
    return {h for h, ip in ips.items() if cc.get(ip) == "RU"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input")
    ap.add_argument("--output", default="subscription.txt")
    ap.add_argument("--reality-only", action="store_true")
    ap.add_argument("--drop-fastly", action="store_true")
    ap.add_argument("--no-check", action="store_true")
    ap.add_argument("--drop-ru", action="store_true")
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
            why = bad_reason(p, not a.reality_only, a.drop_fastly, a.drop_ru)
            if why:
                reasons[why] = reasons.get(why, 0) + 1
                continue
            k = key(p)
            if k in seen:
                reasons["duplicate"] = reasons.get("duplicate", 0) + 1
                continue  # same server, different fingerprint variant
            seen.add(k)
            raw = re.sub(r"([?&])fp=[^&#]*", r"\1fp=chrome", p["raw"].split("#")[0])
            raw = raw.replace("type=raw", "type=tcp")  # Xray's new name for tcp; older parsers choke on it
            if "fp=" not in raw:
                raw += ("&" if "?" in raw else "?") + "fp=chrome"
            p["raw"] = raw
            items.append(p)

    if a.drop_ru:
        ru = ru_hosts(items)
        rest = [p for p in items if p["host"] not in ru]
        if len(rest) >= 5:
            reasons["ru-ip"] = len(items) - len(rest)
            items = rest
        elif ru:
            print("[warn] RU filter would leave <5 servers, ignoring it")

    kept_pre = len(items)
    if not a.no_check:
        with ThreadPoolExecutor(32) as ex:
            ok = list(ex.map(check_server, items))
        good = [p for p, k in zip(items, ok) if k]
        if len(good) >= 5:
            reasons["dead-tls-check"] = len(items) - len(good)
            items = good
        else:  # runner probably blocked: don't throw the list away
            print("[warn] TLS check left <5 servers, ignoring its result")

    items.sort(key=lambda p: p["q"].get("security") != "reality")  # Reality first
    items = items[:MAX_SERVERS]
    print(f"parsed={total} after_filter={kept_pre} alive_kept={len(items)}")
    print("dropped:", reasons)
    if not items:
        sys.exit(1)  # don't overwrite a good file with an empty one in CI
    out = [
        "# profile-title: Custom clean (auto)",
        "# profile-update-interval: 3",
    ]
    for i, p in enumerate(items, 1):
        t = p["q"].get("type", "tcp")
        out.append(f"{p['raw']}#{i:02d}-{country(p['name'])}-{p['q'].get('security')}-{t}")
    with open(a.output, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
