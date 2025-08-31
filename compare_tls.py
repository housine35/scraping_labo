# -*- coding: utf-8 -*-
"""
TLS Fingerprint Comparison for Scraping:
- Request A: requests (standard)
- Request B: noble-tls (browser emulation)
Displays JA3, UA, ALPN, H2/H3, and a consistency verdict.

Requirements:
  pip install requests noble-tls

Run:
  python compare_tls.py
"""

import json
import sys
import asyncio
from textwrap import shorten

import requests

try:
    import noble_tls
    from noble_tls import Client
except Exception as e:
    noble_tls = None

ENDPOINT = "https://tls.peet.ws/api/all"


def fetch_with_requests():
    headers = {
        # Standard Chrome UA, intentionally inconsistent with requests' TLS fingerprint
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,fr;q=0.8",
        "Connection": "keep-alive",
    }
    r = requests.get(ENDPOINT, headers=headers, timeout=20)
    r.raise_for_status()
    data = r.json()
    return {
        "client": "requests/OpenSSL",
        "ua": data.get("browser", {}).get("user_agent") or headers["User-Agent"],
        "ja3": data.get("tls", {}).get("ja3"),
        "alpn": data.get("tls", {}).get("alpn"),
        "http_version": data.get("http", {}).get("version"),
        "tls_version": data.get("tls", {}).get("version"),
        "ip": data.get("ip"),
        "raw": data,
    }


async def fetch_with_nobletls():
    if noble_tls is None:
        raise RuntimeError(
            "The noble_tls module is not available. Install it: pip install noble-tls"
        )

    # Update profiles if necessary (browser fingerprints)
    await noble_tls.update_if_necessary()

    # Choose the desired profile (Chrome/Firefox/Safari/iOS/Android...)
    session = noble_tls.Session(
        client=Client.CHROME_124,  # e.g., Client.FIREFOX_126, Client.SAFARI_17, etc.
        # proxy="http://user:pass@host:port",  # uncomment if a proxy is needed
        debug=False,
    )

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        )
    }
    res = await session.get("https://tls.peet.ws/api/all", headers=headers)

    if res.status_code != 200:
        raise RuntimeError(f"noble-tls status={res.status_code} body={res.text[:200]}")
    data = json.loads(res.text)
    return {
        "client": "noble-tls (Chrome 124)",
        "ua": data.get("browser", {}).get("user_agent"),
        "ja3": data.get("tls", {}).get("ja3"),
        "alpn": data.get("tls", {}).get("alpn"),
        "http_version": data.get("http", {}).get("version"),
        "tls_version": data.get("tls", {}).get("version"),
        "ip": data.get("ip"),
        "raw": data,
    }


def verdict(ua: str, ja3: str) -> str:
    ua_l = (ua or "").lower()
    # Simple heuristic: we don’t know the true JA3 table for Chrome/Firefox here,
    # but we can flag a potential mismatch if the UA claims a popular browser
    # while the TLS stack is clearly non-browser (typical for requests).
    if "chrome" in ua_l or "chromium" in ua_l or "edg" in ua_l:
        # JA3 from requests/OpenSSL usually doesn’t match a real Chrome
        # Display a generic warning if the JA3 string is short/atypical
        if ja3 and "," in ja3 and "-" in ja3:
            # No formal validation (no whitelist), just an indicative message
            return "→ Likely consistent if the client is a real browser. Verify server-side if needed."
        return "⚠️ Possible UA↔JA3 mismatch (non-browser fingerprint)."
    if "firefox" in ua_l or "safari" in ua_l or "ios" in ua_l or "android" in ua_l:
        if ja3 and "," in ja3 and "-" in ja3:
            return "→ Likely consistent if the fingerprint matches the declared client."
        return "⚠️ Possible UA↔JA3 mismatch."
    # Generic UA: remain neutral
    return "ℹ️ Unable to assess consistency without a known JA3 database."


def p(s):  # Small display helper
    return s if s is not None else "—"


def main():
    print("\n=== A) Request with requests (Python/OpenSSL TLS stack) ===")
    try:
        a = fetch_with_requests()
        print(f"Client        : {a['client']}")
        print(f"IP            : {p(a['ip'])}")
        print(f"TLS version   : {p(a['tls_version'])}")
        print(f"HTTP version  : {p(a['http_version'])}")
        print(f"ALPN          : {p(a['alpn'])}")
        print(f"User-Agent    : {shorten(p(a['ua']), width=100)}")
        print(f"JA3           : {p(a['ja3'])}")
        print(f"Diagnostic    : {verdict(a['ua'], a['ja3'])}")
    except Exception as e:
        print("Requests error:", e, file=sys.stderr)

    print("\n=== B) Request with noble-tls (browser emulation) ===")
    try:
        b = asyncio.run(fetch_with_nobletls())
        print(f"Client        : {b['client']}")
        print(f"IP            : {p(b['ip'])}")
        print(f"TLS version   : {p(b['tls_version'])}")
        print(f"HTTP version  : {p(b['http_version'])}")
        print(f"ALPN          : {p(b['alpn'])}")
        print(f"User-Agent    : {shorten(p(b['ua']), width=100)}")
        print(f"JA3           : {p(b['ja3'])}")
        print(f"Diagnostic    : {verdict(b['ua'], b['ja3'])}")
    except Exception as e:
        print("Noble-tls error:", e, file=sys.stderr)

    print("\nTip: If A shows a typical OpenSSL JA3 and B shows a browser-like JA3, "
          "the difference will be immediately visible. "
          "For highly protected sites, other signals (cookies, JS, timings) may also matter.")


if __name__ == "__main__":
    main()