# -*- coding: utf-8 -*-
"""
Comparatif d'empreinte TLS pour le scraping :
- Requête A : requests (classique)
- Requête B : noble-tls (imitation navigateur)
Affiche JA3, UA, ALPN, H2/H3, et un verdict de cohérence.

Prérequis :
  pip install requests noble-tls

Exécuter :
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
        # UA Chrome "classique", volontairement incohérent avec l'empreinte TLS de requests
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
            "Le module noble_tls n'est pas disponible. Installez-le : pip install noble-tls"
        )

    # Met à jour les profils si nécessaire (empreintes navigateurs)
    await noble_tls.update_if_necessary()

    # Choisissez le profil qui vous intéresse (Chrome/Firefox/Safari/iOS/Android…)
    session = noble_tls.Session(
        client=Client.CHROME_124,  # ex: Client.FIREFOX_126, Client.SAFARI_17, etc.
        # proxy="http://user:pass@host:port",  # décommentez si besoin d'un proxy
        debug=False,
    )

    headers = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
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
    # Heuristique simple : on ne connaît pas la vraie table des JA3 Chrome/Firefox ici,
    # mais on peut indiquer le risque de mismatch si UA annonce un navigateur populaire
    # alors que la pile TLS est manifestement non-navigateur (cas typique de requests).
    if "chrome" in ua_l or "chromium" in ua_l or "edg" in ua_l:
        # JA3 de requests/OpenSSL ne ressemble pas à un vrai Chrome généralement
        # On affiche un warning générique si la chaîne est courte/atypique
        if ja3 and "," in ja3 and "-" in ja3:
            # On ne valide pas formellement (pas de base blanche), juste un message indicatif
            return "→ Cohérence probable si le client est un vrai navigateur. Vérifiez côté serveur si nécessaire."
        return "⚠️ Possible mismatch UA↔JA3 (empreinte non navigateur)."
    if "firefox" in ua_l or "safari" in ua_l or "ios" in ua_l or "android" in ua_l:
        if ja3 and "," in ja3 and "-" in ja3:
            return "→ Cohérence probable si l'empreinte est bien celle du client déclaré."
        return "⚠️ Possible mismatch UA↔JA3."
    # UA générique : on reste neutre
    return "ℹ️ Impossible d’évaluer la cohérence sans base de JA3 connue."


def p(s):  # petit helper d’affichage
    return s if s is not None else "—"


def main():
    print("\n=== A) Requête avec requests (pile TLS Python/OpenSSL) ===")
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
        print("Erreur requests:", e, file=sys.stderr)

    print("\n=== B) Requête avec noble-tls (imitation navigateur) ===")
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
        print("Erreur noble-tls:", e, file=sys.stderr)

    print("\nAstuce : si A montre un JA3 typique d’OpenSSL et B un JA3 ‘navigateur’, "
          "vous verrez la différence immédiatement. "
          "Côté sites très protégés, d’autres signaux (cookies, JS, timings) peuvent aussi compter.")


if __name__ == "__main__":
    main()
