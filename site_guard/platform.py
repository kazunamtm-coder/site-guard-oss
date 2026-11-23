"""Guess which platform a shop runs on from its public homepage.

The platform decides which risks matter: a self-hosted WordPress/EC-CUBE shop
is responsible for its own server; Shopify/BASE are hosted by the platform.
"""
from __future__ import annotations

import re

# (name, hosted_by_platform, patterns matched against HTML + headers)
SIGNATURES: list[tuple[str, bool, list[str]]] = [
    ("Shopify", True, [r"cdn\.shopify\.com", r"Shopify\.theme", r"x-shopid", r"myshopify\.com"]),
    ("BASE", True, [r"thebase\.in", r"base-ec\d*\.imgix\.net", r"static\.thebase\.in"]),
    ("STORES", True, [r"stores\.jp", r"storesjp"]),
    ("カラーミーショップ", True, [r"shop-pro\.jp", r"colorme"]),
    ("MakeShop", True, [r"makeshop\.jp"]),
    ("EC-CUBE", False, [r"eccube", r"ec-cube", r"/html/template/default/", r"ECCUBE"]),
    ("WooCommerce", False, [r"woocommerce", r"wc-block", r"/wp-json/wc/"]),
    ("Welcart", False, [r"usc-e-shop", r"welcart"]),
    ("WordPress", False, [r"/wp-content/", r"/wp-includes/", r'name="generator" content="WordPress']),
    ("Lovable", True, [r"lovable", r"gptengineer"]),
    ("Wix", True, [r"wixstatic\.com", r"x-wix-"]),
    ("STUDIO", True, [r"studio\.design", r"studiodesign"]),
]


def detect(html: str, headers: dict[str, str]) -> list[str]:
    blob = html[:300_000] + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
    found = []
    for name, _, pats in SIGNATURES:
        if any(re.search(p, blob, re.I) for p in pats):
            found.append(name)
    # WooCommerce/Welcart imply WordPress; keep the more specific first.
    if ("WooCommerce" in found or "Welcart" in found) and "WordPress" in found:
        found.remove("WordPress")
        found.append("WordPress")
    return found


def is_self_hosted(platforms: list[str]) -> bool | None:
    """True = the owner runs the server (owner is responsible for patching)."""
    hosted = {n: h for n, h, _ in SIGNATURES}
    known = [p for p in platforms if p in hosted]
    if not known:
        return None
    return not hosted[known[0]]
