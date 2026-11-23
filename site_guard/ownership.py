"""Proof that the person running site-guard controls the domain.

Checks that look like an attack from the outside (hidden-file probes, user
enumeration, xmlrpc) and actions that change state on the site (putting a
product in a throwaway cart to render the checkout page) only run after the
domain owner has published a DNS TXT record. Only someone who can edit the
domain's DNS can add it, so the gate holds even though this code is public.

Being listed in config/sites.toml is NOT proof: anyone can type any URL there.
"""
from __future__ import annotations

import hashlib

from .checks import mail_dns


def verify_token(domain: str) -> str:
    return "site-guard-verify=" + hashlib.sha256(f"site-guard:{domain}".encode()).hexdigest()[:24]


def _candidates(domain: str) -> list[str]:
    """Names to look for the TXT record on. www.example.com may be proven by
    the record on example.com, because the owner of example.com controls www."""
    names = [domain]
    if domain.startswith("www."):
        names.append(domain.removeprefix("www."))
    return names


def is_verified(domain: str) -> tuple[bool, str]:
    for d in _candidates(domain):
        token = verify_token(d)
        for name in (f"_site-guard.{d}", d):
            try:
                if token in mail_dns.txt_records(name):
                    return True, f"DNS TXT（{name}）で所有者確認済み"
            except Exception:  # noqa: BLE001 - DNS failure just means "not verified"
                pass
    return False, "所有者確認なし（外から誰でも見える範囲だけ点検）"


def instructions(domain: str) -> str:
    d = domain.removeprefix("www.")
    return (f"DNSにTXTレコードを追加してください: ホスト名 `_site-guard.{d}` / 値 `{verify_token(d)}`\n"
            "追加後、反映まで数分〜1時間ほどかかることがあります。")
