from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Site:
    name: str
    base_url: str
    # Pages whose loaded scripts are fingerprinted. Payment pages are "critical".
    watch_pages: list[str] = field(default_factory=lambda: ["/"])
    payment_pages: list[str] = field(default_factory=list)
    # WooCommerce: put this product in a throwaway cart so /checkout/ renders.
    # "auto" picks the first purchasable product from the Store API.
    checkout_product_id: str | int | None = None
    # Findings the owner has already dealt with or scheduled:
    # {finding_key: {"note": "...", "until": date (optional)}}
    acknowledged: dict = field(default_factory=dict)
    # Owner's own statements for guideline items site-guard cannot see (see guideline.py).
    declared: dict = field(default_factory=dict)
    # Notable events for the monthly report: [{date, text}]
    events: list = field(default_factory=list)

    @property
    def domain(self) -> str:
        return self.base_url.split("://", 1)[1].split("/", 1)[0]


@dataclass
class Settings:
    sites: list[Site]
    tls_warn_days: int = 21
    user_agent: str = "site-guard/0.1 (owner self-monitoring)"
    discord_webhook_url: str | None = None


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def load_settings(path: Path | None = None, require_sites: bool = True) -> Settings:
    load_dotenv(ROOT / ".env")
    path = path or ROOT / "config" / "sites.toml"
    raw = tomllib.loads(path.read_text())
    sites = [Site(**s) for s in raw.get("site", [])]
    if not require_sites:
        sites = [s for s in sites if s.domain not in ("example.com", "www.example.com")]
    placeholders = [s.name for s in sites if s.domain in ("example.com", "www.example.com")]
    if placeholders and require_sites:
        raise SystemExit("config/sites.toml の base_url が example.com のままです。"
                         "自分のサイトのURLに書き換えてください。")
    general = raw.get("general", {})
    return Settings(
        sites=sites,
        tls_warn_days=general.get("tls_warn_days", 21),
        user_agent=general.get("user_agent", Settings.user_agent),
        discord_webhook_url=os.environ.get("DISCORD_WEBHOOK_URL") or None,
    )
