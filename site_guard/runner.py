from __future__ import annotations

from datetime import date, datetime, timezone

import requests

from . import state as state_store
from .checks import mail_dns, scripts, tls, wordpress
from .config import Settings, Site
from .models import SEVERITY_ORDER, Finding
from .ownership import instructions, is_verified


def _session(settings: Settings) -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = settings.user_agent
    return s


def run_site(settings: Settings, site: Site, accept: bool = False, persist: bool = True) -> tuple[list[Finding], list[Finding], list[str]]:
    """Run every check. Returns (all_findings, new_findings, resolved_titles).

    resolved_titles: findings that were open on the last run and are gone now.

    Script fingerprints and DNS records become the new baseline only on the
    first run or when accept=True, so an unexplained change keeps alerting
    until the owner reviews it.
    """
    prev = state_store.load(site.name)
    session = _session(settings)
    findings: list[Finding] = []

    verified, _ = is_verified(site.domain)
    if not verified:
        findings.append(Finding(
            site.name, "ownership", "low", "所有者確認がまだです（外から誰でも見える範囲だけ点検しています）",
            "流出ファイル・ユーザー名の露出・xmlrpc の点検と、決済ページを表示するためのカート投入は、"
            "ドメインの所有者確認が済むまで行いません。",
            instructions(site.domain),
            key="ownership:unverified",
        ))

    findings += tls.check(site, settings.tls_warn_days)
    mail_findings, dns_now = mail_dns.check(site)
    findings += mail_findings
    findings += wordpress.check(session, site, intrusive=verified)

    script_now, script_problems = scripts.collect(_session(settings), site, allow_cart=verified)
    findings += script_problems

    base_scripts = prev.get("scripts", {})
    base_dns = prev.get("dns", {})
    if not accept:
        findings += scripts.diff(site, base_scripts, script_now)
        findings += mail_dns.diff_dns(site, base_dns, dns_now)

    def merge(base: dict, now: dict) -> dict:
        # New pages / record types join the baseline; known ones only on accept.
        return {**now, **base} if not accept else {**base, **now}

    today = datetime.now(timezone.utc).date()
    for f in findings:
        ack = site.acknowledged.get(f.key)
        if ack:
            f.ack_note = ack.get("note", "対応済み")
            until = ack.get("until")
            f.ack_expired = isinstance(until, date) and until < today

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    seen = set(prev.get("open_findings", []))
    new = [f for f in findings if f.key not in seen and not f.acknowledged]
    now_keys = {f.key for f in findings}
    prev_titles = prev.get("open_titles", {})
    resolved = [prev_titles.get(k, k) for k in sorted(seen - now_keys)]

    if persist:
        state_store.save(site.name, {
            **prev,  # keep keys owned by other parts (e.g. issued_issues)
            "scripts": merge(base_scripts, script_now),
            "dns": merge(base_dns, dns_now),
            "open_findings": sorted(now_keys),
            "open_titles": {f.key: f.title for f in findings},
            "last_run": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        })
    return findings, new, resolved
