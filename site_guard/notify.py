from __future__ import annotations

import os

import requests

from .models import SEVERITY_EMOJI, SEVERITY_ORDER, Finding

DISCORD_LIMIT = 1900  # Discord caps message content at 2000 chars


RUNBOOK_ANCHORS = {
    "scripts": "scripts--決済カートのスクリプトが変化した-",
    "dns": "dns--dnsレコードが変わった-",
    "tls": "tls--ssl証明書の期限エラー",
    "mail": "mail--spf--dmarc",
    "wordpress": "wordpress--headers--露出設定不足",
    "headers": "wordpress--headers--露出設定不足",
}


def runbook_url(check: str) -> str | None:
    """Link into RUNBOOK.md on GitHub (available when running in Actions)."""
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        return None
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    anchor = RUNBOOK_ANCHORS.get(check, "")
    return f"{server}/{repo}/blob/main/RUNBOOK.md" + (f"#{anchor}" if anchor else "")


def format_finding(f: Finding) -> str:
    parts = [f"{SEVERITY_EMOJI.get(f.severity, '')} **[{f.site}] {f.title}** ({f.severity})"]
    if f.detail:
        parts.append("```\n" + f.detail[:800] + "\n```")
    if f.fix:
        parts.append(f"対処: {f.fix}")
    link = runbook_url(f.check)
    if link and f.severity in ("critical", "high"):
        parts.append(f"📖 対応手順: <{link}>")
    return "\n".join(parts)


def chunk(messages: list[str], limit: int = DISCORD_LIMIT) -> list[str]:
    out, cur = [], ""
    for m in messages:
        m = m[:limit]
        if cur and len(cur) + len(m) + 2 > limit:
            out.append(cur)
            cur = ""
        cur = f"{cur}\n\n{m}" if cur else m
    if cur:
        out.append(cur)
    return out


def send_discord(webhook_url: str, findings: list[Finding], header: str) -> None:
    bodies = chunk([header] + [format_finding(f) for f in findings])
    for body in bodies:
        r = requests.post(webhook_url, json={"content": body, "username": "Site Guard"}, timeout=15)
        r.raise_for_status()


def resolved_message(site_name: str, titles: list[str]) -> str:
    lines = [f"✅ Site Guard: **{site_name}** — 解消 {len(titles)} 件"]
    lines += [f"- ~~{t}~~" for t in titles]
    return "\n".join(lines)[:DISCORD_LIMIT]


def send_resolved(webhook_url: str, site_name: str, titles: list[str]) -> None:
    r = requests.post(webhook_url, json={"content": resolved_message(site_name, titles), "username": "Site Guard"}, timeout=15)
    r.raise_for_status()


def status_report(site_name: str, findings: list[Finding]) -> list[str]:
    """Weekly digest: say plainly whether anything needs the owner, and list
    what is already handled or scheduled separately so it doesn't read as an alarm."""
    action = [f for f in findings if not f.acknowledged and f.severity != "info"]
    calm = [f for f in findings if f.acknowledged or f.severity == "info"]
    worst = min((SEVERITY_ORDER.get(f.severity, 9) for f in action), default=9)
    light = {0: "🔴", 1: "🔴", 2: "🟠", 3: "🟡"}.get(worst, "🟢")
    if action:
        head = f"{light} **{site_name}** — 対応が必要な項目が {len(action)} 件あります"
    else:
        head = f"🟢 **{site_name}** — 今週の状態：問題なし（対応が必要な項目はありません）"
    parts = [head]
    for f in action:
        text = format_finding(f)
        if f.ack_expired:
            text += f"\n⏰ 予定日を過ぎました（予定: {f.ack_note}）"
        parts.append(text)
    if calm:
        lines = ["**対策済み・計画どおり進んでいる項目**"]
        for f in calm:
            mark = "🗓️" if f.acknowledged and "予定" in f.ack_note else ("✅" if f.acknowledged else "ℹ️")
            note = f.ack_note if f.acknowledged else f.fix
            lines.append(f"{mark} {f.title}\n　→ {note}")
        parts.append("\n".join(lines))
    return chunk(parts)


def send_status_report(webhook_url: str, site_name: str, findings: list[Finding]) -> None:
    for body in status_report(site_name, findings):
        r = requests.post(webhook_url, json={"content": body, "username": "Site Guard"}, timeout=15)
        r.raise_for_status()
