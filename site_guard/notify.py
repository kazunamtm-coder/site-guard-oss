from __future__ import annotations

import os

import requests

from .explain import explain, tech_block
from .models import SEVERITY_ORDER, Finding

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
    p = explain(f)
    parts = [f"{p.icon} **{p.label}｜[{f.site}] {p.headline}**",
             f"**何が起きているか**：{p.what}",
             f"**放っておくと**：{p.risk}",
             "**あなたがやること**\n" + "\n".join(f"{i}. {t}" for i, t in enumerate(p.todo, 1))]
    parts.append("制作会社・技術者の方へ：\n```\n" + tech_block(f)[:700] + "\n```")
    link = runbook_url(f.check)
    if link and p.level <= 1:
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
    """Weekly summary for the owner: what to do this week, most important first,
    and what happens if it is left alone. Handled/scheduled items are listed
    separately so they don't read as alarms."""
    todo = [f for f in findings if not f.acknowledged and f.severity != "info"]
    todo.sort(key=lambda f: (explain(f).level, SEVERITY_ORDER.get(f.severity, 9)))
    urgent = [f for f in todo if explain(f).level <= 2]
    later = [f for f in todo if explain(f).level > 2]
    calm = [f for f in findings if f.acknowledged or f.severity == "info"]

    if urgent:
        head = (f"{explain(urgent[0]).icon} **{site_name}** — やることが {len(urgent)} 件あります。"
                "上から順に対応してください。")
    else:
        head = f"🟢 **{site_name}** — 今週、急いでやることはありません。"
    parts = [head]
    if urgent:
        lines = ["**やること（大事な順）**"]
        for i, f in enumerate(urgent, 1):
            p = explain(f)
            line = f"{i}. {p.icon} {p.label}：{p.headline}\n　放っておくと：{p.risk}"
            if f.ack_expired:
                line += f"\n　⏰ 予定日を過ぎています（予定：{f.ack_note}）"
            lines.append(line)
        lines.append("くわしい手順は、それぞれの知らせのメールに書いてあります。")
        parts.append("\n".join(lines))
    if later:
        parts.append("\n".join(["**急ぎではないこと**"] + [f"・{explain(f).headline}" for f in later]))
    if calm:
        lines = ["**対応ずみ・予定どおりのこと**"]
        for f in calm:
            p = explain(f)
            note = f.ack_note if f.acknowledged else p.what
            lines.append(f"✅ {p.headline}\n　→ {note}")
        parts.append("\n".join(lines))
    return chunk(parts)


def send_status_report(webhook_url: str, site_name: str, findings: list[Finding]) -> None:
    for body in status_report(site_name, findings):
        r = requests.post(webhook_url, json={"content": body, "username": "Site Guard"}, timeout=15)
        r.raise_for_status()
