"""Monthly evidence report (printable HTML → save as PDF from the browser)."""
from __future__ import annotations

import html
from datetime import datetime, timezone, timedelta

from .config import Site
from .guideline import ICON, NA, NG, ASK, PARTIAL, Row
from .models import Finding

JST = timezone(timedelta(hours=9))

CSS = """
@page { size: A4; margin: 16mm 14mm; }
:root { --ink:#1d2433; --muted:#5b6475; --line:#d9dee7; --ok:#1f7a4d; --warn:#a15c00; --ng:#b42318; --ask:#3b5bdb; --bg:#ffffff; --soft:#f5f7fa; }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--ink); font: 14px/1.7 "Hiragino Sans","Noto Sans JP","Yu Gothic",sans-serif; }
main { max-width: 820px; margin: 0 auto; padding: 32px 16px 48px; }
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 16px; margin: 32px 0 8px; padding-bottom: 4px; border-bottom: 2px solid var(--ink); }
.meta { color: var(--muted); font-size: 13px; }
.verdict { margin: 20px 0; padding: 14px 16px; border-radius: 8px; background: var(--soft); border-left: 6px solid var(--ok); }
.verdict.warn { border-color: var(--warn); } .verdict.ng { border-color: var(--ng); }
.verdict strong { font-size: 16px; }
.counts span { display:inline-block; margin-right: 14px; }
table { width: 100%; border-collapse: collapse; margin-top: 8px; }
th, td { border: 1px solid var(--line); padding: 8px 10px; vertical-align: top; text-align: left; }
th { background: var(--soft); font-weight: 600; }
td.st { white-space: nowrap; width: 8.5em; }
.item { font-weight: 600; }
ul.sub { margin: 6px 0 0; padding-left: 0; list-style: none; }
ul.sub li { margin: 3px 0; }
.note { color: var(--muted); font-size: 12.5px; white-space: pre-line; }
.s-ng { color: var(--ng); } .s-warn { color: var(--warn); } .s-ask { color: var(--ask); } .s-ok { color: var(--ok); }
.events li { margin: 4px 0; }
.foot { margin-top: 36px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--line); padding-top: 10px; }
@media (max-width: 600px) { td.st { white-space: normal; width: auto; } }
@media print { main { padding: 0; } h2 { break-after: avoid; } tr { break-inside: avoid; } }
"""


def _jst(iso: str | None) -> str:
    if not iso:
        return "?"
    try:
        return datetime.fromisoformat(iso).astimezone(JST).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return iso


def _cls(status: str) -> str:
    return {NG: "s-ng", PARTIAL: "s-warn", ASK: "s-ask", NA: ""}.get(status, "s-ok")


def render(site: Site, rows: list[Row], external: list[Finding], server: dict | None,
           month: str, last_external: str | None) -> str:
    e = html.escape
    statuses = [r.status for r in rows if r.status != NA]
    n_ng, n_part, n_ask = statuses.count(NG), statuses.count(PARTIAL), statuses.count(ASK)
    n_ok = len(statuses) - n_ng - n_part - n_ask
    if n_ng:
        vclass, vtext = "ng", f"未対応の項目が {n_ng} 件あります。下の表の ❌ から順に対応します。"
    elif n_part or n_ask:
        vclass, vtext = "warn", "大きな問題はありません。一部対応・要確認の項目を順に埋めていきます。"
    else:
        vclass, vtext = "", "5項目すべてで対策を確認できました。"

    out = [f"<!doctype html><html lang='ja'><head><meta charset='utf-8'>"
           f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
           f"<title>{e(site.name)} 月次報告 {e(month)}</title><style>{CSS}</style></head><body><main>",
           f"<h1>セキュリティ対策 月次報告書</h1>",
           f"<div class='meta'>{e(site.name)}（{e(site.base_url)}）／ 対象月 {e(month)} ／ "
           f"作成 {datetime.now(JST):%Y-%m-%d}</div>",
           f"<div class='verdict {vclass}'><strong>{e(vtext)}</strong><div class='counts'>"
           f"<span>✅ 対応済み {n_ok}</span><span>⚠️ 一部対応 {n_part}</span>"
           f"<span>❓ 要確認 {n_ask}</span><span>❌ 未対応 {n_ng}</span></div></div>",
           "<h2>クレジットカード・セキュリティガイドライン　脆弱性対策5項目</h2>",
           "<table><tr><th>項目</th><th>状態</th></tr>"]
    for r in rows:
        subs = "".join(
            f"<li><span class='{_cls(c.status)}'>{ICON[c.status]} {e(c.status)}</span>　{e(c.label)}"
            + (f"<div class='note'>{e(c.note)}</div>" if c.note else "") + "</li>"
            for c in r.checks)
        out.append(f"<tr><td><div class='item'>({e(r.no)}) {e(r.title)}</div><ul class='sub'>{subs}</ul></td>"
                   f"<td class='st {_cls(r.status)}'>{ICON[r.status]} {e(r.status)}</td></tr>")
    out.append("</table>")

    out.append("<h2>監視の実施状況</h2><ul>")
    out.append(f"<li>外部からの点検：3時間ごと（決済ページのスクリプト、DNS、メール認証、SSL、公開設定）"
               f"{'／最終 ' + e(_jst(last_external)) if last_external else ''}</li>")
    if server:
        out.append(f"<li>サーバー内部の点検：毎日（改ざん検知、更新状況、管理者）／最終 {e(_jst(server.get('last_run')))}</li>")
    else:
        out.append("<li>サーバー内部の点検：未導入</li>")
    out.append("</ul>")

    events = [ev for ev in site.events if str(ev.get("date", "")).startswith(month)]
    if events:
        out.append("<h2>今月の出来事</h2><ul class='events'>")
        out += [f"<li><strong>{e(str(ev['date']))}</strong>　{e(ev['text'])}</li>" for ev in events]
        out.append("</ul>")

    other = [f for f in external if f.check in ("mail", "tls", "headers", "dns")]
    out.append("<h2>その他の点検（ガイドライン外）</h2>")
    if other:
        out.append("<ul>")
        for f in other:
            state = f"対応予定：{f.ack_note}" if f.acknowledged else (f.fix or "")
            out.append(f"<li>{e(f.title)}<div class='note'>{e(state)}</div></li>")
        out.append("</ul>")
    else:
        out.append("<p>メール認証・SSL証明書・セキュリティヘッダーに問題はありません。</p>")

    out.append("<div class='foot'>この報告書は site-guard の自動点検と運営者の申告をまとめたもので、"
               "ガイドラインへの準拠を証明するものではありません。「確認済み（外部）」は外部から、"
               "「確認済み（サーバー）」はサーバー内部の自動点検で確認した項目、「本人申告」は運営者の申告による項目です。"
               "項目名はガイドライン6.0版の要約に基づきます。</div></main></body></html>")
    return "\n".join(out)
