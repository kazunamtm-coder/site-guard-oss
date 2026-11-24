"""One-shot diagnosis of any URL: `python -m site_guard diagnose <url>`.

Without proof of ownership only passive checks run (what any visitor's browser
sees: TLS, DNS/mail records, headers, page source). Probes that would look like
an attack (hidden files, user enumeration, xmlrpc) need the domain owner to add
a DNS TXT record first.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

import requests

from .checks import mail_dns, tls, wordpress
from .checks.scripts import parse_scripts
from .config import Settings, Site
from .models import SEVERITY_ORDER, Finding
from .explain import explain, tech_block
from .ownership import instructions, is_verified
from .platform import detect, is_self_hosted


@dataclass
class Diagnosis:
    url: str
    domain: str
    platforms: list[str]
    self_hosted: bool | None
    verified: bool
    verified_note: str
    third_party: list[str]
    findings: list[Finding] = field(default_factory=list)


def run(url: str, settings: Settings) -> Diagnosis:
    if "://" not in url:
        url = "https://" + url
    domain = urlsplit(url).hostname or url
    base = f"https://{domain}"
    site = Site(name=domain, base_url=base)
    session = requests.Session()
    session.headers["User-Agent"] = settings.user_agent

    verified, note = is_verified(domain)
    html, headers = "", {}
    try:
        r = session.get(base, timeout=30)
        html, headers = r.text, {k.lower(): v for k, v in r.headers.items()}
    except requests.RequestException as e:
        findings = [Finding(domain, "http", "high", "サイトに接続できません", str(e), key="http:unreachable")]
        return Diagnosis(url, domain, [], None, verified, note, [], findings)

    platforms = detect(html, headers)
    srcs, _ = parse_scripts(html)
    third = sorted({urlsplit(s).hostname for s in srcs
                    if urlsplit(s).hostname and not urlsplit(s).hostname.endswith(domain.removeprefix("www."))})

    findings: list[Finding] = []
    findings += tls.check(site, settings.tls_warn_days)
    mail_findings, _ = mail_dns.check(site)
    findings += mail_findings
    if "WordPress" in platforms:
        findings += wordpress.check(session, site, intrusive=verified)
    else:
        missing = [label for h, label in wordpress.SECURITY_HEADERS.items()
                   if h not in headers and not (h == "content-security-policy" and "content-security-policy-report-only" in headers)]
        if missing:
            findings.append(Finding(domain, "headers", "low" if len(missing) < 3 else "medium",
                                    f"セキュリティヘッダー不足: {len(missing)}件", "\n".join(f"- {m}" for m in missing),
                                    "ホスティング側の設定で追加できるか確認してください。",
                                    key="headers:missing"))
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    return Diagnosis(url, domain, platforms, is_self_hosted(platforms), verified, note, third, findings)


RESPONSIBILITY = {
    True: "ホームページを置いている場所（サーバー）は、お店が自分で管理しています。"
          "ソフトの更新や、悪いプログラムを仕込まれないための対策は、お店（または制作会社）の仕事です。",
    False: "ホームページを置いている場所は、サービスの会社が管理しています。"
           "お店がやることは、主に「にせのメール対策」「追加したアプリやタグの管理」「ログインの守り」です。",
    None: "ホームページを作っているサービスを、特定できませんでした。",
}


def to_text(d: Diagnosis) -> str:
    todo = [f for f in d.findings if f.severity != "info"]
    todo.sort(key=lambda f: (explain(f).level, SEVERITY_ORDER.get(f.severity, 9)))
    urgent = [f for f in todo if explain(f).level <= 2]
    if urgent:
        rest = len(todo) - len(urgent)
        verdict = (f"{explain(urgent[0]).icon} 直したほうがよいことが {len(urgent)} 件あります。上から順に対応してください。"
                   + (f"（ほかに、急ぎではないことが {rest} 件あります）" if rest else ""))
    elif todo:
        verdict = "🟢 急いで直すことはありません。時間があるときに見直せることが、いくつかあります。"
    else:
        verdict = "🟢 外から確認できる範囲では、問題は見つかりませんでした。"
    lines = [
        f"# {d.domain} の診断結果",
        "",
        verdict,
        "",
        f"- 使っているサービス：{', '.join(d.platforms) or '不明'}",
        f"- だれが守る？：{RESPONSIBILITY[d.self_hosted]}",
        f"- 点検したはんい：{'くわしい点検まで（持ち主の確認ずみ）' if d.verified else 'だれでも見られる範囲だけ'}",
        "",
    ]
    for i, f in enumerate(todo, 1):
        p = explain(f)
        lines += [f"## {i}. {p.icon} {p.label}：{p.headline}", "",
                  f"**何が起きているか**：{p.what}", "",
                  f"**放っておくと**：{p.risk}", "",
                  "**あなたがやること**"]
        lines += [f"{j}. {t}" for j, t in enumerate(p.todo, 1)]
        lines.append("")
    if todo:
        lines += ["---", "## 制作会社・技術者の方へ", "",
                  f"外部スクリプト: {', '.join(d.third_party) or 'なし'}", ""]
        for i, f in enumerate(todo, 1):
            lines += [f"{i}. " + tech_block(f).replace("\n", "\n   "), ""]
    if not d.verified:
        lines += [
            "---",
            "## もっとくわしく点検するには",
            "支払いページの中や、見られてはいけないファイルがないかまで調べるには、お店の「持ち主の確認」が必要です。",
            instructions(d.domain),
        ]
    return "\n".join(lines)
