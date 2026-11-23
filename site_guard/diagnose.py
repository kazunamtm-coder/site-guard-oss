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
        findings = [Finding(domain, "http", "high", "サイトに接続できません", str(e))]
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
                                    "ホスティング側の設定で追加できるか確認してください。"))
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    return Diagnosis(url, domain, platforms, is_self_hosted(platforms), verified, note, third, findings)


RESPONSIBILITY = {
    True: "サーバーは運営者自身の管理です。本体・プラグインの更新や改ざん対策は運営者（または制作会社）の責任範囲です。",
    False: "サーバーはプラットフォーム側が管理しています。運営者の責任範囲は主に、メール認証・追加アプリやタグ・管理アカウントの保護です。",
    None: "プラットフォームを特定できませんでした。",
}


def to_text(d: Diagnosis) -> str:
    action = [f for f in d.findings if f.severity != "info"]
    worst = min((SEVERITY_ORDER.get(f.severity, 9) for f in action), default=9)
    light = {0: "🔴", 1: "🔴", 2: "🟠", 3: "🟡"}.get(worst, "🟢")
    verdict = (f"{light} 対応をおすすめする項目が {len(action)} 件あります" if action
               else "🟢 外から確認できる範囲では問題は見つかりませんでした")
    lines = [
        f"# {d.domain} の診断結果",
        "",
        verdict,
        "",
        f"- プラットフォーム: {', '.join(d.platforms) or '不明'}",
        f"- 責任範囲: {RESPONSIBILITY[d.self_hosted]}",
        f"- 点検の深さ: {d.verified_note}",
        f"- 外部から読み込んでいるスクリプト: {', '.join(d.third_party) or 'なし'}",
        "",
    ]
    for f in d.findings:
        lines.append(f"## {f.title}（{f.severity}）")
        if f.detail:
            lines.append(f.detail)
        if f.fix:
            lines.append(f"→ {f.fix}")
        lines.append("")
    if not d.verified:
        lines += [
            "---",
            "より詳しい点検（流出ファイル・管理画面の露出など）には、ドメイン所有者の確認が必要です。",
            instructions(d.domain),
        ]
    return "\n".join(lines)
