"""WordPress exposure seen from outside: info leaks, attack entry points, headers."""
from __future__ import annotations

import re
from urllib.parse import urljoin

import requests

from ..config import Site
from ..models import Finding

SECURITY_HEADERS = {
    "strict-transport-security": "HTTPS強制(HSTS)",
    "x-content-type-options": "MIMEスニッフィング防止",
    "x-frame-options": "クリックジャッキング防止",
    "content-security-policy": "CSP(不正スクリプトの読み込み制限)",
}


def _get(session, url, **kw):
    try:
        return session.get(url, timeout=20, allow_redirects=False, **kw)
    except requests.RequestException:
        return None


def check(session: requests.Session, site: Site, intrusive: bool = True) -> list[Finding]:
    """intrusive=False skips probes that look like an attack from the outside
    (user enumeration, xmlrpc, hidden files). Use it until the domain owner is verified."""
    f: list[Finding] = []
    base = site.base_url
    if not intrusive:
        return f + _passive(session, site)
    f += _probes(session, site)
    return f + _passive(session, site)


def _probes(session: requests.Session, site: Site) -> list[Finding]:
    f: list[Finding] = []
    base = site.base_url

    r = _get(session, urljoin(base, "/wp-json/wp/v2/users"))
    if r is not None and r.status_code == 200:
        try:
            n = len(r.json())
        except ValueError:
            n = 0
        if n:
            f.append(Finding(
                site.name, "wordpress", "medium", f"REST APIからユーザー名が{n}件見えます",
                "ログイン総当たり攻撃の「ID」が公開されている状態です。",
                "functions.php か小さなプラグインで、未ログイン時の /wp/v2/users を無効化してください"
                "（例: rest_endpoints フィルタで該当ルートを unset）。",
                key="wordpress:users-endpoint",
            ))

    r = _get(session, urljoin(base, "/xmlrpc.php"))
    if r is not None and r.status_code in (200, 405):
        f.append(Finding(
            site.name, "wordpress", "medium", "xmlrpc.php が有効です",
            "パスワード総当たりを1リクエストで大量に試せる入口として悪用されます。",
            "Jetpack等で使っていなければ、nginx で `location = /xmlrpc.php { deny all; }`。",
            key="wordpress:xmlrpc",
        ))

    r = _get(session, urljoin(base, "/readme.html"))
    if r is not None and r.status_code == 200 and "wordpress" in r.text.lower():
        f.append(Finding(site.name, "wordpress", "low", "readme.html が公開されています",
                         fix="VPSで readme.html を削除するか、nginxでアクセス拒否してください。",
                         key="wordpress:readme"))

    r = _get(session, urljoin(base, "/wp-login.php"))
    if r is not None and r.status_code == 200:
        f.append(Finding(
            site.name, "wordpress", "low", "ログイン画面が外から見える状態です（WordPressでは一般的）",
            "パスワードだけで守っていると、総当たり攻撃の対象になります。",
            "管理者に二要素認証を設定し、可能ならログインURL変更かIP制限・fail2banを。",
            key="wordpress:login-open",
        ))

    for path in ("/wp-config.php.bak", "/wp-config.php~", "/.env", "/.git/HEAD", "/wp-content/debug.log"):
        r = _get(session, urljoin(base, path))
        if r is not None and r.status_code == 200 and len(r.content) > 0 and "<html" not in r.text[:500].lower():
            f.append(Finding(site.name, "wordpress", "critical", f"{path} が外部から読めます",
                             "設定・鍵・ログが漏れている可能性があります（Stripeの秘密鍵を含む場合あり）。",
                             "すぐに削除し、中に含まれていた鍵・パスワードをすべて再発行してください。",
                             key=f"wordpress:exposed:{path}"))
    return f


def _passive(session: requests.Session, site: Site) -> list[Finding]:
    f: list[Finding] = []
    base = site.base_url
    r = _get(session, base)
    if r is not None:
        m = re.search(r'<meta name="generator" content="WordPress ([\d.]+)"', r.text)
        if m:
            f.append(Finding(site.name, "wordpress", "low", f"WordPressのバージョン({m.group(1)})が公開されています",
                             fix="`remove_action('wp_head', 'wp_generator');` で非表示にできます。",
                             key="wordpress:generator"))
        missing = [label for h, label in SECURITY_HEADERS.items() if h not in r.headers]
        if "content-security-policy" not in r.headers and "content-security-policy-report-only" in r.headers:
            # Rolled out in report-only mode: track it, but it is not "missing".
            missing.remove(SECURITY_HEADERS["content-security-policy"])
            f.append(Finding(
                site.name, "headers", "info", "CSPは報告モードで稼働中（まだブロックはしていません）",
                fix="違反報告が落ち着いたら Content-Security-Policy（強制モード）に切り替えます。",
                key="headers:csp-report-only",
            ))
        if missing:
            f.append(Finding(
                site.name, "headers", "low" if len(missing) < 3 else "medium",
                f"セキュリティヘッダー不足: {len(missing)}件", "\n".join(f"- {m}" for m in missing),
                "nginx の server ブロックに add_header で追加してください（CSPは決済ページを壊さないよう段階的に）。",
                key="headers:missing:" + ",".join(sorted(missing)),
            ))
    return f
