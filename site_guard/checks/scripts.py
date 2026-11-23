"""Fingerprint the JavaScript each watched page loads (Web-skimming detection).

A skimmer has to get JavaScript onto the checkout page: a new <script src>,
a modified existing file, or a new inline block. We record a SHA-256 of every
script and alert on any difference from the accepted baseline.
"""
from __future__ import annotations

import hashlib
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests

from ..config import Site
from ..models import Finding

# Values that legitimately change on every request (nonces, timestamps, ids).
_VOLATILE = [
    re.compile(r'(nonce|_wpnonce|security|token|key|hash|scope)(["\']?\s*[:=]\s*["\'])[^"\']*', re.I),
    # Signed tokens / base64 blobs (must contain a digit, so plain words and URLs survive).
    re.compile(r"(?=[A-Za-z0-9_+=-]*\d)[A-Za-z0-9_+=-]{24,}"),
    re.compile(r"\b[0-9a-f]{8,}\b", re.I),
    re.compile(r"\d+"),
]


class _ScriptParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.external: list[str] = []
        self.inline: list[str] = []
        self._in_script = False
        self._buf: list[str] = []
        self._is_data = False

    def handle_starttag(self, tag, attrs):
        if tag != "script":
            return
        a = dict(attrs)
        typ = (a.get("type") or "").lower()
        # JSON / templates are data, not code.
        self._is_data = typ in {"application/ld+json", "application/json", "text/template", "text/html"}
        if a.get("src"):
            self.external.append(a["src"])
            self._in_script = False
        else:
            self._in_script = True
            self._buf = []

    def handle_data(self, data):
        if self._in_script:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script:
            body = "".join(self._buf).strip()
            if body and not self._is_data:
                self.inline.append(body)
            self._in_script = False


def parse_scripts(html: str) -> tuple[list[str], list[str]]:
    p = _ScriptParser()
    p.feed(html)
    return p.external, p.inline


def normalize_inline(code: str) -> str:
    for rx in _VOLATILE:
        code = rx.sub(lambda m: (m.group(1) + m.group(2) + "~") if m.lastindex else "~", code)
    return re.sub(r"\s+", " ", code).strip()


def script_key(page_url: str, src: str) -> str:
    """Absolute URL without query string (?ver= changes on every plugin update)."""
    u = urlsplit(urljoin(page_url, src))
    return urlunsplit((u.scheme, u.netloc, u.path, "", ""))


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# Vendors that serve per-request content from a fixed URL. We alert if they
# appear/disappear, not on content changes (their content is out of our control).
PRESENCE_ONLY_HOSTS = {
    "www.googletagmanager.com", "www.google-analytics.com", "js.stripe.com",
    "m.stripe.network", "connect.facebook.net", "static.cloudflareinsights.com",
}


def fingerprint_page(session: requests.Session, page_url: str, html: str) -> dict[str, str]:
    external, inline = parse_scripts(html)
    fp: dict[str, str] = {}
    for src in external:
        key = script_key(page_url, src)
        if urlsplit(key).netloc in PRESENCE_ONLY_HOSTS:
            fp[key] = "present"
            continue
        try:
            r = session.get(urljoin(page_url, src), timeout=20)
            fp[key] = sha(r.content) if r.ok else f"http-{r.status_code}"
        except requests.RequestException as e:
            fp[key] = f"error-{type(e).__name__}"
    for code in inline:
        h = sha(normalize_inline(code).encode())
        fp[f"inline:{h[:16]}"] = h
    return fp


def pick_cart_item(products: list[dict]) -> int | None:
    """An id that ?add-to-cart= accepts: a simple product or a variation id."""
    for p in products:
        if not (p.get("is_purchasable") and p.get("is_in_stock")):
            continue
        if p.get("type") == "simple":
            return p["id"]
        if p.get("variations"):
            return p["variations"][0]["id"]
    return None


def _prepare_checkout(session: requests.Session, site: Site) -> None:
    pid = site.checkout_product_id
    if not pid:
        return
    if pid == "auto":
        r = session.get(urljoin(site.base_url, "/wp-json/wc/store/v1/products?per_page=20"), timeout=20)
        r.raise_for_status()
        pid = pick_cart_item(r.json())
        if pid is None:
            return
    session.get(urljoin(site.base_url, f"/?add-to-cart={pid}"), timeout=20)


def collect(session: requests.Session, site: Site, allow_cart: bool = False) -> tuple[dict[str, dict[str, str]], list[Finding]]:
    """Return {page_path: {script_key: hash}} and any fetch problems.

    allow_cart: put a product in a throwaway cart so the checkout page renders.
    That changes state on the site, so it only runs for owner-verified domains.
    """
    findings: list[Finding] = []
    result: dict[str, dict[str, str]] = {}
    pages = list(dict.fromkeys(site.watch_pages + site.payment_pages))
    if site.payment_pages and allow_cart:
        try:
            _prepare_checkout(session, site)
        except requests.RequestException as e:
            findings.append(Finding(site.name, "scripts", "medium", "テスト用カートを作れませんでした", str(e)))
    for path in pages:
        url = urljoin(site.base_url, path)
        try:
            r = session.get(url, timeout=30, allow_redirects=True)
        except requests.RequestException as e:
            findings.append(Finding(site.name, "scripts", "high", f"{path} を取得できません", str(e),
                                    key=f"scripts:fetch:{path}"))
            continue
        if path in site.payment_pages and urlsplit(r.url).path.rstrip("/") != urlsplit(url).path.rstrip("/"):
            findings.append(Finding(
                site.name, "scripts", "medium", f"{path} が {urlsplit(r.url).path} に転送されました",
                "カートが空のため決済ページが表示されず、決済ページのスクリプトを確認できていません。",
                ("config/sites.toml の checkout_product_id に、在庫のある通常商品のIDを設定してください。"
                 if allow_cart else
                 "決済ページの点検には、テスト用カートに商品を入れる必要があります。ドメインの所有者確認が済むと自動で行います。"),
                key=f"scripts:redirect:{path}",
            ))
            continue
        if not r.ok:
            findings.append(Finding(site.name, "scripts", "high", f"{path} が HTTP {r.status_code}",
                                    key=f"scripts:status:{path}"))
            continue
        result[path] = fingerprint_page(session, r.url, r.text)
    return result, findings


def diff(site: Site, baseline: dict[str, dict[str, str]], current: dict[str, dict[str, str]]) -> list[Finding]:
    findings: list[Finding] = []
    for path, now in current.items():
        before = baseline.get(path)
        if before is None:
            continue  # first sighting of this page; becomes baseline
        sev = "critical" if path in site.payment_pages else "high"
        added = sorted(set(now) - set(before))
        removed = sorted(set(before) - set(now))
        changed = sorted(k for k in set(now) & set(before) if now[k] != before[k])
        if not (added or removed or changed):
            continue
        lines = [f"+ 追加: {k}" for k in added] + [f"~ 変更: {k}" for k in changed] + [f"- 削除: {k}" for k in removed]
        if not (added or changed):
            # Scripts only disappeared (e.g. a plugin was removed). Skimmers add code,
            # they don't remove it, so this is a heads-up rather than an alarm.
            findings.append(Finding(
                site.name, "scripts", "low", f"{path} で読み込むスクリプトが減りました（追加・変更はありません）",
                "\n".join(lines[:15]) + (f"\n…他 {len(lines) - 15} 件" if len(lines) > 15 else ""),
                "プラグインを削除・停止した後なら問題ありません。`python -m site_guard accept` で承認してください。",
                key=f"scripts:removed:{path}:{sha(repr(sorted(now.items())).encode())[:12]}",
            ))
            continue
        findings.append(Finding(
            site.name, "scripts", sev, f"{path} のスクリプトが変化しました",
            "\n".join(lines[:15]) + (f"\n…他 {len(lines) - 15} 件" if len(lines) > 15 else ""),
            "自分でプラグイン・テーマを更新した直後なら `python -m site_guard accept` で承認してください。"
            "心当たりがなければ、管理画面へのログイン履歴と追加ファイルを至急確認してください。",
            key=f"scripts:diff:{path}:{sha(repr(sorted(now.items())).encode())[:12]}",
        ))
    return findings
