"""Map site-guard results onto the five 脆弱性対策 items that the
クレジットカード・セキュリティガイドライン (6.0版, 2025-04〜) requires of EC加盟店.

Every row says HOW it was confirmed, so the report never claims more than we
know: confirmed from outside, confirmed on the server, declared by the owner,
not done, or needs checking. It is evidence for a conversation with the card
company, not a certificate of compliance.

Item names follow the guideline as summarised by Adyen (2025-03-24); check the
original 「セキュリティ・チェックリスト」 before quoting them officially.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import Finding

ITEMS = [
    ("1", "システム管理画面のアクセス制限と管理者のID・パスワード管理"),
    ("2", "データディレクトリの露見に伴う設定不備への対策"),
    ("3", "Webアプリケーションの脆弱性対策"),
    ("4", "マルウェア対策としてのウイルス対策ソフトの導入、運用"),
    ("5", "悪質な有効性確認、クレジットマスターへの対策"),
]

OK_EXT, OK_SRV, OK_DECL, PARTIAL, NG, ASK, NA = (
    "確認済み（外部）", "確認済み（サーバー）", "本人申告", "一部対応", "未対応", "要確認", "対象外")
ICON = {OK_EXT: "✅", OK_SRV: "✅", OK_DECL: "☑️", PARTIAL: "⚠️", NG: "❌", ASK: "❓", NA: "—"}
RANK = {NG: 0, ASK: 1, PARTIAL: 2, OK_DECL: 3, OK_SRV: 4, OK_EXT: 4, NA: 5}


@dataclass
class Check:
    label: str
    status: str
    note: str = ""


@dataclass
class Row:
    no: str
    title: str
    checks: list[Check] = field(default_factory=list)

    @property
    def status(self) -> str:
        live = [c.status for c in self.checks if c.status != NA]
        if not live:
            return NA
        worst = min(live, key=lambda s: RANK[s])
        if worst in (NG, ASK) and any(RANK[s] >= RANK[OK_DECL] for s in live):
            return PARTIAL if worst == NG else worst
        return worst


def _has(findings: list[Finding], prefix: str) -> list[Finding]:
    return [f for f in findings if f.key.startswith(prefix)]


def _srv_has(server: dict | None, prefix: str) -> list[dict]:
    return [f for f in (server or {}).get("findings", []) if f["key"].startswith(prefix)]


def _declared(declared: dict, key: str, label: str, missing_status: str, missing_note: str) -> Check:
    v = declared.get(key)
    if v is False:
        return Check(label, NG, missing_note)
    if v in (None, ""):
        return Check(label, missing_status, missing_note)
    if isinstance(v, str) and v.startswith("対象外"):
        return Check(label, NA, v)
    if isinstance(v, str) and v.startswith("一部:"):
        return Check(label, PARTIAL, v.removeprefix("一部:").strip())
    return Check(label, OK_DECL, v if isinstance(v, str) else "")


def evaluate(external: list[Finding], server: dict | None, declared: dict,
             has_payment_page: bool, intrusive_ran: bool = True) -> list[Row]:
    rows = {no: Row(no, title) for no, title in ITEMS}
    srv = server is not None
    snap = (server or {}).get("snapshot", {})

    # (1) admin screen
    r = rows["1"]
    if srv:
        admins = snap.get("admins", {})
        no2fa = [u for u, a in admins.items() if not a.get("two_factor")]
        r.checks.append(Check("管理者の二要素認証", NG if no2fa else OK_SRV,
                              f"未設定: {', '.join(no2fa)}" if no2fa else f"管理者{len(admins)}名すべて設定済み"))
        added = _srv_has(server, "admin:added")
        r.checks.append(Check("管理者アカウントの増減監視", NG if added else OK_SRV,
                              "新しい管理者が追加されています" if added else "毎日照合"))
    else:
        r.checks.append(Check("管理者の二要素認証", ASK, "サーバー内部の点検が未導入"))
    gate = _declared(declared, "admin_access_restriction", "管理画面のIP制限・Basic認証", NG,
                     "未導入。wp-admin / wp-login.php にIP制限かBasic認証を追加します")
    if intrusive_ran and gate.status == OK_DECL and not _has(external, "wordpress:login-open"):
        gate = Check(gate.label, OK_EXT, gate.note + "（ログイン画面が外部から開けないことを確認）")
    r.checks.append(gate)
    r.checks.append(_declared(declared, "login_lockout", "ログイン失敗時のロック", ASK, "設定内容を確認してください"))
    if intrusive_ran:
        leak = _has(external, "wordpress:users-endpoint")
        r.checks.append(Check("管理者ユーザー名の非公開", NG if leak else OK_EXT,
                              "REST APIからユーザー名が見えます" if leak else "外部から取得できないことを確認"))

    # (2) data directory exposure
    r = rows["2"]
    if intrusive_ran:
        exposed = _has(external, "wordpress:exposed")
        r.checks.append(Check("設定ファイル・バックアップの流出", NG if exposed else OK_EXT,
                              ", ".join(f.title for f in exposed) if exposed
                              else ".env / .git / wp-config のバックアップ / debug.log が外から読めないことを確認"))
    else:
        r.checks.append(Check("設定ファイル・バックアップの流出", ASK, "所有者確認後に点検できます"))
    if srv:
        up = _srv_has(server, "integrity:uploads")
        r.checks.append(Check("アップロード先にプログラムが無いこと", NG if up else OK_SRV,
                              "uploads にPHPファイルがあります" if up else "uploads フォルダを毎日点検"))
    r.checks.append(_declared(declared, "upload_restriction", "アップロード先でのプログラム実行禁止", ASK,
                              "Webサーバーの設定を確認してください"))

    # (3) web application vulnerabilities
    r = rows["3"]
    if srv:
        upd = _srv_has(server, "update:")
        r.checks.append(Check("本体・プラグイン・テーマが最新", NG if upd else OK_SRV,
                              "\n".join(f["title"] for f in upd) if upd
                              else f"WordPress {snap.get('core', '?')}・プラグイン{len(snap.get('plugins', {}))}個を毎日照合"))
    else:
        r.checks.append(Check("本体・プラグイン・テーマが最新", ASK, "サーバー内部の点検が未導入"))
    gen = _has(external, "wordpress:generator")
    r.checks.append(Check("バージョン情報の非公開", NG if gen else OK_EXT, "" if gen else "外部から読めないことを確認"))
    r.checks.append(_declared(declared, "vulnerability_assessment", "定期的な脆弱性診断", PARTIAL,
                              "site-guard の点検は簡易診断です。専門の脆弱性診断は未実施"))
    r.checks.append(_declared(declared, "custom_code_review", "自作部分のセキュアコーディング確認", ASK,
                              "自作テーマ・独自機能のコード確認を実施したか"))

    # (4) malware / antivirus
    r = rows["4"]
    av = snap.get("antivirus") or {}
    if srv and av.get("last_scan"):
        hits = _srv_has(server, "av:infected")
        stale = _srv_has(server, "av:stale")
        r.checks.append(Check("ウイルス対策ソフト", NG if hits else (PARTIAL if stale else OK_SRV),
                              f"ClamAV（公式シグネチャ＋PHP不正プログラム用の独自ルール）で毎日スキャン。"
                              f"最終 {av['last_scan']}、{av.get('files') or '?'}ファイル、検出 {av.get('infected', 0)}件"))
    else:
        r.checks.append(_declared(declared, "antivirus", "ウイルス対策ソフト", NG,
                                  "未導入。サーバーにウイルス対策ソフト（ClamAV等）を導入し定期スキャンします"))
    if srv:
        bad = [f for f in server.get("findings", []) if f["key"].startswith("integrity:") and f["severity"] in ("critical", "high")]
        r.checks.append(Check("ファイル改ざんの検知（補完策）", NG if bad else OK_SRV,
                              "\n".join(f["title"] for f in bad) if bad
                              else "本体・プラグインを公式配布物と毎日照合、自作コードの変化を監視"))
    if has_payment_page:
        sk = [f for f in external if f.check == "scripts" and f.severity == "critical"]
        r.checks.append(Check("決済ページのスクリプト監視（スキミング対策）", NG if sk else OK_EXT,
                              "決済ページのスクリプトが変化しています" if sk else "3時間ごとに照合、変化なし"))

    # (5) card testing / credit master
    rows["5"].checks.append(_declared(declared, "card_testing", "カード番号の総当たり（有効性確認）対策", ASK,
                                      "決済サービス側の設定（不正検知ルール、3Dセキュア、試行回数制限）を確認してください"))
    return list(rows.values())
