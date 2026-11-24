"""Notify through GitHub Issues: zero setup, and GitHub emails the owner.

Each open problem gets one issue; when the problem disappears on a later run,
its issue is closed (quietly: no comment). GitHub sends the repository owner an
email for every new issue (and the GitHub mobile app shows it), so owners who
don't use Discord still hear about problems without configuring anything.

Runs inside GitHub Actions, where GITHUB_TOKEN and GITHUB_REPOSITORY exist.
Each issue carries a hidden marker so it can be matched to its finding later.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timedelta, timezone

import requests

from .explain import explain, tech_block
from .models import SEVERITY_ORDER, Finding
from .notify import runbook_url, status_report

LABEL = "site-guard"
URGENT_LABEL = "緊急"
DIGEST_LABEL = "週次まとめ"
JST = timezone(timedelta(hours=9))
_MARK = re.compile(r"<!-- site-guard-key: (.+?) -->")


def available() -> bool:
    return bool(os.environ.get("GITHUB_TOKEN") and os.environ.get("GITHUB_REPOSITORY")) \
        and os.environ.get("SITE_GUARD_ISSUES", "on").lower() not in ("off", "0", "false", "no")


class GitHub:
    def __init__(self, token: str | None = None, repo: str | None = None,
                 api: str | None = None, session: requests.Session | None = None) -> None:
        self.repo = repo or os.environ["GITHUB_REPOSITORY"]
        self.api = (api or os.environ.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")
        self.s = session or requests.Session()
        self.s.headers.update({
            "Authorization": f"Bearer {token or os.environ['GITHUB_TOKEN']}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })

    @property
    def owner(self) -> str:
        return self.repo.split("/", 1)[0]

    def _url(self, path: str) -> str:
        return f"{self.api}/repos/{self.repo}{path}"

    def ensure_labels(self) -> None:
        for name, color, desc in [
            (LABEL, "d93f0b", "site-guard が見つけた項目"),
            (URGENT_LABEL, "b60205", "すぐに確認が必要"),
            (DIGEST_LABEL, "0e8a16", "site-guard の週次まとめ"),
        ]:
            r = self.s.post(self._url("/labels"), json={"name": name, "color": color, "description": desc}, timeout=20)
            if r.status_code not in (201, 422):  # 422 = already exists
                r.raise_for_status()

    def open_issues(self, label: str = LABEL) -> list[dict]:
        out, page = [], 1
        while True:
            r = self.s.get(self._url("/issues"), params={"state": "open", "labels": label, "per_page": 100, "page": page}, timeout=20)
            r.raise_for_status()
            batch = [i for i in r.json() if "pull_request" not in i]
            out += batch
            if len(r.json()) < 100:
                return out
            page += 1

    def create(self, title: str, body: str, labels: list[str]) -> dict:
        r = self.s.post(self._url("/issues"), json={"title": title[:250], "body": body, "labels": labels}, timeout=20)
        r.raise_for_status()
        return r.json()

    def close(self, number: int, comment: str | None = None) -> None:
        # No comment by default: a comment is one more email to the owner,
        # and GitHub already emails "Closed as completed".
        if comment:
            self.s.post(self._url(f"/issues/{number}/comments"), json={"body": comment}, timeout=20).raise_for_status()
        self.s.patch(self._url(f"/issues/{number}"), json={"state": "closed", "state_reason": "completed"}, timeout=20).raise_for_status()


def marker(site: str, key: str) -> str:
    return f"<!-- site-guard-key: {site}|{key} -->"


def issue_title(f: Finding) -> str:
    p = explain(f)
    return f"{p.icon} {p.label}｜{f.site}：{p.headline}"


def issue_body(f: Finding, owner: str) -> str:
    p = explain(f)
    parts = [f"@{owner}", "",
             f"## {p.icon} {p.label}：{p.headline}", "",
             "**何が起きているか**", p.what, "",
             "**放っておくと**", p.risk, "",
             "**あなたがやること**"]
    parts += [f"{i}. {t}" for i, t in enumerate(p.todo, 1)]
    parts += ["", "<details><summary>制作会社・技術者の方へ（この部分をそのまま転送できます）</summary>", "",
              "```", tech_block(f)[:3000], "```"]
    link = runbook_url(f.check)
    if link:
        parts.append(f"📖 対応手順: {link}")
    parts += ["", "</details>", "", "---",
              "この問題が直ると、次の点検（3時間ごと）で、このお知らせは自動で閉じます。",
              marker(f.site, f.key)]
    return "\n".join(parts)


def actionable(findings: list[Finding]) -> list[Finding]:
    """What deserves an issue: real problems the owner hasn't already handled."""
    return [f for f in findings if f.severity != "info" and not f.acknowledged]


def sync(gh: GitHub, site: str, findings: list[Finding], issued: set[str],
         issues: list[dict] | None = None) -> tuple[set[str], int, int]:
    """Open an issue for each new problem, close issues whose problem is gone.

    issued: finding keys that already got an issue (kept in the site's state).
    If the owner closes an issue by hand while the problem remains, it is not
    reopened every 3 hours; it comes back only if the problem goes away and
    later returns. Returns (issued, opened, closed).
    """
    issues = gh.open_issues() if issues is None else issues
    by_key: dict[str, dict] = {}
    for i in issues:
        m = _MARK.search(i.get("body") or "")
        if m and m.group(1).startswith(f"{site}|"):
            by_key[m.group(1).split("|", 1)[1]] = i

    want = {f.key: f for f in actionable(findings)}
    opened = closed = 0
    for key, f in sorted(want.items(), key=lambda kv: SEVERITY_ORDER.get(kv[1].severity, 9)):
        if key in by_key or key in issued:
            continue
        labels = [LABEL] + ([URGENT_LABEL] if explain(f).level == 0 else [])
        gh.create(issue_title(f), issue_body(f, gh.owner), labels)
        opened += 1
    for key, issue in by_key.items():
        if key in want:
            continue
        # Resolved, or registered as handled/scheduled in config: close quietly.
        gh.close(issue["number"])
        closed += 1
    return set(want), opened, closed


def post_digest(gh: GitHub, site: str, findings: list[Finding]) -> None:
    """Weekly summary as one issue per site; last week's summary is closed."""
    today = datetime.now(JST).strftime("%Y-%m-%d")
    for old in gh.open_issues(DIGEST_LABEL):
        if old.get("title", "").endswith(f"— {site}"):
            gh.close(old["number"])
    body = "\n\n".join(status_report(site, findings))
    body = f"@{gh.owner}\n\n{body}\n\n---\n{marker(site, 'digest')}"
    gh.create(f"📋 今週のまとめ {today} — {site}", body, [DIGEST_LABEL])


def test_notice(gh: GitHub) -> dict:
    """One email only: the issue stays open for the owner to close."""
    return gh.create(
        "✅ site-guard: テスト通知",
        f"@{gh.owner} このメールが届いていれば、設定は完了です。このIssueは閉じて構いません。\n\n"
        "届かない場合は、GitHub の Settings → Notifications で、メール通知が有効になっているか、"
        "このリポジトリを Watch しているかを確認してください。迷惑メールフォルダも確認してください。",
        [LABEL],
    )
