"""site-guard CLI.

  python -m site_guard run            # check all sites, notify Discord about NEW findings
  python -m site_guard run --all      # notify every open finding (weekly digest)
  python -m site_guard run --dry-run  # print only, no Discord
  python -m site_guard accept         # accept current scripts/DNS as the new baseline
  python -m site_guard diagnose <url> # one-shot diagnosis of any site (passive unless owner-verified)
  python -m site_guard report [--month 2026-11]
                                      # monthly guideline report (HTML in reports/)
"""
from __future__ import annotations

import argparse
import sys

from .config import load_settings
from .models import SEVERITY_EMOJI
from .notify import send_discord, send_resolved, send_status_report, status_report
from .runner import run_site


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="site_guard")
    ap.add_argument("command", choices=["run", "accept", "test-notify", "diagnose", "report"])
    ap.add_argument("target", nargs="?", help="URL for diagnose")
    ap.add_argument("--month", help="YYYY-MM for report (default: this month)")
    ap.add_argument("--site", help="only this site name")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--all", action="store_true", help="report all open findings, not just new ones")
    args = ap.parse_args(argv)

    settings = load_settings(require_sites=args.command not in ("diagnose", "test-notify"))
    if args.command == "test-notify":
        if not settings.discord_webhook_url:
            print("DISCORD_WEBHOOK_URL が設定されていません", file=sys.stderr)
            return 2
        send_discord(settings.discord_webhook_url, [], "✅ Site Guard: テスト通知です。この通知が見えれば設定は完了です。")
        print("送信しました")
        return 0
    if args.command == "diagnose":
        if not args.target:
            print("URLを指定してください: python -m site_guard diagnose https://example.com", file=sys.stderr)
            return 2
        from .diagnose import run as diagnose_run, to_text
        print(to_text(diagnose_run(args.target, settings)))
        return 0
    if args.command == "report":
        return make_reports(settings, args)
    sites = [s for s in settings.sites if not args.site or s.name == args.site]
    if not sites:
        print("該当するサイトがありません", file=sys.stderr)
        return 2

    worst = 0
    for site in sites:
        findings, new, resolved = run_site(settings, site, accept=args.command == "accept")
        # info-level findings are status notes: shown in the weekly digest, never pushed on their own.
        # Push alerts only for new, unhandled problems; info notes and acknowledged items wait for the digest.
        report = [f for f in new if f.severity != "info"]
        print(f"\n== {site.name} ({site.base_url}) — 検出 {len(findings)} 件 / 新規 {len(new)} 件")
        for f in findings:
            mark = "NEW " if f in new else ("ACK " if f.acknowledged else "    ")
            print(f"{mark}{SEVERITY_EMOJI.get(f.severity, '')} [{f.severity}] {f.title}")
        for title in resolved:
            print(f"DONE ✅ {title}")
        if args.command == "accept":
            print("   現在のスクリプト・DNSをベースラインとして承認しました。")
        if args.all:
            if args.dry_run or not settings.discord_webhook_url:
                print("\n--- weekly report preview ---\n" + "\n\n".join(status_report(site.name, findings)))
            else:
                send_status_report(settings.discord_webhook_url, site.name, findings)
        elif report and settings.discord_webhook_url and not args.dry_run:
            send_discord(settings.discord_webhook_url, report,
                         f"🛡️ Site Guard: **{site.name}** — 新しく見つかった項目 {len(report)} 件")
        if resolved and not args.all and settings.discord_webhook_url and not args.dry_run:
            send_resolved(settings.discord_webhook_url, site.name, resolved)
        if any(f.severity == "critical" for f in findings):
            worst = 1
    return worst


def make_reports(settings, args) -> int:
    import re
    from datetime import datetime

    from . import state as state_store
    from .config import ROOT
    from .guideline import evaluate
    from .report import JST, render

    month = args.month or datetime.now(JST).strftime("%Y-%m")
    outdir = ROOT / "reports"
    outdir.mkdir(exist_ok=True)
    for site in settings.sites:
        if args.site and site.name != args.site:
            continue
        findings, _, _ = run_site(settings, site, persist=False)
        server = None  # server-side agent is not part of the public release
        verified = not any(f.key == "ownership:unverified" for f in findings)
        rows = evaluate(findings, server, site.declared, has_payment_page=bool(site.payment_pages),
                        intrusive_ran=verified)
        last = state_store.load(site.name).get("last_run")
        slug = re.sub(r"\W+", "_", site.name)
        path = outdir / f"{month}-{slug}.html"
        path.write_text(render(site, rows, findings, server, month, last))
        print(f"{site.name}: {path}")
        for row in rows:
            print(f"  ({row.no}) {row.status}  {row.title}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
