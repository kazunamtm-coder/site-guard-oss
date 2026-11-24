from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

import certifi

from ..config import Site
from ..models import Finding


def cert_days_left(host: str, port: int = 443, now: datetime | None = None) -> int:
    # python.org builds on macOS ship without system CAs; use certifi's bundle.
    ctx = ssl.create_default_context(cafile=certifi.where())
    with socket.create_connection((host, port), timeout=15) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            cert = s.getpeercert()
    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
    return (expires - (now or datetime.now(timezone.utc))).days


def check(site: Site, warn_days: int) -> list[Finding]:
    try:
        days = cert_days_left(site.domain)
    except ssl.SSLCertVerificationError as e:
        return [Finding(site.name, "tls", "critical", "SSL証明書の検証に失敗しました", str(e),
                        "証明書が失効・不一致です。サーバーの証明書の自動更新（certbot 等）の状態を確認してください。",
                        key="tls:verify-failed")]
    except OSError as e:
        return [Finding(site.name, "tls", "high", "HTTPS(443)に接続できません", str(e), key="tls:unreachable")]
    if days < 0:
        return [Finding(site.name, "tls", "critical", "SSL証明書の期限が切れています",
                        fix="証明書を更新してください（certbot 等の自動更新の状態を確認）。", key="tls:expired")]
    if days <= warn_days:
        return [Finding(site.name, "tls", "high" if days <= 7 else "medium",
                        f"SSL証明書の期限まで残り{days}日",
                        fix="証明書の自動更新が動いているか確認してください（例: `sudo certbot renew --dry-run`）。",
                        key="tls:expiring")]
    return []
