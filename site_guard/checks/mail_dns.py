"""Email-spoofing defences (SPF / DMARC) and DNS-record change tracking."""
from __future__ import annotations

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver

from ..config import Site
from ..models import Finding


def txt_records(name: str) -> list[str]:
    try:
        ans = dns.resolver.resolve(name, "TXT", lifetime=10)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    return [b"".join(r.strings).decode(errors="replace") for r in ans]


def records(name: str, rtype: str, resolver: dns.resolver.Resolver | None = None) -> list[str]:
    try:
        r = resolver or dns.resolver.get_default_resolver()
        return sorted(x.to_text() for x in r.resolve(name, rtype, lifetime=10))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []


def delegated_nameservers(domain: str) -> list[str]:
    """NS names as the TLD registry currently delegates them (no caches).

    After a nameserver move, recursive resolvers keep the old NS set for up
    to two days; the registry's answer is the truth.
    """
    tld = domain.rsplit(".", 1)[-1] + "."
    for tld_ns in records(tld, "NS"):
        try:
            ip = dns.resolver.resolve(tld_ns, "A", lifetime=10)[0].to_text()
            q = dns.message.make_query(domain, "NS")
            q.flags &= ~dns.flags.RD
            resp = dns.query.udp(q, ip, timeout=5)
        except dns.exception.DNSException:
            continue
        names = [rr.to_text() for rrset in resp.authority + resp.answer
                 if rrset.rdtype == dns.rdatatype.NS for rr in rrset]
        if names:
            return sorted(names)
    return records(domain, "NS")


def authoritative_resolver(domain: str, ns_names: list[str] | None = None) -> dns.resolver.Resolver:
    """Ask the domain's own nameservers directly, bypassing caches.

    Recursive resolvers serve stale answers for up to a TTL after a change,
    which made the change detector flap between old and new values.
    """
    ips = []
    for ns in ns_names if ns_names is not None else delegated_nameservers(domain):
        try:
            ips += [a.to_text() for a in dns.resolver.resolve(ns, "A", lifetime=10)]
        except dns.exception.DNSException:
            continue
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = ips or dns.resolver.get_default_resolver().nameservers
    return r


def evaluate_spf(txts: list[str]) -> tuple[str, str] | None:
    """Return (severity, problem) or None if SPF looks fine."""
    spf = [t for t in txts if t.lower().startswith("v=spf1")]
    if not spf:
        return "high", "SPFレコードがありません"
    if len(spf) > 1:
        return "high", "SPFレコードが複数あり、無効扱いになります"
    rec = spf[0].lower()
    if "+all" in rec or rec.rstrip().endswith(" all"):
        return "critical", "SPFが +all で、誰でもこのドメインで送信できます"
    if "?all" in rec:
        return "medium", "SPFが ?all（判定なし）です"
    return None


def evaluate_dmarc(txts: list[str]) -> tuple[str, str] | None:
    dmarc = [t for t in txts if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        return "high", "DMARCレコードがありません"
    tags = {k.strip().lower(): v.strip().lower()
            for k, _, v in (p.partition("=") for p in dmarc[0].split(";")) if k.strip()}
    if tags.get("p") == "none":
        return "medium", "なりすましメール対策が「観察モード」です（偽メールはまだ止めていません）"
    return None


FIX_SPF = ("DNSに `v=spf1 include:<送信サービス> -all` 形式のTXTを1つだけ置いてください。"
           "メールを送らないドメインなら `v=spf1 -all`。")
FIX_DMARC = ("`_dmarc.<ドメイン>` にTXT `v=DMARC1; p=quarantine; rua=mailto:<受信用アドレス>` を追加。"
             "レポートで正規送信を確認後 p=reject へ。")


def check(site: Site) -> tuple[list[Finding], dict[str, list[str]]]:
    findings: list[Finding] = []
    snapshot: dict[str, list[str]] = {}
    d = site.domain
    try:
        spf = evaluate_spf(txt_records(d))
        if spf:
            findings.append(Finding(site.name, "mail", spf[0], spf[1], fix=FIX_SPF, key="mail:spf"))
        dmarc = evaluate_dmarc(txt_records(f"_dmarc.{d}"))
        if dmarc:
            key = "mail:dmarc-none" if dmarc[0] == "medium" else "mail:dmarc"
            findings.append(Finding(site.name, "mail", dmarc[0], dmarc[1], fix=FIX_DMARC, key=key))
        # NS comes from the delegation (cached resolvers are fine for that);
        # everything else straight from the authoritative servers.
        snapshot["NS"] = delegated_nameservers(d)
        auth = authoritative_resolver(d, snapshot["NS"])
        for rtype in ("A", "AAAA", "MX"):
            snapshot[rtype] = records(d, rtype, auth)
    except dns.exception.DNSException as e:
        findings.append(Finding(site.name, "mail", "medium", "DNSを照会できませんでした", str(e)))
    return findings, snapshot


def diff_dns(site: Site, before: dict[str, list[str]], now: dict[str, list[str]]) -> list[Finding]:
    out = []
    for rtype, vals in now.items():
        if rtype in before and before[rtype] != vals:
            out.append(Finding(
                site.name, "dns", "critical" if rtype in ("A", "NS") else "high",
                f"DNSの{rtype}レコードが変わりました",
                f"前回: {', '.join(before[rtype]) or '(なし)'}\n今回: {', '.join(vals) or '(なし)'}",
                "自分で変更していなければ、ドメイン管理会社のアカウントが乗っ取られている可能性があります。",
                key=f"dns:{rtype}:{'|'.join(vals)}",
            ))
    return out
