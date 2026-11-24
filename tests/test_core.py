from site_guard.checks import mail_dns, scripts
from site_guard.config import Site
from site_guard.models import Finding
from site_guard.notify import chunk

SITE = Site(name="t", base_url="https://example.com", payment_pages=["/checkout/"])


def test_parse_scripts_skips_json_and_collects_inline():
    html = """
    <script src="/a.js?ver=1"></script>
    <script type="application/ld+json">{"x":1}</script>
    <script>var wc = {"nonce":"abc123def456"};</script>
    """
    ext, inline = scripts.parse_scripts(html)
    assert ext == ["/a.js?ver=1"]
    assert len(inline) == 1


def test_script_key_drops_query_and_resolves_relative():
    assert scripts.script_key("https://example.com/checkout/", "/a.js?ver=9") == "https://example.com/a.js"
    assert scripts.script_key("https://example.com/x/", "b.js") == "https://example.com/x/b.js"


def test_normalize_inline_ignores_nonces_and_numbers():
    a = 'var p = {"nonce":"9f8e7d6c5b","ts":1700000000};'
    b = 'var p = {"nonce":"0a1b2c3d4e","ts":1800000001};'
    assert scripts.normalize_inline(a) == scripts.normalize_inline(b)
    assert scripts.normalize_inline(a) != scripts.normalize_inline('fetch("https://evil.example/c")')


def test_normalize_inline_ignores_signed_tokens_but_keeps_urls():
    a = 'cfg={"t":"eyJwdXJwb3NlIjoicGFnZSIsImV4cGlyZXMiOjE3OTUzMjY0MDQs.abc"}'
    b = 'cfg={"t":"eyJwdXJwb3NlIjoicGFnZSIsImV4cGlyZXMiOjE3OTUzMjY0MDUs.abc"}'
    assert scripts.normalize_inline(a) == scripts.normalize_inline(b)
    assert "evil-collector.example/steal" in scripts.normalize_inline('x("https://evil-collector.example/steal")')


def test_diff_flags_new_script_on_checkout_as_critical():
    base = {"/checkout/": {"https://example.com/a.js": "h1"}}
    now = {"/checkout/": {"https://example.com/a.js": "h1", "https://evil.example/skim.js": "h2"}}
    (f,) = scripts.diff(SITE, base, now)
    assert f.severity == "critical"
    assert "evil.example" in f.detail


def test_diff_quiet_when_unchanged_or_first_seen():
    same = {"/checkout/": {"a": "1"}}
    assert scripts.diff(SITE, same, same) == []
    assert scripts.diff(SITE, {}, same) == []


def test_pick_cart_item_uses_variation_for_variable_products():
    prods = [
        {"id": 1, "type": "variable", "is_purchasable": True, "is_in_stock": False, "variations": [{"id": 2}]},
        {"id": 3, "type": "variable", "is_purchasable": True, "is_in_stock": True, "variations": [{"id": 4}]},
    ]
    assert scripts.pick_cart_item(prods) == 4


def test_spf_evaluation():
    assert mail_dns.evaluate_spf([]) [0] == "high"
    assert mail_dns.evaluate_spf(["v=spf1 +all"])[0] == "critical"
    assert mail_dns.evaluate_spf(["v=spf1 include:_spf.google.com -all"]) is None
    assert mail_dns.evaluate_spf(["v=spf1 -all", "v=spf1 a -all"])[0] == "high"


def test_dmarc_evaluation():
    assert mail_dns.evaluate_dmarc([])[0] == "high"
    assert mail_dns.evaluate_dmarc(["v=DMARC1; p=none; rua=mailto:x@y"])[0] == "medium"
    assert mail_dns.evaluate_dmarc(["v=DMARC1; p=reject"]) is None


def test_dns_change_detected():
    (f,) = mail_dns.diff_dns(SITE, {"A": ["1.1.1.1"]}, {"A": ["6.6.6.6"]})
    assert f.severity == "critical"


def test_discord_chunking_respects_limit():
    msgs = ["x" * 1000] * 5
    parts = chunk(msgs, limit=1900)
    assert all(len(p) <= 1900 for p in parts)
    assert sum(p.count("x") for p in parts) == 5000


def test_finding_default_key():
    assert Finding("s", "c", "low", "t").key == "c:t"


def test_resolved_message_lists_titles():
    from site_guard.notify import resolved_message
    msg = resolved_message("Example Shop", ["xmlrpc.php が有効です", "DMARCが未設定です"])
    assert "解消 2 件" in msg and "~~xmlrpc.php が有効です~~" in msg


def test_status_report_separates_handled_from_action_items():
    from datetime import date
    from site_guard.models import Finding
    from site_guard.notify import status_report
    handled = Finding("S", "wordpress", "low", "ログイン画面", key="wordpress:login-open", ack_note="二要素認証で保護済み")
    open_ = Finding("S", "mail", "high", "SPFレコードがありません", key="mail:spf")
    calm = "\n".join(status_report("S", [handled]))
    assert calm.startswith("🟢") and "保護済み" in calm
    alarm = "\n".join(status_report("S", [handled, open_]))
    assert alarm.startswith("🔴") and "1 件" in alarm
    expired = Finding("S", "mail", "medium", "DMARC", key="mail:dmarc-none", ack_note="12月に強化予定", ack_expired=True)
    assert "予定日を過ぎました" in "\n".join(status_report("S", [expired]))


def test_platform_detection():
    from site_guard.platform import detect, is_self_hosted
    wc = detect('<link href="/wp-content/plugins/woocommerce/x.css">', {})
    assert wc[0] == "WooCommerce" and "WordPress" in wc and is_self_hosted(wc) is True
    shop = detect('<script src="https://cdn.shopify.com/s/x.js">', {})
    assert shop == ["Shopify"] and is_self_hosted(shop) is False
    assert detect("<html></html>", {}) == [] and is_self_hosted([]) is None


def test_verify_token_is_stable_per_domain():
    from site_guard.ownership import verify_token
    assert verify_token("a.com") == verify_token("a.com") != verify_token("b.com")
    assert verify_token("a.com").startswith("site-guard-verify=")


def test_guideline_rows_never_overstate():
    from site_guard.guideline import ASK, NG, OK_SRV, PARTIAL, evaluate
    server = {"snapshot": {"admins": {"admin": {"two_factor": True}}, "core": "7.1.5", "plugins": {}},
              "findings": []}
    rows = {r.no: r for r in evaluate([], server, {}, has_payment_page=True)}
    # no IP restriction declared -> item 1 is partial, not done
    assert rows["1"].status == PARTIAL
    assert any(c.status == OK_SRV for c in rows["1"].checks)
    # antivirus missing -> item 4 partial; card testing unknown -> ask
    assert rows["4"].status == PARTIAL and rows["5"].status == ASK
    # without server state nothing claims server confirmation
    rows = {r.no: r for r in evaluate([], None, {}, has_payment_page=False)}
    assert all(c.status != OK_SRV for r in rows.values() for c in r.checks)
    assert any(c.status == NG for c in rows["4"].checks)


def test_diff_only_removed_scripts_is_low():
    from site_guard.checks.scripts import diff
    from site_guard.config import Site
    site = Site(name="S", base_url="https://s.example", payment_pages=["/checkout/"])
    f = diff(site, {"/checkout/": {"a": "1", "b": "2"}}, {"/checkout/": {"a": "1"}})
    assert len(f) == 1 and f[0].severity == "low"
    f = diff(site, {"/checkout/": {"a": "1"}}, {"/checkout/": {"a": "1", "evil": "9"}})
    assert f[0].severity == "critical"


# --- ownership gate -------------------------------------------------------

from site_guard import ownership


def test_unverified_without_txt_record(monkeypatch):
    monkeypatch.setattr(ownership.mail_dns, "txt_records", lambda name: [])
    ok, _ = ownership.is_verified("shop.example")
    assert not ok


def test_verified_by_txt_on_underscore_name(monkeypatch):
    token = ownership.verify_token("shop.example")
    monkeypatch.setattr(ownership.mail_dns, "txt_records",
                        lambda name: [token] if name == "_site-guard.shop.example" else [])
    ok, _ = ownership.is_verified("shop.example")
    assert ok


def test_www_is_verified_by_apex_record(monkeypatch):
    token = ownership.verify_token("shop.example")
    monkeypatch.setattr(ownership.mail_dns, "txt_records",
                        lambda name: [token] if name == "_site-guard.shop.example" else [])
    ok, _ = ownership.is_verified("www.shop.example")
    assert ok


def test_token_for_another_domain_does_not_verify(monkeypatch):
    other = ownership.verify_token("attacker.example")
    monkeypatch.setattr(ownership.mail_dns, "txt_records", lambda name: [other])
    ok, _ = ownership.is_verified("victim.example")
    assert not ok


def test_dns_error_means_unverified(monkeypatch):
    def boom(name):
        raise RuntimeError("SERVFAIL")
    monkeypatch.setattr(ownership.mail_dns, "txt_records", boom)
    assert not ownership.is_verified("shop.example")[0]


class _FakeResp:
    def __init__(self, url, text="<html></html>", status=200):
        self.url, self.text, self.status_code, self.ok, self.content = url, text, status, status < 400, b""
        self.headers = {}


class _RecordingSession:
    def __init__(self):
        self.urls = []

    def get(self, url, **kw):
        self.urls.append(url)
        return _FakeResp(url)


def test_collect_never_touches_cart_without_ownership():
    site = Site(name="t", base_url="https://shop.example", payment_pages=["/checkout/"],
                checkout_product_id="auto")
    s = _RecordingSession()
    scripts.collect(s, site, allow_cart=False)
    assert not any("add-to-cart" in u or "/wp-json/wc/store" in u for u in s.urls)


def test_wordpress_passive_mode_sends_no_probes():
    from site_guard.checks import wordpress
    site = Site(name="t", base_url="https://shop.example")
    s = _RecordingSession()
    wordpress.check(s, site, intrusive=False)
    probes = ("/wp-json/wp/v2/users", "/xmlrpc.php", ".env", "wp-config", ".git", "backup", ".sql", ".zip")
    assert not any(p in u for u in s.urls for p in probes)


def test_placeholder_config_is_refused(tmp_path):
    import pytest
    from site_guard.config import load_settings
    cfg = tmp_path / "sites.toml"
    cfg.write_text('[[site]]\nname = "x"\nbase_url = "https://example.com"\n')
    with pytest.raises(SystemExit) as e:
        load_settings(cfg)
    assert e.value.code == 2  # 1 would show as a green run in Actions


# --- GitHub Issue notifications -------------------------------------------

from site_guard import github_issues as gi


class _FakeGH:
    owner = "shop-owner"

    def __init__(self, issues=None):
        self.issues = list(issues or [])
        self.created, self.closed = [], []

    def open_issues(self, label=gi.LABEL):
        return [i for i in self.issues if label in i.get("labels", [gi.LABEL])]

    def create(self, title, body, labels):
        n = 100 + len(self.created)
        self.created.append({"number": n, "title": title, "body": body, "labels": labels})
        return {"number": n}

    def close(self, number, comment=None):
        self.closed.append((number, comment))


def _f(key, sev="medium", ack=""):
    f = Finding("Shop", "mail", sev, f"title {key}", key=key)
    f.ack_note = ack
    return f


def test_new_problem_opens_one_issue_with_marker_and_mention():
    gh = _FakeGH()
    issued, opened, closed = gi.sync(gh, "Shop", [_f("mail:dmarc-none")], set(), gh.open_issues())
    assert (opened, closed) == (1, 0)
    body = gh.created[0]["body"]
    assert "@shop-owner" in body and gi.marker("Shop", "mail:dmarc-none") in body
    assert issued == {"mail:dmarc-none"}


def test_existing_open_issue_is_not_duplicated():
    gh = _FakeGH([{"number": 7, "body": gi.marker("Shop", "mail:dmarc-none")}])
    _, opened, closed = gi.sync(gh, "Shop", [_f("mail:dmarc-none")], {"mail:dmarc-none"}, gh.open_issues())
    assert (opened, closed) == (0, 0)


def test_resolved_problem_closes_its_issue():
    gh = _FakeGH([{"number": 7, "body": gi.marker("Shop", "mail:dmarc-none")}])
    issued, opened, closed = gi.sync(gh, "Shop", [], {"mail:dmarc-none"}, gh.open_issues())
    assert closed == 1 and gh.closed[0][0] == 7 and issued == set()


def test_issue_closed_by_owner_is_not_reopened_every_run():
    gh = _FakeGH([])  # owner closed it; problem remains
    _, opened, _ = gi.sync(gh, "Shop", [_f("mail:dmarc-none")], {"mail:dmarc-none"}, gh.open_issues())
    assert opened == 0


def test_problem_that_returns_after_fix_opens_again():
    gh = _FakeGH([])
    issued, _, _ = gi.sync(gh, "Shop", [], {"mail:dmarc-none"}, [])
    _, opened, _ = gi.sync(gh, "Shop", [_f("mail:dmarc-none")], issued, [])
    assert opened == 1


def test_info_and_acknowledged_items_get_no_issue_and_ack_closes():
    gh = _FakeGH([{"number": 9, "body": gi.marker("Shop", "headers:x")}])
    items = [_f("headers:csp-report-only", sev="info"), _f("headers:x", ack="来月対応予定")]
    _, opened, closed = gi.sync(gh, "Shop", items, {"headers:x"}, gh.open_issues())
    assert opened == 0 and closed == 1


def test_other_sites_issues_are_left_alone():
    gh = _FakeGH([{"number": 5, "body": gi.marker("Other", "mail:dmarc-none")}])
    _, _, closed = gi.sync(gh, "Shop", [], set(), gh.open_issues())
    assert closed == 0


def test_critical_findings_are_labelled_urgent():
    gh = _FakeGH()
    gi.sync(gh, "Shop", [_f("scripts:diff:/checkout/:abc", sev="critical")], set(), [])
    assert gi.URGENT_LABEL in gh.created[0]["labels"]


def test_issues_channel_can_be_turned_off(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "x")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    assert gi.available()
    monkeypatch.setenv("SITE_GUARD_ISSUES", "off")
    assert not gi.available()


def test_runner_state_save_keeps_issued_issues(tmp_path, monkeypatch):
    from site_guard import state as st
    monkeypatch.setattr(st, "STATE_DIR", tmp_path)
    st.save("Shop", {"issued_issues": ["a"], "scripts": {}})
    prev = st.load("Shop")
    st.save("Shop", {**prev, "scripts": {"x": {}}})
    assert st.load("Shop")["issued_issues"] == ["a"]


def test_closing_sends_no_extra_comment():
    gh = _FakeGH([{"number": 7, "body": gi.marker("Shop", "mail:dmarc-none")}])
    gi.sync(gh, "Shop", [], {"mail:dmarc-none"}, gh.open_issues())
    assert gh.closed == [(7, None)]


def test_test_notice_is_one_email_and_stays_open():
    gh = _FakeGH()
    gi.test_notice(gh)
    assert len(gh.created) == 1 and gh.closed == []
