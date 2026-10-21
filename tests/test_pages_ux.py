"""WARDEN's pages, upgraded (owner, 2026-10-16): the records list pages and filters on the server - its query read
strictly, a limited approver still shown only its environments - the record page's way to the next one, light and dark
themes that pass WCAG 2.2 AA, a quiet background and a wave on a press that hold still for reduced motion, and the
logo in every header - all inside the pages' Content-Security-Policy."""

from __future__ import annotations

import base64
import dataclasses
import math
import re
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_approval_page import setup as page_setup  # noqa: F401
from test_slack_login_g10q import MEMBER, Slack, _login
from warden import approval_page, audit, brand, records, slack_login

T0 = datetime(2026, 10, 16, 9, 0, tzinfo=UTC)
ENDS = ("recovered", "denied", "")


def _log(tmp_path, n=137):
    """`n` incidents an hour apart, newest first by index: environments dev/prod in turn, services a/b/c, ends in
    turn (recovered -> "Fixed and held", denied -> "Denied", none -> "Waiting for approval")."""
    now = [T0]
    log = audit.AuditLog(tmp_path / "a.db", key=Ed25519PrivateKey.generate(), clock=lambda: now[0])
    for i in range(n):
        now[0] = T0 - timedelta(hours=i)
        cid = f"{i:016x}-x"
        env, svc = ("dev", "prod")[i % 2], "abc"[i % 3]
        log.append(cid, "incident.ingest", {"node": "ingest", "alert_id": cid, "env": env})
        log.append(cid, "incident.alert", {"alert": {"alert_id": cid, "name": "N", "service": svc, "environment": env,
                                                     "labels": {"alarm": f"warden-{env}-{svc}-alarm-{i}"}}})
        log.append(cid, "remediation.plan", {"workflow_id": f"w{i}", "entry": "e", "tier": "T1", "target": "t",
                                             "plan_hash": "h"})
        if ENDS[i % 3]:
            log.append(cid, "workflow.end", {"workflow_id": f"w{i}", "status": ENDS[i % 3], "reasons": []})
    return log


@pytest.fixture
def site(page_setup, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.delenv("WARDEN_RECORD_VIEWERS", raising=False)
    page = page_setup[0]
    policy = page.policy.model_copy(deep=True)
    policy.approvers["owner"].slack = MEMBER
    page = dataclasses.replace(page, policy=policy, log=_log(tmp_path), slack=_login(Slack()))
    me = ["warden_who=" + slack_login.remember(page.slack, MEMBER)]
    return page, me


def _get(site, path="/r", query=""):
    page, me = site
    return page.handle("GET", path, query=query, cookies=me)


def _rows(body):
    return re.findall(r'<details class="row">.*?<strong>([^<]+)</strong>', body)


# ------------------------------------------------------------------ paging


def test_pages_count_and_show_where_the_reader_is_and_past_the_end_is_the_last_page(site):
    second = _get(site, query="page=2&size=25")
    assert second.status == 200
    assert "Showing <strong>26–50</strong> of <strong>137</strong>" in second.body
    assert len(_rows(second.body)) == 25
    assert _rows(second.body)[0] == "warden-prod-b-alarm-25"
    assert 'href="/r?size=25" rel="prev">Newer' in second.body
    assert 'href="/r?page=3&amp;size=25" rel="next">Older' in second.body
    assert 'href="/r?page=6&amp;size=25"><span class="t">Oldest' in second.body
    assert "Page 2 of 6" in second.body
    last = _get(site, query="page=6&size=25")
    assert "Showing <strong>126–137</strong>" in last.body
    assert len(_rows(last.body)) == 12
    assert '<span class="step next off" aria-disabled="true">Older</span>' in last.body
    beyond = _get(site, query="page=999&size=25")
    assert beyond.status == 200
    assert _rows(beyond.body) == _rows(last.body)
    assert "Page 6 of 6" in beyond.body
    assert len(_rows(_get(site).body)) == records.PER_PAGE  # no query: the default size, page 1


@pytest.mark.parametrize("query", ["size=7", "size=abc", "size=", "size=1000"])
def test_a_page_size_not_offered_is_the_default_one(site, query):
    out = _get(site, query=query)
    assert out.status == 200
    assert len(_rows(out.body)) == records.PER_PAGE
    assert '<span class="chip" aria-current="true">50</span>' in out.body


@pytest.mark.parametrize("query", [
    "page=-1", "page=0", "page=abc", "page=1.5", "page=%EF%BC%91", "page=1&page=2", "pages=2", "page=2&",
    "env=PROD", "env=dev;drop", "status=Pwned", "service=a%20b", "from=2026-13-01", "from=16-10-2026",
    "from=2026-10-16&to=2026-10-01", "q=" + "x" * 101, "q=a%00b", "a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8&i=9"])
def test_a_query_the_list_does_not_read_is_refused_whole(site, query):
    assert records.parse_query(query) is None
    out = _get(site, query=query)
    assert out.status == 400
    assert "That list cannot be shown" in out.body
    assert "-alarm-" not in out.body
    assert _get(site, f"/r/{0:016x}-x", query=query).status == 400  # the record page reads the same query


# ------------------------------------------------------------------ filters


def test_filters_combine_and_every_link_keeps_them(site):
    out = _get(site, query="env=dev&status=Denied&q=ALARM&size=10")
    shown = _rows(out.body)
    # dev: even i; Denied: i % 3 == 1 -> i in 4, 10, 16, ... (i % 6 == 4)
    assert shown
    assert (all(re.fullmatch(r"warden-dev-[abc]-alarm-(\d+)", t) and int(t.rsplit("-", 1)[1]) % 6 == 4
                for t in shown))
    assert "of <strong>23</strong> matching the filters" in out.body
    assert len(shown) == 10
    assert 'href="/r?page=2&amp;size=10&amp;env=dev&amp;status=Denied&amp;q=ALARM" rel="next">Older' in out.body
    assert f'href="/r/{4:016x}-x?size=10&amp;env=dev&amp;status=Denied&amp;q=ALARM">Open the full record' in out.body
    assert '<option value="Denied" selected>' in out.body
    assert 'value="ALARM"' in out.body
    for control in re.findall(r'<(?:input|select) id="([a-z-]+)"', out.body):  # every filter labelled
        assert f'<label for="{control}">' in out.body, control
    assert len(re.findall(r'<(?:input|select) id=', out.body)) == 6
    from warden.environments import default_environment_policies

    offered = re.findall(r'<option value="([^"]*)"', out.body.split('id="f-env"')[1].split("</select>")[0])
    assert offered == ["", *default_environment_policies().known_environments]  # environments.yaml's own
    assert 'value="ID"' in _get(site, query="q=ID").body  # the text, not the field's own name
    svc = _get(site, query="service=B&from=2026-10-15&to=2026-10-15")
    days = set(re.findall(r'<h2 class="day">([^<]+)</h2>', svc.body))  # the display zone's day, as the list says it
    assert _rows(svc.body)
    assert all("-b-" in t for t in _rows(svc.body))
    assert days == {"Thursday 15 October 2026"}
    assert "No incident matches these filters." in _get(site, query="q=nothing-like-this").body


def test_a_reader_limited_to_some_environments_sees_only_those(site):
    page, me = site
    page.policy.approvers["owner"].environments = ["dev"]
    out = page.handle("GET", "/r", cookies=me)
    assert "of <strong>69</strong>" in out.body
    assert "137" not in out.body
    assert all(t.startswith("warden-dev-") for t in _rows(out.body))
    assert "No incident" in page.handle("GET", "/r", query="env=prod", cookies=me).body
    assert '<option value="prod"' not in out.body
    assert '<option value="dev">' in out.body
    assert page.handle("GET", f"/r/{1:016x}-x", cookies=me).status == 404  # prod: not shown, not said to exist
    one = page.handle("GET", f"/r/{2:016x}-x", cookies=me)
    assert one.status == 200
    assert f'href="/r/{0:016x}-x" rel="prev">Newer' in one.body
    assert f'href="/r/{4:016x}-x" rel="next">Older' in one.body
    assert "2 of 69" in one.body
    page.policy.approvers["owner"].environments = []  # an approver with no list reads every environment
    assert page.handle("GET", f"/r/{1:016x}-x", cookies=me).status == 200


def test_a_record_page_leads_to_the_newer_and_older_one_within_the_same_filters(site):
    one = _get(site, f"/r/{4:016x}-x", query="env=dev&status=Denied&size=10")
    assert one.status == 200
    assert "1 of 23" in one.body
    assert '<span class="step prev off" aria-disabled="true">Newer</span>' in one.body
    assert f'href="/r/{10:016x}-x?size=10&amp;env=dev&amp;status=Denied" rel="next">Older' in one.body
    assert 'href="/r?size=10&amp;env=dev&amp;status=Denied">All incidents' in one.body
    deep = _get(site, f"/r/{60:016x}-x")
    assert 'href="/r?page=2">All incidents' in deep.body
    assert "61 of 137" in deep.body  # back to its own page


# ------------------------------------------------------------------ the policy every page is served under


def _every_page(site):
    page, _ = site
    token = page.new_link("rem-dev-1", "owner")
    return {"approval": page.handle("GET", f"/a/{token}"), "list": _get(site), "record": _get(site, f"/r/{0:016x}-x"),
            "signed-out": page.handle("GET", "/r"), "bad": _get(site, query="page=0"),
            "missing": _get(site, "/r/nope"), "notice": page.handle("GET", "/s/a/" + "x" * 43)}


def test_every_page_keeps_its_policy_and_needs_nothing_it_refuses(site):
    for name, r in _every_page(site).items():
        csp = r.headers["Content-Security-Policy"]
        nonce = re.search(r"script-src 'nonce-([^']+)'", csp).group(1)
        assert "default-src 'none'" in csp, name
        assert "frame-ancestors 'none'" in csp, name
        assert re.search(r"img-src ([^;]+);", csp).group(1) == "data:", name  # the tab icon only; no host
        assert f"style-src 'nonce-{nonce}'" in csp, name
        assert "unsafe" not in csp, name
        form = re.search(r"form-action ([^;]+);", csp).group(1)
        assert form == ("https://approve.example.test/r" if name == "list" else "'none'"), name
        body = r.body
        assert body.count("<script") == body.count(f'<script nonce="{nonce}">') == 1, name
        assert body.count("<style") == body.count(f'<style nonce="{nonce}">') == 1, name
        assert not re.search(r"\son[a-z]+\s*=", body, re.IGNORECASE), name
        assert ' style="' not in body, name  # no inline handler
        for refused in ("http://", "https://", "<img", "<iframe", "@import", "url(", "{{"):
            assert refused not in body, (name, refused)
        assert body.count("<link") == 1, name  # the tab icon alone
        assert brand.FAVICON_LINK in body.split("</head>")[0], name
        assert brand.LOGO_SVG in body, name
        assert '<canvas id="sky" aria-hidden="true">' in body, name


def test_the_theme_toggle_is_labelled_remembered_safely_and_starts_from_the_device(site):
    body = _every_page(site)["list"].body
    assert '<div id="theme" class="theme" role="group" aria-label="Colour theme" hidden>' in body
    for mode, label in (("system", "Theme as the device"), ("light", "Light theme"), ("dark", "Dark theme")):
        assert re.search(rf'<button type="button" data-mode="{mode}" aria-pressed="(true|false)" title="{label}">'
                         rf'<svg[^>]*aria-hidden="true"[^>]*>.*?</svg><span class="vh">{label}</span></button>', body)
    js = approval_page._UI_JS
    assert js.count("localStorage.") == 3
    assert js.count("try {") >= 3  # every read and write caught
    assert ':root[data-theme=dark]{color-scheme:dark;' in body
    assert "@media (prefers-color-scheme:dark){:root:not([data-theme=light]){color-scheme:dark;" in body


def test_motion_holds_still_when_asked_and_the_sky_is_small_and_sleeps(site):
    css, js = approval_page._STYLE, approval_page._UI_JS
    still = css[css.index("@media (prefers-reduced-motion:reduce)"):]
    assert (still.startswith("@media (prefers-reduced-motion:reduce){*,::before,::after{transition:none!important;"
                             "animation:none!important}"))
    assert ".rip{display:none}" in still
    assert "if (calm.matches || t.disabled) { return; }" in js  # no wave
    assert "if (calm.matches) { px = py = -9e3; draw(); }" in js  # the sky drawn once, still
    assert "document.hidden" in js
    assert '"visibilitychange", sky' in js
    assert "Math.min(devicePixelRatio || 1, 1.5)" in js
    assert len(approval_page._SKY_JS.encode()) < 3072
    assert ":focus-visible{outline:3px solid var(--accent)" in css
    assert js.strip().startswith("(() => { try {")
    assert js.rstrip().endswith("} catch (e) {} })();")


def test_the_logo_stays_inside_the_policy():
    svg = brand.LOGO_SVG
    assert svg.startswith("<svg")
    assert 'aria-hidden="true"' in svg
    assert "xmlns" not in svg
    assert not re.search(r"\son[a-z]+\s*=|style=|<script|<image|<use|<foreignObject|//|href", svg, re.IGNORECASE)
    assert all(i.startswith("wdn-") for i in re.findall(r'\sid="([^"]+)"', svg))
    assert all(u.startswith("url(#wdn-") for u in re.findall(r"url\([^)]*\)", svg))
    assert "#000" not in svg
    assert "#fff" not in svg.lower()  # the pages' own test refuses them


def test_the_tab_icon_is_the_logo_embedded_and_fetches_nothing():
    link = brand.FAVICON_LINK
    prefix = '<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,'
    assert link.startswith(prefix)
    assert link.endswith('">')
    tab = base64.b64decode(link[len(prefix):-2], validate=True).decode()
    assert tab.startswith('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">')
    assert re.findall(r"<(?:path|circle)[^>]*/>", tab) == re.findall(r"<(?:path|circle)[^>]*/>", brand.LOGO_SVG)
    rest = tab.replace('xmlns="http://www.w3.org/2000/svg"', "")
    assert not re.search(r"\son[a-z]+\s*=|style=|<script|<image|<use|<foreignObject|//|href", rest, re.IGNORECASE)


# ------------------------------------------------------------------ escaping


def test_a_records_text_never_becomes_markup_or_a_placeholder(site, tmp_path):
    page, me = site
    log = audit.AuditLog(tmp_path / "e.db", key=Ed25519PrivateKey.generate())
    cid = "e-1"
    log.append(cid, "incident.ingest", {"node": "ingest", "alert_id": cid, "env": "dev"})
    log.append(cid, "incident.alert", {"alert": {"alert_id": cid, "name": "N", "environment": "dev", "service": "s",
                                                 "labels": {"alarm": '"><svg onload=alert(1)>{{NONCE}}{{SCRIPT}}'}}})
    page = dataclasses.replace(page, log=log)
    for out in (page.handle("GET", "/r", cookies=me), page.handle("GET", f"/r/{cid}", cookies=me)):
        nonce = re.search(r"'nonce-([^']+)'", out.headers["Content-Security-Policy"]).group(1)
        assert "<svg onload" not in out.body
        assert "&quot;&gt;&lt;svg onload=alert(1)&gt;" in out.body
        assert out.body.count(nonce) == 2
        assert "&#123;&#123;NONCE&#125;&#125;" in out.body
    notice = approval_page._notice(403, "Slack sign-in failed: <b>{{NONCE}}</b>.")
    assert "&lt;b&gt;&#123;&#123;NONCE&#125;&#125;&lt;/b&gt;" in notice.body


# ------------------------------------------------------------------ contrast, WCAG 2.2 AA


def _tokens(block: str) -> dict[str, tuple[float, float, float, float]]:
    out = {}
    for name, l_, c, h, a in re.findall(r"--([a-z0-9-]+):oklch\(([\d.]+) ([\d.]+) ([\d.]+)(?:/([\d.]+))?\)", block):
        out[name] = (float(l_), float(c), float(h), float(a) if a else 1.0)
    return out


def _rgb(lch):
    lightness, c, h, _ = lch
    a, b = c * math.cos(math.radians(h)), c * math.sin(math.radians(h))
    l_ = (lightness + 0.3963377774 * a + 0.2158037573 * b) ** 3
    m = (lightness - 0.1055613458 * a - 0.0638541728 * b) ** 3
    s = (lightness - 0.0894841775 * a - 1.2914855480 * b) ** 3
    rgb = (4.0767416621 * l_ - 3.3077115913 * m + 0.2309699292 * s,
           -1.2684380046 * l_ + 2.6097574011 * m - 0.3413193965 * s,
           -0.0041960863 * l_ - 0.7034186147 * m + 1.7076147010 * s)
    return tuple(min(1.0, max(0.0, v)) for v in rgb)  # linear sRGB, clipped to the gamut a screen shows


def _over(top, ground, alpha):
    return tuple(t * alpha + g * (1 - alpha) for t, g in zip(top, ground, strict=True))


def _ratio(x, y):
    lum = [0.2126 * r + 0.7152 * g + 0.0722 * b for r, g, b in (x, y)]
    return (max(lum) + 0.05) / (min(lum) + 0.05)


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_every_text_on_every_ground_passes_wcag_aa_in_both_themes(theme):
    t = _tokens(approval_page._LIGHT if theme == "light" else approval_page._DARK)
    sheet = _rgb(t["sheet"])
    # The panel is translucent: its ground is the sheet over whatever lies behind it - the page, or an aurora's glow.
    panels = [_over(sheet, _rgb(t[under]), t["panel"][3]) for under in ("bg", "bg2", "aur1", "aur2", "aur3")]
    grounds = [sheet, _rgb(t["well"]), *panels]
    for text in ("ink", "muted", "accent", "ok", "warn", "bad"):
        worst = min(_ratio(_rgb(t[text]), g) for g in grounds)
        assert worst >= 4.5, (theme, text, round(worst, 2))
    assert _ratio(_rgb(t["accent-ink"]), _rgb(t["accent"])) >= 4.5  # a primary button's label, and the chosen chip
    assert _ratio(_rgb(t["accent-ink"]), _rgb(t["accent-hi"])) >= 4.5  # and hovered
    assert min(_ratio(_rgb(t["accent"]), g) for g in grounds) >= 3  # the focus ring, a non-text contrast
