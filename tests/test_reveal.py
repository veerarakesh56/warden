"""The reveal (owner, 2026-10-20): authorised people see the real values behind an incident's placeholders, through
the records page, each reveal on the signed audit first; nobody else - and no AI - can.

Built on the records page's own tests (test_records_g10w) and the vault's fake KMS (test_vault)."""

from __future__ import annotations

import pathlib
import re
import urllib.parse

import pytest

from test_approval_page import setup as page_setup  # noqa: F401
from test_records_g10w import INC, _page
from test_slack_login_g10q import OTHER
from test_vault import EMAIL, MAPPING, FakeKms, FakeSsm, _sealed_pseudonym_key
from warden import reveal, slack_login, vault

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOKEN_FIELD = re.compile(r'name="t" value="([0-9a-f]{32})"')


@pytest.fixture
def site(page_setup, tmp_path, monkeypatch):  # noqa: F811
    """The records site with one incident whose map the read zone sealed; the approval role opens the vault."""
    monkeypatch.setenv("WARDEN_ENV", "ops")
    monkeypatch.delenv("WARDEN_RECORD_VIEWERS", raising=False)
    page, log = _page(page_setup, tmp_path)
    sealed = vault.Vault(key="alias/warden-ops-vault", environment="ops", kms=FakeKms("read"),
                         ssm=FakeSsm(_sealed_pseudonym_key())).seal(INC, MAPPING)
    vault.store(log, sealed)
    opener = vault.Vault(key="alias/warden-ops-vault", environment="ops", kms=FakeKms("approval"))
    monkeypatch.setattr(vault, "_BUILT", {("alias/warden-ops-vault", "ops"): opener})
    from test_slack_login_g10q import MEMBER

    cookie = slack_login.remember(page.slack, MEMBER)
    return page, log, cookie, MEMBER


def _get(page, cookie, query=""):
    return page.handle("GET", f"/r/{INC}/masked", query=query, cookies=[f"warden_who={cookie}"])


def _form(page, cookie, **extra):
    shown = _get(page, cookie)
    [t] = TOKEN_FIELD.findall(shown.body)
    q = [("reveal", "1"), ("t", t), ("why", "checking which customer the 5xx hit"), ("p", "<EMAIL_1>")]
    q += list(extra.items())
    return urllib.parse.urlencode(q)


def test_the_record_links_its_masked_values_and_they_show_by_id_without_a_reveal(site):
    page, log, cookie, _ = site
    record = page.handle("GET", f"/r/{INC}", cookies=[f"warden_who={cookie}"]).body
    assert f'href="/r/{INC}/masked">Masked values (3)' in record
    shown = _get(page, cookie)
    assert shown.status == 200 and "&lt;EMAIL_1&gt;" in shown.body and re.search(r"email:[0-9a-f]{12}", shown.body)
    assert EMAIL not in shown.body and not log.entries(INC, kinds=(reveal.REVEAL,))
    assert shown.headers["Cache-Control"] == "no-store" and shown.headers["Referrer-Policy"] == "no-referrer"
    assert "form-action https://" in shown.headers["Content-Security-Policy"]


def test_a_reveal_is_recorded_first_and_shows_only_what_was_chosen(site):
    page, log, cookie, member = site
    out = _get(page, cookie, _form(page, cookie))
    assert out.status == 200 and EMAIL in out.body
    assert MAPPING["<IPV4_1>"] not in out.body  # not chosen, not shown
    [row] = log.entries(INC, kinds=(reveal.REVEAL,))
    assert row["body"]["member"] == member and row["body"]["placeholders"] == ["<EMAIL_1>"]
    assert row["body"]["why"] == "checking which customer the 5xx hit" and EMAIL not in str(row["body"])


def test_no_row_no_value(site, monkeypatch):
    page, log, cookie, _ = site

    def broken(*_a, **_k):
        raise OSError("the audit is down")

    query = _form(page, cookie)
    monkeypatch.setattr(log, "append", broken)
    with pytest.raises(OSError):
        _get(page, cookie, query)  # the page fails; nothing was opened or shown


def test_a_forged_form_reveals_and_records_nothing(site):
    page, log, cookie, _ = site
    forged = urllib.parse.urlencode([("reveal", "1"), ("t", "0" * 32), ("why", "x" * 20), ("p", "<EMAIL_1>")])
    out = _get(page, cookie, forged)
    assert out.status == 400 and EMAIL not in out.body and not log.entries(INC, kinds=(reveal.REVEAL,))


@pytest.mark.parametrize("change", [{"why": "short"}, {"p": "<NOPE_1>"}])
def test_a_reason_and_a_known_value_are_required(site, change):
    page, log, cookie, _ = site
    query = _form(page, cookie).replace("why=checking", "why=" + change["why"] + "&x=") if "why" in change \
        else _form(page, cookie).replace("p=%3CEMAIL_1%3E", "p=" + urllib.parse.quote(change["p"]))
    out = _get(page, cookie, query)
    assert out.status == 400 and EMAIL not in out.body and not log.entries(INC, kinds=(reveal.REVEAL,))


def test_a_pasted_secret_in_the_reason_is_not_kept(site):
    page, log, cookie, _ = site
    key = "AKIA" + "IOSFODNN7EXAMPLE"
    _get(page, cookie, _form(page, cookie).replace("why=checking", "why=" + key + "+checking"))
    [row] = log.entries(INC, kinds=(reveal.REVEAL,))
    assert key not in row["body"]["why"]


def test_reveals_are_limited_per_reader(site, monkeypatch):
    page, _, cookie, _ = site
    monkeypatch.setattr(reveal, "MAX_PER_HOUR", 2)
    assert [_get(page, cookie, _form(page, cookie)).status for _ in range(3)] == [200, 200, 429]


def test_nobody_else_learns_the_incident_or_its_values(site):
    page, *_ = site
    stranger = slack_login.remember(page.slack, OTHER)  # signed in, on no list
    assert _get(page, stranger).status == 403
    signed_out = page.handle("GET", f"/r/{INC}/masked")
    assert EMAIL not in signed_out.body and "&lt;EMAIL_1&gt;" not in signed_out.body
    assert page.handle("POST", f"/r/{INC}/masked", cookies=[]).status == 404
    assert page.handle("GET", f"/r/{INC}/masked/x", cookies=[]).status == 404


def test_expired_values_are_said_to_be_gone(site):
    page, log, cookie, _ = site
    log.store.run("DELETE FROM vault")
    out = _get(page, cookie, _form(page, cookie))
    assert out.status == 410 and EMAIL not in out.body


def test_a_vault_that_will_not_open_shows_nothing_and_says_so(site, monkeypatch):
    page, log, cookie, _ = site
    monkeypatch.setattr(vault, "_BUILT", {("alias/warden-ops-vault", "ops"): vault.Vault(
        key="alias/warden-ops-vault", environment="ops", kms=FakeKms("llm"))})  # a role the key refuses
    out = _get(page, cookie, _form(page, cookie))
    assert out.status == 503 and EMAIL not in out.body
    assert log.entries(INC, kinds=(reveal.REFUSED,))


def test_no_ai_path_reaches_the_reveal():
    """No Temporal activity, MCP tool or command calls it: only the records page does."""
    src = ROOT / "src" / "warden"
    callers = {p.name for p in src.rglob("*.py") if re.search(r"\breveal\.(reveal|link)\(", p.read_text("utf-8"))}
    assert callers == {"approval_page.py"}
    from warden import workflows

    activities = {name for names in workflows.ZONES.values() for name in names}
    assert not {a for a in activities if "reveal" in a or "vault" in a}


def test_the_runtime_routes_the_masked_values_to_the_approval_function_alone():
    tf = (ROOT / "terraform" / "modules" / "warden-runtime" / "reveal.tf").read_text(encoding="utf-8")
    assert 'route_key = "GET /r/{incident}/masked"' in tf
    assert 'aws_apigatewayv2_integration.front["approval"]' in tf


def test_the_row_is_on_the_record_before_the_vault_is_opened(site, monkeypatch):
    page, log, cookie, _ = site
    real = vault._BUILT[("alias/warden-ops-vault", "ops")]
    seen = []

    class Spy:
        def open(self, row):
            seen.append(len(log.entries(INC, kinds=(reveal.REVEAL,))))
            return real.open(row)

    monkeypatch.setattr(vault, "_BUILT", {("alias/warden-ops-vault", "ops"): Spy()})
    assert _get(page, cookie, _form(page, cookie)).status == 200
    assert seen == [1]
