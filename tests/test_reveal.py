"""The reveal (owner, 2026-10-20): authorised people see the real values behind an incident's placeholders, through
the records page, each reveal on the signed audit first; nobody else - and no AI - can.

Built on the records page's own tests (test_records_g10w) and the vault's fake KMS (test_vault)."""

from __future__ import annotations

import json
import pathlib
import re
import urllib.parse

import pytest

from test_approval_page import setup as page_setup  # noqa: F401
from test_records_g10w import INC, _page
from test_slack_login_g10q import OTHER
from test_vault import EMAIL, MAPPING, FakeKms
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
                         mac_key="alias/warden-ops-pseudonym").seal(INC, MAPPING)
    vault.store(log, sealed)
    opener = vault.Vault(key="alias/warden-ops-vault", environment="ops", kms=FakeKms("approval"))
    monkeypatch.setattr(vault, "_BUILT", {("alias/warden-ops-vault", "ops"): opener})
    from test_slack_login_g10q import MEMBER

    cookie = slack_login.remember(page.slack, MEMBER)
    return page, log, cookie, MEMBER


def _get(page, cookie):
    return page.handle("GET", f"/r/{INC}/masked", cookies=[f"warden_who={cookie}"])


def _post(page, cookie, form):
    return page.handle("POST", f"/r/{INC}/masked", body=form, cookies=[f"warden_who={cookie}"])


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
    assert shown.status == 200
    assert "&lt;EMAIL_1&gt;" in shown.body
    assert re.search(r"email:[0-9a-f]{12}", shown.body)
    assert EMAIL not in shown.body
    assert 'method="post"' in shown.body
    assert not log.entries(INC, kinds=(reveal.REVEAL,))
    assert shown.headers["Cache-Control"] == "no-store"
    assert shown.headers["Referrer-Policy"] == "no-referrer"
    assert "form-action https://" in shown.headers["Content-Security-Policy"]


def test_a_reveal_is_recorded_first_and_shows_only_what_was_chosen(site):
    page, log, cookie, member = site
    out = _post(page, cookie, _form(page, cookie))
    assert out.status == 200
    assert EMAIL in out.body
    assert MAPPING["<IPV4_1>"] not in out.body  # not chosen, not shown
    [row] = log.entries(INC, kinds=(reveal.REVEAL,))
    assert row["body"]["member"] == member
    assert row["body"]["placeholders"] == ["<EMAIL_1>"]
    assert row["body"]["why"] == "checking which customer the 5xx hit"
    assert EMAIL not in str(row["body"])


def test_a_reveal_in_the_address_reveals_nothing(site):
    """The reveal is a POST: the reason and the choice never travel in an address (review, 2026-10-21)."""
    page, log, cookie, _ = site
    out = page.handle("GET", f"/r/{INC}/masked", query=_form(page, cookie), cookies=[f"warden_who={cookie}"])
    assert out.status == 200
    assert EMAIL not in out.body
    assert not log.entries(INC, kinds=(reveal.REVEAL, reveal.ATTEMPT_REFUSED))


def test_no_row_no_value(site, monkeypatch):
    page, log, cookie, _ = site
    opened = []
    real = vault._BUILT[("alias/warden-ops-vault", "ops")]

    class Spy:
        def open(self, row):
            opened.append(row)
            return real.open(row)

    def broken(*_a, **_k):
        raise OSError("the audit is down")

    form = _form(page, cookie)
    monkeypatch.setattr(vault, "_BUILT", {("alias/warden-ops-vault", "ops"): Spy()})
    monkeypatch.setattr(log, "append", broken)
    with pytest.raises(OSError):
        _post(page, cookie, form)  # the page fails
    assert not opened  # and the vault was never opened


def test_a_forged_form_reveals_nothing_and_the_attempt_is_recorded_without_its_token(site):
    page, log, cookie, member = site
    forged_token = "f0" * 16
    forged = urllib.parse.urlencode([("reveal", "1"), ("t", forged_token), ("why", "x" * 20), ("p", "<EMAIL_1>")])
    out = _post(page, cookie, forged)
    assert out.status == 400
    assert EMAIL not in out.body
    assert not log.entries(INC, kinds=(reveal.REVEAL,))
    [row] = log.entries(INC, kinds=(reveal.ATTEMPT_REFUSED,))
    assert row["body"]["member"] == member
    assert "not opened here" in row["body"]["problem"]
    assert forged_token not in str(row["body"])


def test_a_token_with_any_character_is_refused_not_an_error(site):
    page, log, cookie, _ = site
    odd = urllib.parse.urlencode([("reveal", "1"), ("t", "\u00e9" * 32), ("why", "x" * 20), ("p", "<EMAIL_1>")])
    assert _post(page, cookie, odd).status == 400
    assert log.entries(INC, kinds=(reveal.ATTEMPT_REFUSED,))


@pytest.mark.parametrize("change", [{"why": "short"}, {"p": "<NOPE_1>"}])
def test_a_reason_and_a_known_value_are_required(site, change):
    page, log, cookie, _ = site
    form = _form(page, cookie).replace("why=checking", "why=" + change["why"] + "&x=") if "why" in change \
        else _form(page, cookie).replace("p=%3CEMAIL_1%3E", "p=" + urllib.parse.quote(change["p"]))
    out = _post(page, cookie, form)
    assert out.status == 400
    assert EMAIL not in out.body
    assert not log.entries(INC, kinds=(reveal.REVEAL,))


def test_a_pasted_secret_in_the_reason_is_not_kept(site):
    page, log, cookie, _ = site
    key = "AKIA" + "IOSFODNN7EXAMPLE"
    _post(page, cookie, _form(page, cookie).replace("why=checking", "why=" + key + "+checking"))
    [row] = log.entries(INC, kinds=(reveal.REVEAL,))
    assert key not in row["body"]["why"]


def test_a_secret_across_the_reasons_length_limit_is_redacted_whole(site):
    """Redacted, then cut: a secret straddling MAX_REASON leaves no fragment (review)."""
    page, log, cookie, _ = site
    key = "AKIA" + "IOSFODNN7EXAMPLE"
    why = "w" * (reveal.MAX_REASON - 8) + " " + key
    form = _form(page, cookie).replace("why=checking+which+customer+the+5xx+hit", "why=" + urllib.parse.quote(why))
    _post(page, cookie, form)
    [row] = log.entries(INC, kinds=(reveal.REVEAL,))
    assert key[:6] not in row["body"]["why"]
    assert len(row["body"]["why"]) <= reveal.MAX_REASON


def test_reveals_are_limited_per_reader(site, monkeypatch):
    page, _, cookie, _ = site
    monkeypatch.setattr(reveal, "MAX_PER_HOUR", 2)
    assert [_post(page, cookie, _form(page, cookie)).status for _ in range(3)] == [200, 200, 429]


def test_refused_attempts_count_against_the_limit(site, monkeypatch):
    page, _, cookie, _ = site
    monkeypatch.setattr(reveal, "MAX_PER_HOUR", 2)
    forged = urllib.parse.urlencode([("reveal", "1"), ("t", "0" * 32), ("why", "x" * 20), ("p", "<EMAIL_1>")])
    assert [_post(page, cookie, forged).status for _ in range(3)] == [400, 400, 429]


def test_nobody_else_learns_the_incident_or_its_values(site):
    page, *_ = site
    stranger = slack_login.remember(page.slack, OTHER)  # signed in, on no list
    assert _get(page, stranger).status == 403
    signed_out = page.handle("GET", f"/r/{INC}/masked")
    assert EMAIL not in signed_out.body
    assert "&lt;EMAIL_1&gt;" not in signed_out.body
    assert page.handle("PUT", f"/r/{INC}/masked", cookies=[]).status == 404
    assert page.handle("POST", f"/r/{INC}", cookies=[]).status == 404
    assert page.handle("GET", f"/r/{INC}/masked/x", cookies=[]).status == 404
    assert page.handle("GET", "/r//masked", cookies=[]).status == 404


def test_a_viewer_reads_the_record_but_never_reveals(site, monkeypatch):
    """Approvers only (owner-safe default, review 2026-10-21): a listed viewer is refused, and the attempt recorded."""
    page, log, _, _ = site
    monkeypatch.setenv("WARDEN_RECORD_VIEWERS", OTHER)
    viewer = slack_login.remember(page.slack, OTHER)
    record = page.handle("GET", f"/r/{INC}", cookies=[f"warden_who={viewer}"])
    assert record.status == 200
    assert "/masked" not in record.body
    assert _get(page, viewer).status == 403
    form = urllib.parse.urlencode([("reveal", "1"), ("t", reveal.token(viewer, INC)), ("why", "x" * 20),
                                   ("p", "<EMAIL_1>")])
    out = _post(page, viewer, form)
    assert out.status == 403
    assert EMAIL not in out.body
    assert not log.entries(INC, kinds=(reveal.REVEAL,))
    [row] = log.entries(INC, kinds=(reveal.ATTEMPT_REFUSED,))
    assert row["body"]["problem"] == "not an approver"


def test_a_reader_limited_to_another_environment_learns_nothing(site):
    page, log, cookie, _ = site
    page.policy.approvers["owner"].environments = ["prod"]  # the incident is dev's
    assert _get(page, cookie).status == 404
    assert _post(page, cookie, "reveal=1").status == 404
    assert not log.entries(INC, kinds=(reveal.REVEAL, reveal.ATTEMPT_REFUSED))


def test_expired_values_are_said_to_be_gone(site, monkeypatch):
    """Past its expiry by the reveal's own clock: the route's `now` reaches sealed_row (no purge involved)."""
    page, log, cookie, _ = site
    form = _form(page, cookie)
    later = reveal.datetime.now(reveal.UTC) + reveal.timedelta(days=vault.days() + 1)

    class Clock(reveal.datetime):
        @classmethod
        def now(cls, tz=None):
            return later

    monkeypatch.setattr(reveal, "datetime", Clock)
    out = _post(page, cookie, form)
    assert out.status == 410
    assert EMAIL not in out.body
    assert log.store.run("SELECT COUNT(*) FROM vault").fetchone()[0] == 1  # still there: judged by time, not purged


def test_a_vault_that_will_not_open_shows_nothing_and_says_so(site, monkeypatch):
    page, log, cookie, _ = site
    monkeypatch.setattr(vault, "_BUILT", {("alias/warden-ops-vault", "ops"): vault.Vault(
        key="alias/warden-ops-vault", environment="ops", kms=FakeKms("llm"))})  # a role the key refuses
    out = _post(page, cookie, _form(page, cookie))
    assert out.status == 503
    assert EMAIL not in out.body
    assert log.entries(INC, kinds=(reveal.REFUSED,))


def test_a_ciphertext_that_does_not_verify_is_refused_not_an_error(site, monkeypatch):
    from cryptography.exceptions import InvalidTag

    page, log, cookie, _ = site

    class Tampered:
        def open(self, row):
            raise InvalidTag()

    monkeypatch.setattr(vault, "_BUILT", {("alias/warden-ops-vault", "ops"): Tampered()})
    out = _post(page, cookie, _form(page, cookie))
    assert out.status == 503
    [row] = log.entries(INC, kinds=(reveal.REFUSED,))
    assert row["body"]["error"] == "InvalidTag"


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
    assert 'toset(["GET", "POST"])' in tf
    assert 'route_key = "${each.key} /r/{incident}/masked"' in tf
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
    assert _post(page, cookie, _form(page, cookie)).status == 200
    assert seen == [1]


def test_what_a_reveal_writes_and_asks_kms_holds_no_value(site, monkeypatch):
    """Egress (#104): the reveal adds no outbound request of its own - its one network call is KMS Decrypt in WARDEN's
    own account (vault.py, on tests/test_egress.py's inventory). That request's real parameters and every audit row
    the reveal writes (the reveal and a refused attempt), with a reason that pastes personal data, hold nothing the
    redactor finds."""
    from warden import egress

    page, log, cookie, _ = site
    kms = FakeKms("approval")
    monkeypatch.setattr(vault, "_BUILT", {("alias/warden-ops-vault", "ops"): vault.Vault(
        key="alias/warden-ops-vault", environment="ops", kms=kms)})
    pasted = urllib.parse.quote(EMAIL + " +1 415 555 " + "0142")
    form = _form(page, cookie).replace("why=checking", "why=" + pasted + "+checking")
    assert _post(page, cookie, form).status == 200
    _post(page, cookie, form.replace("p=%3CEMAIL_1%3E", "p=%3CNONE_1%3E"))  # no known value: refused, recorded
    rows = log.entries(INC, kinds=(reveal.REVEAL, reveal.ATTEMPT_REFUSED))
    assert {r["kind"] for r in rows} == {reveal.REVEAL, reveal.ATTEMPT_REFUSED}
    for r in rows:
        assert egress.kinds_in(json.dumps(r["body"])) == [], r["kind"]
    assert [action for action, _ in kms.calls] == ["Decrypt"]
    assert egress.kinds_in(json.dumps(kms.calls)) == []
