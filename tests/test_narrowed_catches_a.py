"""Hidden warnings, first lot (owner, 2026-10-17): every blind `except Exception` either names what the call really
raises, or stays broad with its reason on the line - and then leaves a record of what it caught, never swallows it.

These pin the narrowed catches (a malformed request is still answered, never a crash) and the records the kept ones
now write."""

from __future__ import annotations

import base64
import json
import logging

import pytest

from test_bench_approver import _page, _plan
from test_killswitch_reset_g10m import World
from test_killswitch_stop_page import _off
from test_platform_db import _Conn, _platform
from test_revert_config_history_g10d3 import ECS, Fake, _p
from warden import bounds, environments, slack_login
from warden.approval_page import STOP_INVITE, ApprovalPage


def test_a_signed_approval_of_the_wrong_shape_is_refused_whole(tmp_path):
    page, _, _, sent = _page(tmp_path, _plan())
    for body in ({"approver": "bench"}, {"approver": "bench", "workflow_id": ["not", "a", "string"]}):
        got = page.handle("POST", "/a/signed/approve", json.dumps(body))
        assert got.status == 400
        assert json.loads(got.body) == {"error": "not a signed approval"}
    assert not sent


@pytest.mark.parametrize("body", ["not json", "[1, 2]", '"a string"', "\xff"])
def test_a_stop_request_that_is_not_an_object_stops_nothing_and_never_crashes(tmp_path, body):
    w = World(tmp_path)
    token = w.link(STOP_INVITE)
    assert w.page.handle("POST", f"/x/{token}/options", body).status == 400


@pytest.mark.parametrize("body", ["not json", "[1, 2]", json.dumps({"reason": "stop now"}),
                                  json.dumps({"reason": "stop now", "response": "not an assertion"})])
def test_a_stop_answer_that_cannot_be_read_stops_nothing(tmp_path, body):
    w = World(tmp_path)
    _off(w)
    token = w.link(STOP_INVITE)
    assert w.page.handle("POST", f"/x/{token}/options", json.dumps({"reason": "stop now"})).status == 200
    assert w.page.handle("POST", f"/x/{token}/on", body).status in (400, 403)
    assert bounds.killswitch(w.log) is None


def test_the_filter_offers_only_any_when_the_environment_policy_cannot_be_read(monkeypatch):
    def broken():
        raise environments.EnvironmentPolicyError("environment policy is not valid YAML")

    monkeypatch.setattr(environments, "default_environment_policies", broken)
    assert ApprovalPage._environment_choices(None) == ()
    assert ApprovalPage._environment_choices({"dev"}) == ("dev",)


def _token(claims) -> str:
    part = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"header.{part}.signature"


@pytest.mark.parametrize("claims", [["a", "list"], "a string", 7, None])
def test_a_slack_answer_whose_claims_are_not_an_object_is_unreadable_never_a_crash(claims):
    login = slack_login.SlackLogin("client", "s3cret-not-real",
                                   post=lambda url, form: {"ok": True, "id_token": _token(claims)})
    with pytest.raises(slack_login.SlackLoginError, match="could not be read"):
        login.member("c", redirect_uri="r", nonce="n")


@pytest.mark.parametrize("token", ["header.!!!.signature", "header.bm90IGpzb24.signature", "header./w.signature"])
def test_a_slack_token_whose_payload_is_not_base64_utf8_json_is_unreadable(token):
    login = slack_login.SlackLogin("client", "s3cret-not-real", post=lambda url, form: {"ok": True, "id_token": token})
    with pytest.raises(slack_login.SlackLoginError, match="could not be read"):
        login.member("c", redirect_uri="r", nonce="n")


@pytest.mark.parametrize("error", [TimeoutError("no route"), ValueError("not json"), OSError("reset")])
def test_slack_unreachable_or_unreadable_is_a_sign_in_that_did_not_happen(error):
    def post(url, form):
        raise error

    login = slack_login.SlackLogin("client", "s3cret-not-real", post=post)
    with pytest.raises(slack_login.SlackLoginError, match=f"could not be reached \\({type(error).__name__}\\)"):
        login.member("c", redirect_uri="r", nonce="n")


def test_a_failed_aws_health_check_is_not_healthy_and_says_why(caplog):
    class Broken(Fake):
        def describe_services(self, *a, **kw):
            raise RuntimeError("throttled")

    with caplog.at_level(logging.WARNING, logger="warden.platforms"):
        assert _p(Broken()).healthy("warden-dev-orders", "ecs_rollback_service", ECS) is False
    assert "the health check for ecs_rollback_service failed (RuntimeError): not healthy" in caplog.text


def test_a_failed_aws_live_read_allows_nothing_and_says_why(caplog):
    f = Fake()

    def boom(*a, **kw):
        raise KeyError("Services")

    f.describe_services = boom
    with caplog.at_level(logging.WARNING, logger="warden.platforms"):
        assert _p(f).live("ecs_restore_desired", ECS) == {}
    assert "the live read for ecs_restore_desired failed (KeyError): nothing is allowed" in caplog.text


def test_an_unreadable_database_is_not_healthy_allows_nothing_and_says_why(caplog):
    with caplog.at_level(logging.WARNING, logger="warden.platforms"):
        assert _platform(conn=_Conn(fail=True)).live("db_terminate_idle_in_tx", {}) == {}
        assert _platform(conn=_Conn(fail=True)).healthy("orders") is False
    assert "the database could not be read" in caplog.text
