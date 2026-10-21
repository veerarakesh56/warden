"""Plant checks (S19, lane SE) broke each of these helper rules and no existing test failed: each is pinned here."""

from __future__ import annotations

import pytest

import test_playbook_stack as stack
from warden import catalog, playbook, resolver, tripwire
from warden.models import ContextBundle
from warden.playbook import detect


@pytest.fixture(autouse=True)
def _region(monkeypatch):
    monkeypatch.setenv("AWS_REGION", stack.REGION)


def _keys(**kw):
    return [p.key for p in detect(stack.alert(), stack.ctx(**kw))]


def test_an_unread_concurrency_plans_no_raise():
    entry = catalog.CATALOG["lambda_set_reserved_concurrency"]
    assert resolver._bounded(entry, {}, {}) == "the current concurrency was not read"


def test_a_short_text_gets_no_short_windows():
    cut = tripwire._Windows(lambda *a, **k: [])
    assert cut.short("a" * 50) == []


def test_a_long_text_gets_short_windows():
    cut = tripwire._Windows(lambda *a, **k: [])
    assert len(cut.short("a" * 300)) > 1


def test_one_sentence_is_not_scored_again_as_a_segment():
    cut = tripwire._Windows(lambda *a, **k: [])
    assert cut.segments("one sentence only that is long enough here") == []


def test_two_sentences_are_scored_as_segments():
    cut = tripwire._Windows(lambda *a, **k: [])
    assert len(cut.segments("The first sentence is long enough. The second sentence is long enough too.")) == 2


def test_an_ecs_login_refusal_asks_for_the_services_task_role():
    line = 'LOG ecs/orders-api x PAM authentication failed for user "app"'
    assert "for the failing ECS service" in playbook._db_iam_refused(ContextBundle(logs=[line]), line)


def test_another_login_refusal_asks_for_the_signing_identity():
    line = 'LOG lambda/fn x PAM authentication failed for user "app"'
    assert "the identity that signs the tokens" in playbook._db_iam_refused(ContextBundle(logs=[line]), line)


def test_the_evidence_specific_advice_leads_the_oncall_list():
    out: list = []
    playbook._add(out, "k", "t", "s", "c", "why", oncall=["x"])
    assert out[0].oncall == ["why", "x"]


def test_the_caches_own_group_is_not_an_application_group():
    ctx = ContextBundle(logs=["APPSG ecs/orders sgs=[sg-app1,sg-cache]"])
    assert playbook._app_sgs(ctx, ["sg-cache"]) == ["sg-app1"]


def test_an_error_rate_alone_is_its_own_pattern():
    assert _keys(metrics={"error_rate": 0.05}) == ["errors"]


def test_a_deploy_explains_an_error_rate():
    keys = _keys(metrics={"error_rate": 0.05, "replica_lag_seconds": 45.0}, deploys=[stack.ECS_DEPLOY])
    assert keys == ["replica_lag", "deploy"]


def test_unready_pods_alone_are_a_pattern():
    assert _keys(metrics={"pods_total": 3.0, "pods_ready": 1.0}) == ["unready"]


def test_unready_pods_are_not_listed_beside_an_oom_kill():
    assert "unready" not in _keys(metrics={"pods_total": 3.0, "pods_ready": 1.0, "oom_killed_containers": 1.0})


def test_text_past_the_detectors_budget_says_so():
    from warden import verifier
    from warden.environments import default_environment_policies

    findings = verifier._Findings()
    context = ContextBundle(suspected={tripwire.TOO_MUCH_TEXT: 1.0})
    verifier._tripwire_policies(findings, context, default_environment_policies().for_env("dev"))
    reason = (f"The text the model reads is larger than the injection detector's budget "
              f"({tripwire.MAX_SCAN_TOKENS} tokens), so it was not scanned; a person reads it.")
    assert findings.reasons == [reason]
