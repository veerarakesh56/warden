"""The independent review of G9-D1/D2a/D2b (2026-10-10, review-g9-d.md): each finding, held by a test that fails
without its fix."""

from __future__ import annotations

import pytest

from test_aws_fixes_g9d import DLQ, Queues
from test_aws_platform_g6 import NOW, WHO
from test_p15_review4 import _supports
from warden import activities, catalog, resolver
from warden.models import ActionKind as A
from warden.models import Alert, RemediationProposal, Severity
from warden.platforms.aws import AwsPlatform


@pytest.mark.parametrize("action,quote", [
    (A.raise_limit, "error_rate=0.42"), (A.raise_limit, "FATAL: too many connections"),
    (A.raise_limit, "connection limit exceeded"), (A.cancel_query, "DynamoDB Query took 120 ms"),
    (A.resume_flow, "task stopped: Essential container exited"), (A.pause_flow, "CrashLoopBackOff"),
])
def test_h1_evidence_that_says_nothing_about_the_action_supports_none(action, quote):
    assert not _supports(action, quote)


@pytest.mark.parametrize("action,quote", [
    (A.raise_limit, "429 Too Many Requests: throttled by the stage"), (A.raise_limit, "ThrottlingException"),
    (A.cancel_query, "query q-1 long-running, 40 GB scanned"), (A.resume_flow, "event source mapping disabled"),
    (A.pause_flow, "poison message redelivered 50 times"),
])
def test_h1_real_support_still_supports(action, quote):
    assert _supports(action, quote)


def test_h1_raise_limit_never_reaches_the_lambda_entry_scale_up_owns():
    assert catalog.for_action(A.raise_limit, "lambda") is None


def _platform():
    f = Queues()
    return f, AwsPlatform(reader=lambda service: f, actor=f.actor, clock=lambda: NOW, sleep=lambda s: None)


def test_h3_the_cancel_asks_for_what_aws_checks_and_the_move_fits_the_verify_window():
    f, p = _platform()
    params = {"queue": DLQ, "to_queue": "warden-dev-orders", "per_second": 10}
    f.moves = [{"Status": "RUNNING", "TaskHandle": "h-1"}]
    p.rollback("sqs_redrive_dlq", params, p.live("sqs_redrive_dlq", params)["state"], who=WHO)
    assert set(f.sessions[-1]["actions"]) == {"sqs:CancelMessageMoveTask", "sqs:ReceiveMessage", "sqs:DeleteMessage",
                                              "sqs:GetQueueAttributes"}
    live = p.live("sqs_redrive_dlq", {"queue": DLQ})
    assert catalog.validate("sqs_redrive_dlq", {**params, "per_second": 1}, {**live, "waiting": 5000})
    assert resolver._bounded(catalog.CATALOG["sqs_redrive_dlq"], {"queue": DLQ}, {"waiting": 5000}) == {
        "queue": DLQ, "per_second": 21}
    assert isinstance(resolver._bounded(catalog.CATALOG["sqs_redrive_dlq"], {}, {"waiting": 50 * 240 + 1}), str)


def test_m1_the_worker_routes_every_aws_platform_the_catalogue_has():
    from warden.cli import AWS_PLATFORMS
    from warden.platforms import aws

    assert set(AWS_PLATFORMS) == {catalog.CATALOG[e].platform for e in aws._KINDS}


def test_m2_m3_l7_a_redrive_goes_only_to_one_same_environment_unencrypted_source():
    f, p = _platform()
    assert p.live("sqs_redrive_dlq", {"queue": DLQ})["to_queue"] == {"warden-dev-orders"}
    f.sources = f.sources * 2  # two sources: one queue's messages would reach the other's consumer
    assert p.live("sqs_redrive_dlq", {"queue": DLQ})["to_queue"] == set()
    f.sources = f.sources[:1]
    tags = f.list_queue_tags
    f.list_queue_tags = lambda QueueUrl: {"Tags": {"Environment": "prod" if "orders-dlq" not in QueueUrl else "dev"}}
    assert p.live("sqs_redrive_dlq", {"queue": DLQ})["to_queue"] == set()
    f.list_queue_tags = tags


def test_m6_a_dead_letter_queues_depth_is_shown_but_not_drift():
    params = {"queue": DLQ, "to_queue": "warden-dev-orders", "per_second": 10}
    a = activities.plan_hash("sqs_redrive_dlq", params, {"queue": DLQ, "waiting": 42})
    assert a == activities.plan_hash("sqs_redrive_dlq", params, {"queue": DLQ, "waiting": 43})
    assert a != activities.plan_hash("sqs_redrive_dlq", params, {"queue": "x", "waiting": 42})


def test_l1_m2_every_named_resource_of_a_plan_is_of_the_incidents_environment():
    entry = catalog.CATALOG["sqs_redrive_dlq"]
    problems = activities._environment_problems(
        "dev", entry, {"queue": DLQ, "to_queue": "warden-prod-orders", "per_second": 10}, {"environment": "dev"})
    assert any("prod" in x for x in problems)


def test_l6_a_stage_inherits_its_apis_tags_and_the_api_is_what_is_named():
    f, p = _platform()
    f.stage = {**f.stage, "tags": {}}
    f.get_rest_apis = lambda limit, **kw: {"items": [{"id": "a1", "name": "warden-dev-shop",
                                                      "tags": {"Environment": "dev"}}]}
    assert p.live("apigw_raise_stage_throttle", {"api": "warden-dev-shop", "stage": "prod"})["environment"] == "dev"
    alert = Alert(alert_id="a1", name="n", service="warden-dev-shop", environment="dev", severity=Severity.high,
                  summary="", started_at="2026-10-10T00:00:00+00:00",
                  labels={"apigw_rest": "warden-dev-shop", "apigw_stage": "prod"})
    prop = RemediationProposal(action=A.raise_limit, target="warden-dev-shop", reasoning="r", expected_effect="e",
                               blast_radius="single_service", reversible=True)
    live = p.live("apigw_raise_stage_throttle", {"api": "warden-dev-shop", "stage": "prod"})
    req, why = resolver.request_for(alert, prop, lambda e, prm: live)
    assert why == "" and req["params"]["rate_limit"] == 200 and req["service"] == "warden-dev-shop"


def test_h2_a_pause_ends_mitigated_and_never_resolves_the_page(monkeypatch, tmp_path):
    from test_remediation_workflow import FakePlatform, _approve_with, _run
    from test_remediation_workflow import owner as owner_fixture
    from test_remediation_workflow import world as world_fixture
    from warden import chatops

    resolved = []
    monkeypatch.setattr(chatops, "page_resolve", lambda incident: resolved.append(incident))

    class Pause(FakePlatform):
        def live(self, entry, params):
            return {"function": {"warden-dev-fn"}, "mapping": {"u-1"}, "environment": "dev",
                    "state": dict(self.state)}

    key = owner_fixture.__wrapped__()
    world = world_fixture.__wrapped__(tmp_path, key)
    world["platform"] = Pause()
    out = _run(world, _approve_with(key), entry="lambda_disable_esm", service="u-1",
               params={"function": "warden-dev-fn", "mapping": "u-1"})
    assert out.status == "mitigated" and "stays paused until a person resumes it" in out.reasons[0]
    assert resolved == []
