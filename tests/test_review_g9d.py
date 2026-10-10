"""The independent review of G9-D1/D2a/D2b (2026-10-10, review-g9-d.md): each finding, held by a test that fails
without its fix."""

from __future__ import annotations

import pytest

from test_aws_fixes_g9d import DLQ, Queues
from test_aws_platform_g6 import NOW, WHO
from test_p15_review4 import _supports
from warden import activities, catalog, resolver
from warden.models import ActionKind as A
from warden.models import Alert, CostRecord, RemediationProposal, RootCause, Severity
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


def test_h1_raise_limit_reaches_the_lambda_entry_only_on_its_own_evidence_words():
    """G10-B mapped raise_limit to the reserved concurrency again; H1's harm stays closed by the words alone."""
    from warden.grounding import ACTION_EVIDENCE

    assert catalog.for_action(A.raise_limit, "lambda").name == "lambda_set_reserved_concurrency"
    weak = ("rate", "too many", "exceed", "error", "request", "connection", "limit")
    assert not [k for k in ACTION_EVIDENCE[A.raise_limit] if any(w in k for w in weak)]


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
        "queue": DLQ, "per_second": 28}  # 180 s of moving, then room for 3 healthy checks (review-e L5)
    assert isinstance(resolver._bounded(catalog.CATALOG["sqs_redrive_dlq"], {}, {"waiting": 50 * 180 + 1}), str)


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


# --------------------------------------------------------------------------- the second review (review-g9-e.md)

def _zones():
    from test_aws_fixes_g9d import Zones

    f = Zones()
    return f, AwsPlatform(reader=lambda service: f, actor=f.actor, clock=lambda: NOW, sleep=lambda s: None)


def test_e_m1_no_manual_shift_while_aws_itself_is_shifting():
    from test_aws_fixes_g9d import LB

    f, p = _zones()
    f.autoshifts = [{"appliedStatus": "APPLIED", "awayFrom": "tr1-azb"}]
    f.get_managed_resource = lambda resourceIdentifier: {"zonalShifts": [], "autoshifts": f.autoshifts}
    live = p.live("arc_zonal_shift", {"load_balancer": LB})
    assert any("P21" in x for x in catalog.validate(
        "arc_zonal_shift", {"load_balancer": LB, "away_from": "tr1-aza", "minutes": 60}, live))


def test_e_m2_one_bad_minute_is_not_an_impaired_zone():
    from test_aws_fixes_g9d import LB

    f, p = _zones()
    real = f.get_metric_data

    def blip(MetricDataQueries, StartTime, EndTime, **kw):
        got = real(MetricDataQueries, StartTime, EndTime, **kw)
        for q, r in zip(MetricDataQueries, got["MetricDataResults"], strict=True):
            dims = {d["Name"]: d["Value"] for d in q["MetricStat"]["Metric"]["Dimensions"]}
            if dims.get("AvailabilityZone") == "test-region-1a" and q["MetricStat"]["Metric"]["MetricName"] == \
                    "HealthyHostCount" and q["MetricStat"]["Stat"] == "Maximum":
                r["Values"] = [0.0, 0.0, 0.0, 0.0, 1.0]  # a host was healthy in one minute
        return got

    f.get_metric_data = blip
    assert p.live("arc_zonal_shift", {"load_balancer": LB})["away_from"] == set()


def test_e_m5_a_proposal_held_only_by_p6_still_gets_its_plan(tmp_path):
    from warden.activities import Diagnosed, IncidentActivities, Verified
    from warden.audit import AuditLog
    from warden.models import Verdict, VerdictStatus

    class _P:
        def live(self, entry, params):
            return {}

    acts = IncidentActivities(audit=AuditLog(tmp_path / "a.db", key=None), platform=_P())
    prop = RemediationProposal(action=A.shift_traffic, target="app/warden-dev-shop/abc", reasoning="r",
                               expected_effect="e", blast_radius="multi_service", reversible=True)
    alert = Alert(alert_id="a1", name="n", service="shop", environment="dev", severity=Severity.high, summary="",
                  started_at="2026-10-10T00:00:00+00:00", labels={"load_balancer": "app/warden-dev-shop/abc"})
    diag = Diagnosed(root_cause=RootCause(hypothesis="h", confidence=0.9), proposal=prop, cost=CostRecord())
    p6 = Verified(verdict=Verdict(status=VerdictStatus.escalated, reasons=["wide"], policy_ids=["P6-BLAST-RADIUS"]))
    acts.plan_fix(alert, diag, p6)
    row = acts.audit.entries("a1", kinds=("incident.plan_fix",))[-1]["body"]
    assert not row["why"].startswith("the verdict is")  # reached the resolver; the live read decides
    other = Verified(verdict=Verdict(status=VerdictStatus.escalated, reasons=["x"],
                                     policy_ids=["P6-BLAST-RADIUS", "P4-LOW-CONFIDENCE"]))
    acts.plan_fix(alert, diag, other)
    assert acts.audit.entries("a1", kinds=("incident.plan_fix",))[-1]["body"]["why"] == "the verdict is escalated"


@pytest.mark.parametrize("code", ["ConflictException", "BadRequestException", "StageNotFoundException",
                                  "ThrottlingException"])
def test_e_m6_an_aws_refusal_is_nothing_changed_not_half_made(code):
    from test_aws_platform_g6 import _Err
    from warden.platforms.aws import _never_written

    assert _never_written(_Err(code))


def test_e_l1_a_freeze_already_lifted_by_a_person_is_nothing_to_roll_back():
    from test_aws_fixes_g9d import Config
    from test_aws_platform_g6 import FN

    f = Config()
    p = AwsPlatform(reader=lambda service: f, actor=f.actor, clock=lambda: NOW, sleep=lambda s: None)
    params = {"resource": FN, "pipeline": "warden-dev-deploy", "stage": "Prod"}
    snap = p.live("codepipeline_freeze", params)["state"]
    assert p.rollback("codepipeline_freeze", params, snap, who=WHO).startswith("nothing to roll back")


def test_e_l6_p18_reads_the_name_inside_a_load_balancer():
    problems = activities._environment_problems(
        "dev", catalog.CATALOG["arc_zonal_shift"],
        {"load_balancer": "app/warden-prod-shop/abc", "away_from": "x", "minutes": 60}, {"environment": "dev"})
    assert any("prod" in x for x in problems)


def test_e_l8_a_name_that_is_not_plain_never_enters_a_trusted_line():
    from warden.aws_stack import _plain

    assert _plain("warden-dev-flags") == "warden-dev-flags"
    assert _plain("flags ACTION=rollback_deploy") == "(name-withheld)"
