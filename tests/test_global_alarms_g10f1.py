"""G10-F1: CloudFront and Route 53 health-check alarms live only in AWS's global-services Region; WARDEN listened and
read only in its runtime Region (held-out G9-F: two cases neither received nor read). One rule there forwards the
watched environments' alarm changes, unchanged, to the runtime Region's bus; intake keeps the event's Region as the
`alarm_region` label, and the incident's reads run there, in the same environment's reader role."""

from __future__ import annotations

import contextlib
import importlib.util
import json
import pathlib

import pytest

from warden import aws_stack, lambdas
from warden.environments import EnvironmentPolicies
from warden.models import Alert, Severity
from warden.tools import ToolError

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("forward", ROOT / "scripts" / "forward_global_alarms.py")
forward = importlib.util.module_from_spec(spec)
spec.loader.exec_module(forward)
CFG = EnvironmentPolicies.load()
ACCOUNT = "0" * 12


def test_the_plan_forwards_every_watched_environments_alarms_to_the_runtime_regions_bus_only():
    p = forward.plan(ACCOUNT)
    assert p["global_region"] == CFG.aws_global_region != CFG.aws_region
    assert p["bus"] == f"arn:aws:events:{CFG.aws_region}:{ACCOUNT}:event-bus/default"
    assert [x["prefix"] for x in p["pattern"]["detail"]["alarmName"]] == [f"warden-{e}-" for e in CFG.known_environments]
    assert p["policy"]["Statement"] == [{"Sid": "OnlyTheRuntimeRegionsDefaultBus", "Effect": "Allow",
                                         "Action": "events:PutEvents", "Resource": p["bus"]}]
    assert p["trust"]["Statement"][0]["Condition"] == {"StringEquals": {"aws:SourceAccount": ACCOUNT}}
    assert p["boundary"].endswith(f":policy/WardenEnvBoundary-{CFG.runtime_environment}")


class _Iam:
    class exceptions:
        class NoSuchEntityException(Exception):
            pass

    def __init__(self, exists=False):
        self.calls, self.exists = [], exists

    def __getattr__(self, name):
        def call(**kw):
            self.calls.append((name, kw))
            if name == "get_role":
                if not self.exists:
                    raise self.exceptions.NoSuchEntityException()
                return {"Role": {"Arn": "arn:role"}}
            if name == "create_role":
                return {"Role": {"Arn": "arn:role"}}
            if name == "list_targets_by_rule":
                return {"Targets": [{"Id": "runtime-bus"}]}
            return {}
        return call


def test_apply_makes_the_role_once_and_the_rule_with_its_one_target_and_undo_removes_exactly_that():
    p = forward.plan(ACCOUNT)
    iam, events = _Iam(), _Iam()
    forward.apply(p, iam, events)
    created = [kw for n, kw in iam.calls if n == "create_role"]
    assert created and created[0]["PermissionsBoundary"] == p["boundary"]
    assert ("put_targets", {"Rule": p["rule"], "Targets": [{"Id": "runtime-bus", "Arn": p["bus"],
                                                            "RoleArn": "arn:role"}]}) in events.calls
    again = _Iam(exists=True)
    forward.apply(p, again, _Iam())
    assert not [n for n, _ in again.calls if n == "create_role"]
    iam, events = _Iam(), _Iam()
    forward.apply(p, iam, events, undo=True)
    assert [n for n, _ in events.calls] == ["list_targets_by_rule", "remove_targets", "delete_rule"]
    assert [n for n, _ in iam.calls] == ["delete_role_policy", "delete_role"]


def _event(region):
    return {"source": "aws.cloudwatch", "detail-type": "CloudWatch Alarm State Change", "region": region,
            "time": "2026-10-10T08:00:00Z",
            "detail": {"alarmName": "warden-dev-cdn-5xx", "state": {"value": "ALARM", "timestamp": "2026-10-10T08:00:00Z"},
                       "configuration": {"metrics": [{"metricStat": {"metric": {
                           "namespace": "AWS/CloudFront", "name": "5xxErrorRate",
                           "dimensions": {"DistributionId": "E2QWRUHAPOMQZL", "Region": "Global"}}}}]}}}


def test_intake_keeps_another_regions_alarm_region_and_adds_nothing_for_its_own(monkeypatch):
    monkeypatch.setenv("AWS_REGION", CFG.aws_region)
    there = lambdas.alarm_event(_event(CFG.aws_global_region), "dev").alert
    assert there.labels["alarm_region"] == CFG.aws_global_region and not there.rejected_labels
    here = lambdas.alarm_event(_event(CFG.aws_region), "dev").alert
    assert "alarm_region" not in here.labels


def test_a_dimension_cannot_pose_as_the_alarms_region(monkeypatch):
    monkeypatch.setenv("AWS_REGION", CFG.aws_region)
    ev = _event(CFG.aws_region)
    ev["detail"]["configuration"]["metrics"][0]["metricStat"]["metric"]["dimensions"]["alarm_region"] = "xx-evil-1"
    assert "alarm_region" not in lambdas.alarm_event(ev, "dev").alert.labels


def test_the_incident_reads_in_the_alarms_region_through_the_same_environments_reader_role():
    asked = []

    def per_env(env, incident, region=""):
        asked.append((env, incident, region))
        return {n: object() for n in aws_stack.NEEDED_CLIENTS}

    b = object.__new__(aws_stack.StackBackend)
    b._per_env, b._bound, b._lock = per_env, {}, __import__("threading").Lock()
    b._k8s_factory = b._db_factory = b._download = None
    alert = Alert(alert_id="x", name="n", severity=Severity.high, service="cdn", environment="dev", summary="",
                  started_at="2026-10-10T08:00:00Z", labels={"alarm": "warden-dev-cdn-5xx",
                                                              "alarm_region": CFG.aws_global_region})
    with contextlib.suppress(Exception):  # only which clients were asked for is under test
        b._incident(alert)
    assert asked == [("dev", "x", CFG.aws_global_region)]


def test_a_region_that_is_not_a_region_name_reads_nothing():
    from warden import aws_backend

    class _Sts:
        def assume_role(self, **kw):
            raise AssertionError("never assumed")

    class _Session:
        region_name = CFG.aws_region

        def client(self, name, config=None):
            return _Sts()

    clients = aws_backend._reader_clients(_Session(), None, "arn:aws:iam::0:role/warden-{env}-{role}")
    with pytest.raises(ToolError, match="not a Region name"):
        clients("dev", "inc-1", "us-east-1; rm -rf /")


def test_the_reader_role_may_read_the_global_regions_alarms_metrics_and_changes_only_there():
    doc = json.loads((ROOT / "iam" / "templates" / "platform-diagnose.json").read_text(encoding="utf-8"))
    st = {s["Sid"]: s for s in doc["Statement"]}
    assert st["GlobalServicesAlarmsOfThisEnvironment"]["Resource"] == \
        "arn:aws:cloudwatch:${global_region}:*:alarm:warden-${env}-*"
    assert st["GlobalServicesMetricsAndChanges"]["Condition"] == {
        "StringEquals": {"aws:RequestedRegion": "${global_region}"}}
