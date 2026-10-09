"""G6 (2026-10-09): in the cloud runtime the evidence reader read with the worker's own credentials - which may read no
watched environment - and the read zone ran the recorded fixtures instead of live AWS. Every read of an incident now runs
in its environment's reader role, `warden-<env>-platform-reader`, with the incident as SourceIdentity; an environment the
policy does not know is refused before any call; and the read zone reads live AWS."""

from __future__ import annotations

import pathlib
import threading

import pytest

from warden import aws_backend
from warden.tools import ToolError

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATE = "arn:aws:iam::" + "0" * 12 + ":role/warden-{env}-{role}"


class _Sts:
    def __init__(self):
        self.calls = []

    def assume_role(self, **kw):
        self.calls.append(kw)
        return {"Credentials": {"AccessKeyId": "A" * 16, "SecretAccessKey": "s" * 20, "SessionToken": "t" * 20}}


class _Session:
    region_name = "us-east-1"

    def __init__(self):
        self.sts = _Sts()

    def client(self, name, config=None):
        assert name == "sts"
        return self.sts


def test_each_incident_is_read_in_its_own_environments_reader_role_named_by_the_incident():
    session = _Session()
    clients = aws_backend._reader_clients(session, None, TEMPLATE)
    made = clients("dev", "inc-abc-1")
    assert set(made) == {"logs", "cloudwatch", "ecs"}
    (call,) = session.sts.calls
    assert call["RoleArn"] == TEMPLATE.format(env="dev", role="platform-reader")
    assert call["SourceIdentity"] == "inc-abc-1" and call["RoleSessionName"] == "inc-abc-1"
    assert clients("dev", "inc-abc-1") is made  # held, not assumed again
    clients("dev", "inc-abc-2")
    assert len(session.sts.calls) == 2  # another incident, its own session


def test_an_environment_the_policy_does_not_know_is_refused_before_any_call():
    session = _Session()
    clients = aws_backend._reader_clients(session, None, TEMPLATE)
    with pytest.raises(ToolError, match="not a configured environment"):
        clients("nowhere", "inc-abc-1")
    assert session.sts.calls == []


def test_a_refused_reader_role_is_a_failed_read_not_a_crash():
    session = _Session()

    def refuse(**_kw):
        raise RuntimeError("AccessDenied")

    session.sts.assume_role = refuse
    with pytest.raises(ToolError, match="reader role was refused"):
        aws_backend._reader_clients(session, None, TEMPLATE)("dev", "inc-abc-1")


def test_a_bound_incidents_clients_are_its_threads_own():
    b = aws_backend.AwsBackend(logs="base-logs", cloudwatch="base-cw", ecs="base-ecs")
    assert b._per_env is None  # injected clients: never re-bound
    b._per_env = lambda env, incident: {"logs": f"{env}-logs", "cloudwatch": "cw", "ecs": "ecs"}

    class _A:
        environment, alert_id = "dev", "inc-1"

    seen = {}

    def other():
        seen["logs"] = b._logs

    b._bind(_A())
    t = threading.Thread(target=other)
    t.start()
    t.join()
    assert b._logs == "dev-logs" and seen["logs"] == "base-logs"


def test_only_the_read_zone_reads_live_aws():
    compute = (ROOT / "terraform" / "modules" / "warden-runtime" / "compute.tf").read_text(encoding="utf-8")
    assert compute.count("WARDEN_BACKEND") == 1
    assert 'each.key == "read" ? { WARDEN_BACKEND = "aws" } : {}' in compute
    assert "WARDEN_AWS_ROLE_ARN_TEMPLATE = " in compute


def test_every_read_binds_the_incident_first(monkeypatch):
    """logs, metrics and deploys each run _bind before any client call."""

    class _Bound(Exception):
        pass

    b = aws_backend.AwsBackend(logs=object(), cloudwatch=object(), ecs=object())

    def bind(alert):
        raise _Bound(alert)

    monkeypatch.setattr(b, "_bind", bind)
    for name in ("logs", "metrics", "deploys"):
        with pytest.raises(_Bound):
            getattr(b, name)("the-alert")
