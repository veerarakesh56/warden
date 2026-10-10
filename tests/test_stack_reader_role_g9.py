"""G9-A2b (2026-10-10): in the cloud runtime the stack backend reads each incident in its environment's reader role,
`warden-<env>-platform-reader` - every reader, never the worker's own role - and the read zone runs it."""

from __future__ import annotations

import pathlib

import pytest

from warden.aws_stack import NEEDED_CLIENTS, StackBackend
from warden.models import Alert, Severity
from warden.tools import ToolError

ROOT = pathlib.Path(__file__).resolve().parents[1]
NEEDED = NEEDED_CLIENTS


class _Cw:
    def __init__(self, tag):
        self.tag = tag

    def describe_alarms(self, **kw):
        raise ToolError(f"read by {self.tag}")


def _alert(env="dev"):
    return Alert(alert_id="a1", name="n", service="s", environment=env, severity=Severity.high, summary="",
                 started_at="2026-10-10T00:00:00+00:00", labels={"alarm": "warden-dev-x"})


def _worker_backend():
    worker = {n: object() for n in NEEDED}
    worker["cloudwatch"] = _Cw("the worker")
    b = StackBackend(clients=worker)
    made = []

    def per_env(env, incident):
        if env != "dev":
            raise ToolError(f"{env!r} is not a configured environment: nothing was read")
        made.append((env, incident))
        clients = {n: object() for n in NEEDED}
        clients["cloudwatch"] = _Cw(f"{env}'s reader role")
        return clients

    b._per_env = per_env
    return b, made


def test_every_read_of_an_incident_runs_in_its_environments_reader_role():
    b, made = _worker_backend()
    lines = b.logs(_alert())
    assert made == [("dev", "a1")]
    assert any("read by dev's reader role" in ln for ln in lines) and not any("the worker" in ln for ln in lines)


def test_an_unknown_environment_is_a_failed_read_never_a_read_as_the_worker():
    b, made = _worker_backend()
    with pytest.raises(ToolError, match="not a configured environment"):
        b.logs(_alert("nowhere"))
    assert made == []


def test_injected_clients_are_never_rebound_and_the_read_zone_runs_the_stack_backend():
    b = StackBackend(clients={n: object() for n in NEEDED})
    assert b._per_env is None and b._incident(_alert()) is b
    compute = (ROOT / "terraform" / "modules" / "warden-runtime" / "compute.tf").read_text(encoding="utf-8")
    assert 'each.key == "read" ? { WARDEN_BACKEND = "stack" } : {}' in compute


def test_a_service_past_the_first_eighteen_gets_its_client_through_the_real_reader_role_path(monkeypatch):
    """Independent review 2026-10-10, H1: the per-incident clients were copied into a plain dict, so every state-table
    service past the eighteen made up front read "no client" in the cloud. Through the real path, end to end."""
    import boto3

    from warden import aws_backend, identity

    made = []

    class _Session:
        region_name = "r1"

        def __init__(self, **kw):
            pass

        def client(self, name, config=None):
            made.append(name)
            return type(name, (), {"meta": type("M", (), {"region_name": "r1"})()})()

    monkeypatch.setattr(boto3.session, "Session", _Session)
    monkeypatch.setattr(identity, "reader_session", lambda sts, **kw: {})
    template = "arn:aws:iam::" + "0" * 12 + ":role/warden-{env}-{role}"
    clients = aws_backend._reader_clients(_Session(), None, template, NEEDED)("dev", "a1")
    b = StackBackend(clients=clients)
    assert b._clients is clients  # kept as given, still making clients on first use
    assert "kinesis" not in made
    b._clients["kinesis"]
    assert made.count("kinesis") == 1
