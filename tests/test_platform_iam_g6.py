"""G6: the AWS platform's two roles hold exactly the calls it makes. Every entry is run (live, apply, rollback,
health) against recording clients; each call is mapped to its IAM action by botocore's own model, and the set must
equal the reader's and the actor's policies - in both directions, so a grant can neither fall behind the code (an
AccessDenied mid-incident) nor run ahead of it (a standing grant nothing uses)."""

from __future__ import annotations

import json
import pathlib

import boto3

from test_aws_fixes_g9d import DLQ, Queues
from test_aws_platform_g6 import FN, NOW, WHO
from warden import catalog
from warden.platforms.aws import AwsPlatform

ROOT = pathlib.Path(__file__).resolve().parents[1]
PREFIX = {"lambda": "lambda", "events": "events", "dynamodb": "dynamodb", "ecs": "ecs",
          "application-autoscaling": "application-autoscaling", "cloudwatch": "cloudwatch", "cloudtrail": "cloudtrail", "rds": "rds",
          "sqs": "sqs", "athena": "athena", "apigateway": "apigateway", "sts": "sts"}
# Actions AWS authorizes for a call besides the call's own (Service Authorization Reference, read 2026-10-10): the
# session asks for them, the code never calls them.
IMPLICIT = {"sqs:StartMessageMoveTask": {"sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes",
                                         "sqs:SendMessage"}}


def _action(service: str, method: str) -> str:
    if service == "apigateway":  # API Gateway's IAM actions are the HTTP verbs of its control plane
        return "apigateway:" + ("GET" if method.startswith("get_") else "PATCH" if method.startswith("update_") else method)
    client = boto3.client(service, region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x")
    return f"{PREFIX[service]}:{client.meta.method_to_api_mapping[method]}"


class _Recording:
    def __init__(self, service, target, seen):
        self._service, self._target, self._seen = service, target, seen

    def __getattr__(self, name):
        if name == "meta":  # the client's own settings (its Region), not a call
            return self._target.meta
        self._seen.add(_action(self._service, name))
        return getattr(self._target, name)


def _exercise() -> tuple[set[str], set[str], set[str]]:
    reads, writes, granted = set(), set(), set()
    f = Queues()
    f.esm["State"], f.rule["State"] = "Disabled", "DISABLED"

    def actor(who, actions, resources, condition, also=()):
        granted.update(actions)
        for acts, _ in also:
            granted.update(acts)
        clients = f.actor(who, actions, resources, condition, also)
        return lambda service: _Recording(service, clients(service), writes)

    p = AwsPlatform(reader=lambda service: _Recording(service, f, reads), actor=actor, clock=lambda: NOW, sleep=lambda s: None)
    plans = {"lambda_move_alias": {"function": FN, "alias": "live", "to_version": "3"},
             "lambda_set_reserved_concurrency": {"function": FN, "concurrency": 5},
             "lambda_enable_esm": {"function": FN, "mapping": "u-1"}, "events_enable_rule": {"rule": f.rule["Name"]},
             "dynamodb_raise_capacity": {"table": "warden-dev-carts", "capacity": 10},
             "ecs_rollback_service": {"cluster": "c1", "service": "orders", "to_task_definition": "arn:td/orders:9"},
             "aurora_failover": {"cluster": "warden-dev-orders", "target_instance": "warden-dev-orders-b"},
             # G9-D
             "ecs_restart_service": {"cluster": "c1", "service": "orders"},
             "ecs_scale_service": {"cluster": "c1", "service": "orders", "replicas": 3},
             "sqs_redrive_dlq": {"queue": DLQ, "to_queue": "warden-dev-orders", "per_second": 10},
             "athena_stop_query": {"workgroup": "warden-dev-bi", "query": "q-1"},
             "apigw_raise_stage_throttle": {"api": "warden-dev-shop", "stage": "prod", "rate_limit": 200,
                                            "burst_limit": 100}}
    for entry, params in plans.items():
        snap = p.live(entry, params)["state"]
        p.apply(entry, params, snapshot=snap, who=WHO)
        p.healthy(params[catalog.CATALOG[entry].target_param], entry=entry,
                  params=params)
    p.changes(NOW, NOW, "dev")  # the change timeline's CloudTrail read (requirement R38)
    # The rollbacks, each from the state its apply left.
    f.alias["FunctionVersion"] = "3"
    p.rollback("lambda_move_alias", plans["lambda_move_alias"], {**p.live("lambda_move_alias", plans["lambda_move_alias"])["state"], "version": "9"}, who=WHO)
    f.esm["State"], f.rule["State"] = "Enabled", "ENABLED"
    p.rollback("lambda_enable_esm", plans["lambda_enable_esm"], p.live("lambda_enable_esm", plans["lambda_enable_esm"])["state"], who=WHO)
    p.rollback("events_enable_rule", plans["events_enable_rule"], p.live("events_enable_rule", plans["events_enable_rule"])["state"], who=WHO)
    # G9-D: the pauses (same writes, the other way round), and the inverses with a call of their own.
    f.esm["State"], f.rule["State"], f.rule["ScheduleExpression"] = "Enabled", "ENABLED", "rate(5 minutes)"
    for entry, params in (("lambda_disable_esm", {"function": FN, "mapping": "u-1"}),
                          ("events_disable_rule", {"rule": f.rule["Name"]})):
        p.apply(entry, params, snapshot=p.live(entry, params)["state"], who=WHO)
        p.healthy(params.get("mapping") or params["rule"], entry=entry, params=params)
    # The resolver's reads, before a mapping or a query is named: it lists them (resolver.request_for).
    p.live("lambda_disable_esm", {"function": FN})
    p.live("athena_stop_query", {"workgroup": "warden-dev-bi"})
    f.moves = [{"Status": "RUNNING", "TaskHandle": "h-1"}]
    redrive = plans["sqs_redrive_dlq"]
    p.rollback("sqs_redrive_dlq", redrive, p.live("sqs_redrive_dlq", redrive)["state"], who=WHO)
    return reads, writes, granted


def _actions(name: str) -> set[str]:
    doc = json.loads((ROOT / "iam" / "templates" / f"{name}.json").read_text(encoding="utf-8"))
    return {a for st in doc["Statement"] for a in ([st["Action"]] if isinstance(st["Action"], str) else st["Action"])}


def test_the_reader_role_holds_exactly_the_platforms_reads():
    """And the evidence reader's (aws_backend.py, held to this role by tests/test_aws_backend.py): the cloud runtime
    reads each incident in this role, and it held no logs read at all (2026-10-09)."""
    reads, _, _ = _exercise()
    from test_aws_stack import _api_calls, _iam_action
    from warden import aws_describe

    # The evidence readers' (aws_stack + aws_backend, G9-A2b) and the state table's (aws_describe, G9-A2c).
    evidence = {_iam_action(a, m) for a, m in _api_calls()} | {d.action for d in aws_describe.TABLE.values()}
    assert reads <= _actions("platform-reader")
    assert _actions("platform-reader") - reads <= evidence, sorted(_actions("platform-reader") - reads - evidence)


def test_the_actor_role_holds_exactly_the_platforms_writes_and_every_session_asks_only_for_them():
    _, writes, granted = _exercise()
    implicit = {a for w in writes for a in IMPLICIT.get(w, ())}
    assert writes | implicit == _actions("actor") == granted
    assert not any(a.split(":")[1].startswith(("Get", "List", "Describe")) or a == "apigateway:GET" for a in writes)


def test_the_roles_trust_only_the_runtime_zones_and_the_actor_needs_the_approval_tags():
    # Register S15: the actor only the act zone; the reader the zones that read (read, notify, and act, which re-reads).
    for name, zones in (("actor-trust", {"act"}), ("platform-reader-trust", {"read", "notify", "act"})):
        doc = json.loads((ROOT / "iam" / "templates" / f"{name}.json").read_text(encoding="utf-8"))
        principals = {p for st in doc["Statement"] for p in ([st["Principal"]["AWS"]] if isinstance(
            st["Principal"]["AWS"], str) else st["Principal"]["AWS"])}
        assert principals == {f"arn:aws:iam::${{account}}:role/warden-ops-{z}" for z in zones}
    actor = json.loads((ROOT / "iam" / "templates" / "actor-trust.json").read_text(encoding="utf-8"))["Statement"]
    tag = next(st for st in actor if st["Action"] == "sts:TagSession")
    assert tag["Condition"]["Null"] == {f"aws:RequestTag/{k}": "false" for k in ("approver", "incident", "plan")}
    assume = next(st for st in actor if "sts:AssumeRole" in st["Action"])
    assert assume["Condition"] == {"StringLike": {"sts:SourceIdentity": "inc-*"}}
    actor_policy = json.loads((ROOT / "iam" / "templates" / "actor.json").read_text(encoding="utf-8"))["Statement"]
    assert all(st["Condition"]["StringLike"]["aws:SourceIdentity"] == "inc-*" for st in actor_policy)
