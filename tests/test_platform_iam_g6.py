"""G6: the AWS platform's two roles hold exactly the calls it makes. Every entry is run (live, apply, rollback,
health) against recording clients; each call is mapped to its IAM action by botocore's own model, and the set must
equal the reader's and the actor's policies - in both directions, so a grant can neither fall behind the code (an
AccessDenied mid-incident) nor run ahead of it (a standing grant nothing uses)."""

from __future__ import annotations

import json
import pathlib

import boto3

from test_aws_platform_g6 import FN, NOW, WHO, Fake
from warden.platforms.aws import AwsPlatform

ROOT = pathlib.Path(__file__).resolve().parents[1]
PREFIX = {"lambda": "lambda", "events": "events", "dynamodb": "dynamodb", "ecs": "ecs",
          "application-autoscaling": "application-autoscaling", "cloudwatch": "cloudwatch"}


def _action(service: str, method: str) -> str:
    client = boto3.client(service, region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x")
    return f"{PREFIX[service]}:{client.meta.method_to_api_mapping[method]}"


class _Recording:
    def __init__(self, service, target, seen):
        self._service, self._target, self._seen = service, target, seen

    def __getattr__(self, name):
        self._seen.add(_action(self._service, name))
        return getattr(self._target, name)


def _exercise() -> tuple[set[str], set[str], set[str]]:
    reads, writes, granted = set(), set(), set()
    f = Fake()

    def actor(who, actions, resources, condition):
        granted.update(actions)
        clients = f.actor(who, actions, resources, condition)
        return lambda service: _Recording(service, clients(service), writes)

    p = AwsPlatform(reader=lambda service: _Recording(service, f, reads), actor=actor, clock=lambda: NOW)
    plans = {"lambda_move_alias": {"function": FN, "alias": "live", "to_version": "3"},
             "lambda_set_reserved_concurrency": {"function": FN, "concurrency": 5},
             "lambda_enable_esm": {"mapping": "u-1"}, "events_enable_rule": {"rule": f.rule["Name"]},
             "dynamodb_raise_capacity": {"table": "warden-dev-carts", "capacity": 10},
             "ecs_rollback_service": {"cluster": "c1", "service": "orders", "to_task_definition": "arn:td/orders:9"}}
    for entry, params in plans.items():
        snap = p.live(entry, params)["state"]
        p.apply(entry, params, snapshot=snap, who=WHO)
        p.healthy(next(iter(params.values())) if entry != "ecs_rollback_service" else "orders", entry=entry,
                  params=params)
    # The rollbacks, each from the state its apply left.
    f.alias["FunctionVersion"] = "3"
    p.rollback("lambda_move_alias", plans["lambda_move_alias"], {**p.live("lambda_move_alias", plans["lambda_move_alias"])["state"], "version": "9"}, who=WHO)
    f.esm["State"], f.rule["State"] = "Enabled", "ENABLED"
    p.rollback("lambda_enable_esm", plans["lambda_enable_esm"], p.live("lambda_enable_esm", plans["lambda_enable_esm"])["state"], who=WHO)
    p.rollback("events_enable_rule", plans["events_enable_rule"], p.live("events_enable_rule", plans["events_enable_rule"])["state"], who=WHO)
    return reads, writes, granted


def _actions(name: str) -> set[str]:
    doc = json.loads((ROOT / "iam" / "templates" / f"{name}.json").read_text(encoding="utf-8"))
    return {a for st in doc["Statement"] for a in ([st["Action"]] if isinstance(st["Action"], str) else st["Action"])}


def test_the_reader_role_holds_exactly_the_platforms_reads():
    reads, _, _ = _exercise()
    assert reads == _actions("platform-reader")


def test_the_actor_role_holds_exactly_the_platforms_writes_and_every_session_asks_only_for_them():
    _, writes, granted = _exercise()
    assert writes == _actions("actor") == granted
    assert not any(a.split(":")[1].startswith(("Get", "List", "Describe")) for a in writes)


def test_the_roles_trust_only_the_runtime_worker_and_the_actor_needs_the_approval_tags():
    for name in ("actor-trust", "platform-reader-trust"):
        doc = json.loads((ROOT / "iam" / "templates" / f"{name}.json").read_text(encoding="utf-8"))
        assert {st["Principal"]["AWS"] for st in doc["Statement"]} == {"arn:aws:iam::${account}:role/warden-ops-worker"}
    actor = json.loads((ROOT / "iam" / "templates" / "actor-trust.json").read_text(encoding="utf-8"))["Statement"]
    tag = next(st for st in actor if st["Action"] == "sts:TagSession")
    assert tag["Condition"]["Null"] == {f"aws:RequestTag/{k}": "false" for k in ("approver", "incident", "plan")}
    assume = next(st for st in actor if "sts:AssumeRole" in st["Action"])
    assert assume["Condition"] == {"StringLike": {"sts:SourceIdentity": "inc-*"}}
    actor_policy = json.loads((ROOT / "iam" / "templates" / "actor.json").read_text(encoding="utf-8"))["Statement"]
    assert all(st["Condition"]["StringLike"]["aws:SourceIdentity"] == "inc-*" for st in actor_policy)
