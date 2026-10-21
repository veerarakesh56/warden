"""Every write WARDEN may make passes the idempotency or concurrency token its API
offers, so a retried apply cannot act twice or over a change made since the plan's read. Read from AWS's own API
models (botocore), not from memory: when this was written none of the actor role's writes took a ClientToken, and
Lambda's two (UpdateAlias, UpdateFunctionConfiguration) took RevisionId - which the platform passes. A write added later
whose API takes a token fails here until the platform passes it."""

from __future__ import annotations

import json
import pathlib
import re

import botocore.session

ROOT = pathlib.Path(__file__).resolve().parents[1]
# The IAM prefix as botocore names the service (where they differ). apigateway:PATCH is REST, not an operation;
# rds-db:connect is a database sign-in token (platforms/db.py), no API call at all.
SERVICE = {"elasticloadbalancing": "elbv2"}
NOT_OPERATIONS = {"apigateway:PATCH", "rds-db:connect"}
TOKENS = ("ClientToken", "ClientRequestToken", "clientToken", "IdempotencyToken", "RevisionId")


def _writes() -> list[str]:
    doc = json.loads((ROOT / "iam" / "templates" / "actor.json").read_text(encoding="utf-8"))
    actions = set()
    for st in doc["Statement"]:
        if st["Effect"] == "Allow":
            actions |= {st["Action"]} if isinstance(st["Action"], str) else set(st["Action"])
    return sorted(actions - NOT_OPERATIONS)


def _snake(op: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", op).lower()


def test_every_write_passes_the_token_its_api_offers():
    session = botocore.session.get_session()
    source = (ROOT / "src" / "warden" / "platforms" / "aws.py").read_text(encoding="utf-8")
    offered = {}
    for action in _writes():
        prefix, op = action.split(":", 1)
        shape = session.get_service_model(SERVICE.get(prefix, prefix)).operation_model(op).input_shape
        tokens = [m for m in (shape.members if shape else {}) if m in TOKENS]
        if tokens:
            offered[action] = tokens
    assert offered, "botocore found no token at all - the test itself has rotted"
    for action, tokens in offered.items():
        calls = [m.start() for m in re.finditer(rf"\.{_snake(action.split(':', 1)[1])}\(", source)]
        for at in calls:
            call = source[at:source.find(")", source.find("(", at)) + 200]
            assert any(f"{t}=" in call for t in tokens), f"{action} offers {tokens} and a call does not pass it"
