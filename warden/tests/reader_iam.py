"""The platform reader role's managed policies. G10-C1: a second one, platform-diagnose, once the first neared IAM's
6,144-character limit - every test of what the role grants reads both."""

from __future__ import annotations

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
READER_POLICIES = ("platform-reader", "platform-diagnose")


def statements() -> list[dict]:
    return [st for name in READER_POLICIES
            for st in json.loads((ROOT / "iam" / "templates" / f"{name}.json").read_text(encoding="utf-8"))["Statement"]]


def granted() -> set[str]:
    return {a for st in statements() if st["Effect"] == "Allow"
            for a in ([st["Action"]] if isinstance(st["Action"], str) else st["Action"])}
