"""What an alert from an MCP caller may make WARDEN read (audit A-B-H4).

An alert's labels steer the readers: `namespace`, `log_group`, `ecs_cluster`, `lambda`, ... name what is read. From
alert intake they come from the monitoring system; from an MCP caller they are whatever the caller wrote, so a
caller could point WARDEN's read role at any log group or namespace it can reach. For a caller's alert, a steering
label is followed only when the operator's allowlist names that value for that service:

    # WARDEN_READ_SCOPES=/etc/warden/read-scopes.yaml
    orders:
      namespace: [shop]
      log_group: [/ecs/warden-dev-orders]

Any other steering label is dropped, and the readers fall back to what the service name alone gives. Labels that
steer nothing (severity, team, ...) pass unchanged. No file: every steering label from a caller is dropped.
"""

from __future__ import annotations

import os
import pathlib

import yaml

from .models import Alert
from .resources import LABEL_KEYS

# Every label key a reader follows (aws_backend, aws_stack, k8s_backend).
STEERING = frozenset({
    "alb_target_group", "apigw", "aurora_cluster", "cluster", "deployment", "dynamodb_table", "ecs_cluster",
    "ecs_service", "eks_cluster", "elasticache", "eventbridge_rule", "lambda", "log_group", "log_stream_prefix",
    "namespace", "region", "secret", "selector", "sns_topic", "sqs",
    # Every resource label the alarm mapping can give, and the alarm itself (G9; independent review 2026-10-10, F1:
    # a caller's `kms_key=` label survived the restriction and was re-read as a Lambda).
    "alarm", *LABEL_KEYS})


def load(path: str | None = None) -> dict[str, dict[str, set[str]]]:
    """{service: {label: allowed values}} from WARDEN_READ_SCOPES; {} when it is not set. A file that is set but
    unreadable or malformed raises: an operator who wrote an allowlist must not silently get none."""
    where = path or os.environ.get("WARDEN_READ_SCOPES")
    if not where:
        return {}
    raw = yaml.safe_load(pathlib.Path(where).read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict) or not all(isinstance(v, dict) for v in raw.values()):
        raise ValueError(f"{where}: expected service -> label -> list of values")
    return {str(svc): {str(k): {str(x) for x in (v if isinstance(v, list) else [v])} for k, v in labels.items()}
            for svc, labels in raw.items()}


def restrict(alert: Alert, scopes: dict[str, dict[str, set[str]]]) -> tuple[Alert, list[str]]:
    """The alert with only the steering labels the allowlist names for its service - every value of a list label
    must be named - and the keys dropped."""
    allowed = scopes.get(alert.service, {})
    kept: dict[str, str] = {}
    dropped: list[str] = []
    for key, value in alert.labels.items():
        if key.lower() not in STEERING:
            kept[key] = value
            continue
        values = [v.strip() for v in str(value).split(",") if v.strip()]
        if values and all(v in allowed.get(key, set()) for v in values):
            kept[key] = value
        else:
            dropped.append(key)
    return alert.model_copy(update={"labels": kept}), sorted(dropped)
