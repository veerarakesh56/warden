"""WARDEN's own pages, seen from the approval page: which are open, and a person's acknowledgement of them.

The pager (terraform/modules/warden-runtime/pager/pager.py, a function of its own with no WARDEN code in it) writes
each page as `pages/<key>.json` in the runtime's anchors bucket and says it again every 15 minutes until an
`acks/<key>.json` names the same opening time. Only this side writes an acknowledgement, and only after an
approver's passkey signed exactly the pages shown (approval_page `/p`); the acknowledgement is on WARDEN's record
first (`page.acknowledged`), then in the bucket. tests/test_paging.py holds this layout to the pager's.

The kill switch going on is one of the alarms that page: `KILLSWITCH_METRIC`, counted on every trip (bounds.trip).
So are the model's three conditions (item 7c, `model_condition`): the provider unavailable, the daily cap reached, an
incident's budget spent - each counted once per UTC day, whatever the number of calls it stops.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from datetime import UTC, datetime
from typing import Any

KILLSWITCH_METRIC = "KillSwitchTripped"
_PAGE_KEY = re.compile(r"[A-Za-z0-9._-]{1,200}")  # the pager's own key shape (pager._KEY): the only ones it writes
ACK = "page.acknowledged"
_LOG = logging.getLogger("warden.paging")
WORKFLOW = "page-ack"  # what an acknowledgement's passkey signs for: no plan is ever this


def killswitch_tripped() -> None:
    """One count of the kill switch going on, under the runtime's own namespace; its alarm pages a person and the
    pager repeats it until acknowledged. Best effort: a trip is on the record whether or not the count gets out -
    a WARDEN that cannot reach CloudWatch at all is the heartbeat alarm's to page. No namespace: nothing (a workstation,
    a test)."""
    _count(KILLSWITCH_METRIC)


# The model's paging conditions (item 7c) and the metric each is counted on; paging.tf has one alarm per metric, whose
# fixed description is all the page says - never the error's text, a value or the evidence.
PROVIDER_UNAVAILABLE, DAILY_CAP, BUDGET = "provider_unavailable", "daily_cap", "budget"
MODEL_METRICS = {PROVIDER_UNAVAILABLE: "ModelProviderUnavailable", DAILY_CAP: "ModelDailyCapReached",
                 BUDGET: "ModelBudgetReached"}
MODEL_PAGED = "page.model_condition"


def model_condition(log: Any, condition: str, *, now: datetime | None = None) -> bool:
    """Count `condition` for its page - once per UTC day: True when this call counted it, False when it had already
    been counted today (or is not a condition, or the count could not be sent). The metric first, then WARDEN's
    record under "pages": a count that could not be sent is not recorded, so the next call
    tries again - a missed page is worse than a second one. Every worker reads the day's record; two racing on the
    first can each count it and still page once - the alarm acts only on its change into ALARM, and the pager opens
    no second page for an alarm whose page is open. The row holds the condition and the day only."""
    metric = MODEL_METRICS.get(condition)
    if metric is None:
        return False
    now = now or datetime.now(UTC)
    day = now.astimezone(UTC).date().isoformat()
    midnight = datetime.fromisoformat(day).replace(tzinfo=UTC)
    try:
        if any(e["body"].get("condition") == condition and e["body"].get("day") == day
               for e in log.entries("pages", kinds=(MODEL_PAGED,), since=midnight)):
            return False
        if not _count(metric):
            return False
        log.append("pages", MODEL_PAGED, {"condition": condition, "day": day})
    except Exception:  # noqa: BLE001 - a page never stops the incident; it still goes to a person
        _LOG.warning("the model's %s page could not be recorded", condition)
        return False
    return True


def _count(metric: str) -> bool:
    """One count of `metric` under the runtime's own namespace (WARDEN_HEARTBEAT_NAMESPACE); none on a desktop or in a
    test. True when it was sent, or there is nowhere to send it; False when sending failed. Best effort."""
    namespace = os.environ.get("WARDEN_HEARTBEAT_NAMESPACE", "").strip()
    if not namespace:
        return True
    try:
        import boto3

        from .environments import region

        boto3.client("cloudwatch", region_name=region()).put_metric_data(
            Namespace=namespace, MetricData=[{"MetricName": metric, "Value": 1, "Unit": "Count"}])
    except Exception:  # noqa: BLE001 - the caller decides what a count not sent means
        _LOG.warning("the page count %s could not be sent", metric)
        return False
    return True


def signed_for(pages: list[dict[str, Any]]) -> str:
    """What an acknowledgement signs: the pages shown, each by key and opening time. A page opened after they were
    shown changes it, so an acknowledgement never covers a page its approver did not see."""
    shown = ",".join(sorted(f"{p['key']}@{p['opened_at']}" for p in pages))
    return "pages-" + hashlib.sha256(shown.encode()).hexdigest()


class MemoryPages:
    """The bucket's two prefixes in memory: a test, or a runtime with no bucket for them."""

    def __init__(self) -> None:
        self.objects: dict[str, dict[str, Any]] = {}

    def get(self, key: str) -> dict[str, Any] | None:
        return self.objects.get(key)

    def put(self, key: str, body: dict[str, Any]) -> None:
        self.objects[key] = body

    def list(self, prefix: str) -> list[str]:
        return sorted(k for k in self.objects if k.startswith(prefix))


class S3Pages:
    """The runtime's anchors bucket (WARDEN_PAGES_BUCKET), its `pages/` and `acks/`: the approval function reads
    `pages/` and writes `acks/`. Under Object Lock, as the audit's anchors are: no page or acknowledgement is lost or
    rewritten unseen, every version kept for the anchors' retention."""

    def __init__(self, bucket: str, s3: Any = None) -> None:
        if s3 is None:
            import boto3

            from .environments import region

            s3 = boto3.client("s3", region_name=region())
        self.bucket, self.s3 = bucket, s3

    def get(self, key: str) -> dict[str, Any] | None:
        try:
            return json.loads(self.s3.get_object(Bucket=self.bucket, Key=key)["Body"].read())
        except self.s3.exceptions.NoSuchKey:
            return None

    def put(self, key: str, body: dict[str, Any]) -> None:
        # The anchors bucket is under Object Lock, which refuses a write without a checksum.
        self.s3.put_object(Bucket=self.bucket, Key=key, Body=json.dumps(body).encode(), ContentType="application/json",
                           ChecksumAlgorithm="SHA256")

    def list(self, prefix: str) -> list[str]:
        out: list[str] = []
        for got in self.s3.get_paginator("list_objects_v2").paginate(Bucket=self.bucket, Prefix=prefix):
            out += [o["Key"] for o in got.get("Contents", [])]
        return sorted(out)


def from_environment() -> S3Pages | None:
    bucket = os.environ.get("WARDEN_PAGES_BUCKET", "").strip()
    return S3Pages(bucket) if bucket else None


def open_pages(store: Any) -> list[dict[str, Any]]:
    """Every page the pager is still repeating: written, and not acknowledged at its opening time. One object that
    cannot be read, or is not a page, is skipped and never hides the others; an acknowledgement
    that cannot be read acknowledges nothing."""
    out = []
    for name in store.list("pages/"):
        if not name.endswith(".json"):
            continue
        try:
            page = store.get(name)
        except Exception:  # noqa: BLE001 - one unreadable page must not hide the others
            _LOG.warning("a page could not be read: skipped")
            continue
        if not (isinstance(page, dict) and isinstance(page.get("key"), str) and _PAGE_KEY.fullmatch(page["key"])
                and isinstance(page.get("opened_at"), str)):
            continue
        try:
            ack = store.get(f"acks/{page['key']}.json")
        except Exception:  # noqa: BLE001 - an acknowledgement that cannot be read leaves the page open
            ack = None
        if not (isinstance(ack, dict) and ack.get("opened_at") == page["opened_at"]):
            out.append(page)
    return out


def acknowledge(store: Any, log: Any, pages: list[dict[str, Any]], *, approver: str, nonce: str, credential_id: str,
                at: datetime) -> None:
    """On the record, signed, then in the bucket: the pager stops repeating each page at its next tick."""
    log.append("pages", ACK, {"approver": approver, "nonce": nonce, "credential_id": credential_id, "method": "passkey",
                              "pages": [{"key": p["key"], "opened_at": p["opened_at"]} for p in pages]})
    log.checkpoint()
    for p in pages:
        store.put(f"acks/{p['key']}.json", {"key": p["key"], "opened_at": p["opened_at"], "at": at.isoformat()})
