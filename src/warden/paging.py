"""WARDEN's own pages, seen from the approval page: which are open, and a person's acknowledgement of them.

The pager (terraform/modules/warden-runtime/pager/pager.py, a function of its own with no WARDEN code in it) writes
each page as `pages/<key>.json` in the runtime's anchors bucket and says it again every 15 minutes until an
`acks/<key>.json` names the same opening time. Only this side writes an acknowledgement, and only after an
approver's passkey signed exactly the pages shown (approval_page `/p`); the acknowledgement is on WARDEN's record
first (`page.acknowledged`), then in the bucket. tests/test_paging.py holds this layout to the pager's.

The kill switch going on is one of the alarms that page: `KILLSWITCH_METRIC`, counted on every trip (bounds.trip).
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from typing import Any

KILLSWITCH_METRIC = "KillSwitchTripped"
ACK = "page.acknowledged"
WORKFLOW = "page-ack"  # what an acknowledgement's passkey signs for: no plan is ever this


def killswitch_tripped() -> None:
    """One count of the kill switch going on, under the runtime's own namespace; its alarm pages a person and the
    pager repeats it until acknowledged. Best effort: a trip is on the record whether or not the count gets out -
    a WARDEN that cannot reach CloudWatch at all is the heartbeat alarm's to page. No namespace: nothing (a laptop,
    a test)."""
    namespace = os.environ.get("WARDEN_HEARTBEAT_NAMESPACE", "").strip()
    if not namespace:
        return
    try:
        import boto3

        from .environments import region

        boto3.client("cloudwatch", region_name=region()).put_metric_data(
            Namespace=namespace, MetricData=[{"MetricName": KILLSWITCH_METRIC, "Value": 1, "Unit": "Count"}])
    except Exception:  # noqa: BLE001 - the trip itself stands; the record holds it
        import logging

        logging.getLogger("warden.paging").warning("the kill switch's page count could not be sent")


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
    """Every page the pager is still repeating: written, and not acknowledged at its opening time."""
    out = []
    for name in store.list("pages/"):
        page = store.get(name)
        if not page or not name.endswith(".json"):
            continue
        ack = store.get(f"acks/{page['key']}.json")
        if not (ack and ack.get("opened_at") == page.get("opened_at")):
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
