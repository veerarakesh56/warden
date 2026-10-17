"""fs-07, live, 2026-10-15: the approval request for `lambda_enable_esm` named its target by the event source
mapping's UUID - also the shape of many API keys - so the outbound gate withheld the whole message, and the channel
saw only "a WARDEN message ... was withheld". The mapping is now shown by its function; the key the bounds and the
mutex use is unchanged."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from warden import catalog
from warden.activities import Plan, RemediationActivities

MAPPING = str(uuid.UUID(hex="1e224ead6ea54c3a" + "a784605c649a52fd"))  # built from parts: no token literal
PARAMS = {"function": "warden-dev-order-processor", "mapping": MAPPING}


def test_a_mapping_is_shown_by_its_function_and_keyed_by_its_id():
    assert catalog.shown_target("dev", "lambda_enable_esm", PARAMS) == \
        "dev/lambda:event source mapping of warden-dev-order-processor"
    assert catalog.target_key("lambda_enable_esm", PARAMS) == f"lambda:{MAPPING}"  # the bounds still key on the id
    assert catalog.shown_target("dev", "k8s_restart", {"namespace": "shop", "deployment": "orders"}) == \
        "dev/k8s:shop/orders"


def test_the_approval_request_for_a_mapping_reaches_the_channel(world, sink):
    acts = RemediationActivities(audit=world["log"], policy=world["policy"], platform=world["platform"])
    plan = Plan(workflow_id="rem-dev-180000b1cc263177", incident_id="inc-7", entry="lambda_enable_esm", tier="T1",
                params=PARAMS, plan_hash="p" * 64, created_at=datetime.now(UTC),
                target=f"dev/{catalog.target_key('lambda_enable_esm', PARAMS)}", environment="dev")
    acts.announce(plan, "waiting")
    assert sink.texts and "withheld" not in sink.texts[-1]
    assert "event source mapping of warden-dev-order-processor" in sink.texts[-1] and MAPPING not in sink.texts[-1]
