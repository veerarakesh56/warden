"""Live, 2026-10-15: the discussion's facts card named a past fix plan by its target key - an event source mapping's
UUID, masked as a key's shape - so the outbound gate withheld the whole card. Every history text now names the target
as a person reads it (catalog.shown_target); the key still matches plans to each other."""

from __future__ import annotations

import uuid

from warden import audit, history
from warden.gate import enforce

MAPPING = str(uuid.UUID(hex="1e224ead6ea54c3a" + "a784605c649a52fd"))  # built from parts: no token literal
PARAMS = {"function": "warden-dev-order-processor", "mapping": MAPPING}


def _log(tmp_path):
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    log.append("inc-1", "remediation.plan", {"workflow_id": "rem-dev-1", "run_id": "r1", "entry": "lambda_enable_esm",
                                             "params": PARAMS, "target": f"dev/lambda:{MAPPING}", "environment": "dev",
                                             "service": "warden-dev-order-processor", "plan_hash": "h1"})
    log.append("inc-1", "workflow.end", {"workflow_id": "rem-dev-1", "run_id": "r1", "status": "recovered",
                                         "approvers": ["bench"]})
    return log


def test_every_history_text_names_the_mapping_by_its_function(tmp_path):
    rows = history.plans(_log(tmp_path))
    assert rows[0]["target"] == f"dev/lambda:{MAPPING}"  # the key, for matching
    assert rows[0]["shown"] == "dev/lambda:event source mapping of warden-dev-order-processor"
    for text in (history.section(rows), history.prompt_facts(rows), history.again(rows)):
        assert MAPPING not in text
    said = history.section(rows)
    assert "event source mapping of warden-dev-order-processor" in said and enforce(said).verdict != "BLOCK"


def test_a_plan_row_without_params_still_shows_its_key(tmp_path):
    log = audit.AuditLog(tmp_path / "b.db", key=None)
    log.append("inc-2", "remediation.plan", {"workflow_id": "w", "run_id": "r", "entry": "k8s_restart",
                                             "target": "dev/k8s:shop/orders", "environment": "dev"})
    assert history.plans(log)[0]["shown"] == "dev/k8s:shop/orders"
