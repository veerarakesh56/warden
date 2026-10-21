"""Wave 4 report side: the markdown shows the code-level finding and what each stack reader read - and
nothing leaks or arrives as a placeholder. (The runbook and the fix commands it aimed at the stack's
components were removed on 2026-10-16; warden/tests/test_no_commands.py holds that no report carries a command.)
"""

from __future__ import annotations

import itertools

import pytest

from test_playbook_stack import _HOLE, ACCT, FAULTS, REGION, alert, ctx
from warden.models import ActionKind, RemediationProposal, RootCause, Verdict, VerdictStatus
from warden.reporting import build_report


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("AWS_REGION", REGION)
    monkeypatch.delenv("WARDEN_BACKEND", raising=False)


def _report(fid: str | None, action=ActionKind.rollback_deploy, context=None):
    return build_report(
        alert(), context=context or (FAULTS[fid][1] if fid else ctx()), backend="stack", show_identifiers=False,
        root_cause=RootCause(hypothesis="h", confidence=0.8),
        proposal=RemediationProposal(action=action, target="t", reasoning="r", expected_effect="e",
                                     blast_radius="single_service", reversible=True),
        verdict=Verdict(status=VerdictStatus.approved_for_human, reasons=["r"], policy_ids=[]))


@pytest.mark.parametrize("fid,action", list(itertools.product(sorted(FAULTS), list(ActionKind))))
def test_no_stack_report_has_a_placeholder_or_an_account_id(fid, action):
    r = _report(fid, action)
    assert not _HOLE.findall(r.markdown), (fid, action, _HOLE.findall(r.markdown))
    assert ACCT not in r.markdown


def test_the_report_shows_the_code_level_finding():
    md = _report("fs-01").markdown
    section = md[md.index("## Code-level finding"):]
    assert "**`app.py:42`** in `handler`: `KeyError: 'sku'`" in section
    assert "```python\n40 | def handler(event, context):" in section
    assert "42 >|     sku = body['sku']" in section
    assert "start at `app.py:42` in `handler` (warden-dev-checkout)" in section
    assert _report("fs-01").data["code"][0]["line"] == 42


def test_what_warden_read_lists_each_component_and_each_failed_reader():
    c = ctx(tool_errors=["sqs/warden-dev-orders: AccessDenied on GetQueueAttributes"])
    md = _report(None, ActionKind.escalate_to_human, context=c).markdown
    section = md[md.index("## What WARDEN read"):md.index("## What WARDEN thinks")]
    assert "alert time ± 15 min" in section
    assert "alert time ± 10 min" in section
    for reader in ("lambda", "dynamodb", "elasticache", "aurora", "alb", "apigw", "ecs", "k8s", "secret", "sns",
                   "eventbridge"):
        assert f"- {reader} `" in section, reader
        assert "read." in section, reader
    assert "- sqs `warden-dev-orders,warden-dev-notifications`" in section
    assert "**FAILED**: `sqs/warden-dev-orders: AccessDenied on GetQueueAttributes`" in section
    assert "Not read: the data inside the Redis cache itself" in section  # this alert names a cache and containers
    assert "the program code inside the container images" in section
    assert "VPC-only" not in section
    # An alert that names neither says nothing of them (owner, 2026-10-14: a schedule's alarm listed Redis).
    from warden.models import Alert
    from warden.reporting import _stack_sources

    only = Alert(alert_id="x", name="n", severity="high", service="s", environment="dev", summary="s",
                 started_at="2026-10-14T07:14:13Z", labels={"eventbridge_rule": "warden-dev-tick"})
    assert not any(line.startswith("Not read") for line in _stack_sources(only, c))
