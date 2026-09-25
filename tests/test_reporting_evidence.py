"""The report carries the evidence, the affected identifiers and a runbook - and leaks nothing.

⛔ The leak tests come first because the first version of this feature leaked. It restored the real
values into the model's text and redacted again; the model had written `tenant_<TENANT_1>`, which
became `tenant_initech-4`, which no redaction pattern recognises - so a tenant id went out with
identifiers switched OFF. The tests below drive the whole pipeline on bundled incidents, with the
model's text containing exactly that kind of glued-on placeholder.
"""

from __future__ import annotations

import json
import re

import pytest

from warden.models import (
    ActionKind,
    Alert,
    ContextBundle,
    RemediationProposal,
    RootCause,
    RunReport,
    Severity,
    Verdict,
    VerdictStatus,
)
from warden.redaction import redact, redact_many
from warden.reporting import REVEALABLE, build_report

TENANT = "initech-4"
EMAIL = "priya.nair@corp.io"
HOST = "10.0.7.22"
SECRETS = {
    "password": "hunter2-Sup3r-s3cret",
    "apikey": "sk-ant-api03-AAAAAAAAAAAAAAAAAAAA",
    "account": "123456789012",
    "uuid": "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
}


def _context() -> ContextBundle:
    return ContextBundle(
        logs=[
            f"2026-08-26T04:10:01Z payments ERROR connection pool exhausted (100/100) host={HOST}",
            f"2026-08-26T04:10:20Z payments ERROR could not acquire connection tenant_id={TENANT} user={EMAIL}",
            f"2026-08-26T04:10:21Z payments WARN retry with password={SECRETS['password']}",
            f"2026-08-26T04:10:22Z payments ERROR auth failed key={SECRETS['apikey']} trace={SECRETS['uuid']}",
            f"2026-08-26T04:10:23Z payments ERROR arn:aws:iam::{SECRETS['account']}:role/app denied",
            "2026-08-26T04:10:30Z payments WARN pid 4242 idle in transaction for 611s",
        ],
        metrics={"idle_in_transaction": 25.0, "connection_pool_used": 100.0},
        recent_deploys=[{"service": "payments", "sha": "9f2c1ab", "at": "2026-08-26T03:58:00Z", "by": "deploy-bot"}],
        tool_errors=["logs: payments-7d/app: (403)"],
    )


def _pipeline_map(ctx: ContextBundle) -> dict[str, str]:
    """What graph.py builds: one map over logs, then deploys."""
    _, mapping = redact_many(ctx.logs)
    for d in ctx.recent_deploys:
        for v in d.values():
            mapping = redact(str(v), mapping=mapping).mapping
    return mapping


def _placeholder(mapping: dict[str, str], value: str) -> str:
    return next(p for p, v in mapping.items() if v == value)


def _report(show: bool, action=ActionKind.terminate_connections, **alert_kw):
    ctx = _context()
    mapping = _pipeline_map(ctx)
    t = _placeholder(mapping, TENANT)
    # The model writes placeholders glued onto other text, exactly as it did on a real run.
    rc = RootCause(hypothesis=f"stuck transactions for tenant_{t} exhaust the pool",
                   confidence=0.6, evidence=[f"errors for tenant_{t} and {_placeholder(mapping, EMAIL)}"],
                   ruled_out=["replica lag"])
    prop = RemediationProposal(action=action, target=f"payments-db ({t})", reasoning="r",
                               expected_effect="pool frees", blast_radius="single_service", reversible=True)
    alert = Alert(alert_id="inc-x", name="DBConnectionsStuck", severity=Severity.high, service="payments",
                  environment="prod", summary="pool exhausted by idle-in-transaction connections",
                  started_at="2026-08-26T04:10:00Z", **alert_kw)
    verdict = Verdict(status=VerdictStatus.approved_for_human, reasons=["ok"], policy_ids=[])
    return build_report(alert, root_cause=rc, proposal=prop, verdict=verdict, context=ctx,
                        redaction_map=mapping, show_identifiers=show), mapping


def _everything(rep) -> str:
    return rep.markdown + "\n" + json.dumps(rep.data)


# --------------------------------------------------------------------------- leaks


def test_with_identifiers_off_no_masked_value_appears_in_any_form():
    """⛔ THE REGRESSION: `tenant_initech-4` went out unmasked with identifiers switched off."""
    rep, mapping = _report(show=False)
    out = _everything(rep)
    leaked = sorted({v for v in mapping.values() if v in out})
    assert not leaked, f"masked values leaked into the report: {leaked}"
    assert TENANT not in out and EMAIL not in out and HOST not in out


def test_a_raw_value_in_a_form_no_pattern_recognises_is_still_masked():
    """⛔ The worst case: the model's text carries the REAL value glued to other text, where no
    redaction pattern can see it (`tenant_initech-4`), and nothing earlier in the report has taught
    the redactor that value. Only knowing the pipeline's own map catches it - in the JSON data that
    webhooks send as well as in the Markdown."""
    ctx = _context()
    mapping = _pipeline_map(ctx)
    rc = RootCause(hypothesis=f"stuck transactions for tenant_{TENANT}", confidence=0.6,
                   evidence=[f"errors for tenant_{TENANT}"])
    alert = Alert(alert_id="inc-x", name="n", severity=Severity.high, service="payments",
                  environment="prod", summary="pool exhausted", started_at="2026-08-26T04:10:00Z")
    rep = build_report(alert, root_cause=rc, context=ctx, redaction_map=mapping, show_identifiers=False)
    assert TENANT not in rep.markdown
    assert TENANT not in json.dumps(rep.data), "the JSON a webhook sends leaked the tenant"


def test_with_identifiers_on_secrets_stay_masked():
    rep, _ = _report(show=True)
    out = _everything(rep)
    for name, secret in SECRETS.items():
        assert secret not in out, f"{name} was revealed: identifiers must never unmask secrets"


def test_with_identifiers_on_the_operator_sees_who_is_affected():
    """The point of the switch: a tenant id or an email is what you search the logs for."""
    rep, _ = _report(show=True)
    assert f"tenant_{TENANT}" in rep.markdown, "the model's own text should read naturally"
    assert EMAIL in rep.markdown and HOST in rep.markdown


def test_only_identifier_labels_are_revealable():
    """A change to REVEALABLE is a change to what leaves the building - pinned so it is deliberate."""
    assert frozenset({"EMAIL", "TENANT", "IPV4", "IPV6"}) == REVEALABLE


# A value that exists ONLY in the map - the raw context legitimately holds unredacted evidence, so a
# secret that is also in the logs would prove nothing about the map itself.
ONLY_IN_THE_MAP = "map-only-secret-7f3a9c"


def test_the_redaction_map_never_serialises():
    """⛔ It holds every secret the redactor caught; a --json report file must not carry it."""
    ctx = _context()
    run = RunReport(alert=Alert(alert_id="a", name="n", severity=Severity.low, service="s",
                                environment="prod", summary="x", started_at="2026-08-26T04:10:00Z"),
                    redaction_map_size=1, redaction_map={"<SECRET_9>": ONLY_IN_THE_MAP}, context=ctx)
    assert run.redaction_map, "the map must still be there for the report builder"
    assert ONLY_IN_THE_MAP not in run.model_dump_json()
    assert "redaction_map" not in run.model_dump()
    assert ONLY_IN_THE_MAP not in repr(run)


# --------------------------------------------------------------------------- what the reader gets


def test_the_report_carries_the_evidence_not_just_the_conclusion():
    md = _report(show=False)[0].markdown
    assert "## Metrics at the time" in md and "`idle_in_transaction` = **25**" in md
    assert "**⚠ What WARDEN could NOT read**" in md and "(403)" in md
    assert "**Based on:**" in md and "**Ruled out:**" in md
    assert "## Key log lines" in md and "connection pool exhausted" in md


def test_the_timeline_puts_the_deploy_before_the_first_error():
    tl = _report(show=False)[0].data["evidence"]["timeline"]
    labels = [what for _, what in tl]
    assert labels.index(next(w for w in labels if "9f2c1ab" in w)) < labels.index("first error in the evidence")


def test_pids_named_in_the_evidence_become_the_exact_fix():
    """A generic "kill the idle sessions" asks the reader to find them; the PID is in the evidence."""
    rep = _report(show=False)[0]
    assert rep.data["evidence"]["affected"]["pid"] == [["4242", 1]]
    # Guarded: terminates the named pid only if it is STILL idle in a transaction when run - a pid
    # from the evidence may have been reused by a new session since.
    assert "WHERE pid IN (4242) AND state = 'idle in transaction'" in rep.markdown


def test_a_kubernetes_rollback_names_the_real_namespace_and_deployment():
    rep = _report(show=False, action=ActionKind.rollback_deploy,
                  labels={"namespace": "shop", "deployment": "checkout-api"})[0]
    assert "kubectl -n shop rollout undo deploy/checkout-api" in rep.markdown
    assert "rollout status deploy/checkout-api" in rep.markdown


@pytest.mark.parametrize("action", list(ActionKind))
def test_every_action_renders_without_error(action):
    rep = _report(show=False, action=action)[0]
    assert rep.markdown.startswith("# WARDEN incident report")


def test_bare_placeholders_the_model_wrote_are_revealed_but_never_secrets():
    """The model wrote `(EMAIL_1, EMAIL_2)` without brackets on a real run; the operator who asked
    to see identifiers got placeholders anyway."""
    from warden.reporting import reveal_identifiers

    mapping = {"<EMAIL_1>": "a@corp.io", "<EMAIL_12>": "l@corp.io", "<SECRET_1>": "hunter2"}
    text = "users EMAIL_1, EMAIL_12 and <EMAIL_1>; creds SECRET_1 / <SECRET_1>"
    out = reveal_identifiers(text, mapping)
    assert out == "users a@corp.io, l@corp.io and a@corp.io; creds SECRET_1 / <SECRET_1>"


def test_the_fix_names_every_stuck_pid_not_just_the_five_displayed():
    """⛔ Found rendering a real Wave 3 report: twelve sessions idle in a transaction, the Affected
    section shows five, and the runbook took its pids from that - terminating five, leaving seven."""
    pids = [str(3600 + i) for i in range(12)]
    ctx = ContextBundle(logs=[f"postgres stuck connection: pid={p} idle in transaction for 336s: SELECT 1"
                              for p in pids])
    alert = Alert(alert_id="x", name="DatabaseAlarm", severity=Severity.high, service="warden",
                  environment="prod", summary="alert", started_at="2026-09-25T04:47:40Z")
    prop = RemediationProposal(action=ActionKind.terminate_connections, target="warden", reasoning="r",
                               expected_effect="e", blast_radius="single_service", reversible=True)
    rep = build_report(alert, proposal=prop, context=ctx, show_identifiers=False)
    fix = next(ln for ln in rep.markdown.splitlines() if "pg_terminate_backend" in ln and "pid IN (" in ln)
    listed = re.search(r"pid IN \(([^)]*)\)", fix).group(1).split(", ")
    assert listed == pids, f"the fix must name every stuck pid: {listed}"
    assert "AND state = 'idle in transaction'" in fix
    assert "and 7 more" in rep.markdown, "the display should say how many it is not showing"
