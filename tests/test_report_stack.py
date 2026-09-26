"""Wave 4 report side: the runbook aims the closed-set actions at the stack component the evidence
names, `fix_commands` follows contract E (runbook first, then each pattern's fix), the markdown shows
the same commands, the code-level finding and what each stack reader read - and nothing leaks or
arrives as a placeholder.
"""

from __future__ import annotations

import itertools
import json
import shlex

import pytest

from test_playbook_stack import _HOLE, ACCT, FAULTS, REGION, alert, allowed, ctx
from warden.models import ActionKind, RemediationProposal, RootCause, Verdict, VerdictStatus
from warden.reporting import build_report
from warden.runbook import build_runbook, platform_for


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


@pytest.mark.parametrize("fid,action,platform,fix", [
    ("fs-01", ActionKind.rollback_deploy, "lambda",
     "aws lambda update-alias --function-name warden-pg-fs-checkout --name live --function-version 6 --region ap-south-2"),
    ("fs-03", ActionKind.scale_up, "lambda",
     ("aws lambda put-function-concurrency --function-name warden-pg-fs-checkout --reserved-concurrent-executions 4 "
     "--region ap-south-2")),
    ("fs-09", ActionKind.scale_up, "dynamodb",
     ("aws dynamodb update-table --table-name warden-pg-fs-carts --provisioned-throughput "
     "ReadCapacityUnits=1,WriteCapacityUnits=3 --region ap-south-2")),
    ("fs-21", ActionKind.restart_pods, "ecs",
     ("aws ecs update-service --cluster warden-pg-fs-ecs --service warden-pg-fs-orders-api --force-new-deployment "
     "--region ap-south-2")),
    ("fs-17", ActionKind.rollback_deploy, "ecs",
     ("aws ecs update-service --cluster warden-pg-fs-ecs --service warden-pg-fs-orders-api --task-definition "
     "warden-pg-fs-orders-api:11 --region ap-south-2")),
    ("fs-15", ActionKind.failover_replica, "aurora",
     ("aws rds failover-db-cluster --db-cluster-identifier warden-pg-fs-aurora --target-db-instance-identifier "
     "warden-pg-fs-aurora-1 --region ap-south-2")),
    ("fs-26", ActionKind.rollback_deploy, "kubernetes", "kubectl -n shop rollout undo deploy/catalog-api"),
])
def test_the_runbook_acts_on_the_component_the_evidence_names(fid, action, platform, fix):
    rb = build_runbook(alert(), action, backend="stack", context=FAULTS[fid][1])
    assert rb.platform == platform, rb.basis
    assert rb.fix == [fix]
    assert rb.risk, "risk is printed before the steps"


def test_rollback_and_scale_undo_return_to_the_values_in_the_evidence():
    rb = build_runbook(alert(), ActionKind.rollback_deploy, backend="stack", context=FAULTS["fs-01"][1])
    assert rb.undo == [("aws lambda update-alias --function-name warden-pg-fs-checkout --name live "
                       "--function-version 7 --region ap-south-2")]
    rb = build_runbook(alert(), ActionKind.scale_up, backend="stack", context=FAULTS["fs-09"][1])
    assert rb.undo == [("aws dynamodb update-table --table-name warden-pg-fs-carts --provisioned-throughput "
                       "ReadCapacityUnits=1,WriteCapacityUnits=1 --region ap-south-2")]
    rb = build_runbook(alert(), ActionKind.failover_replica, backend="stack", context=FAULTS["fs-15"][1])
    assert rb.undo[0].endswith("--target-db-instance-identifier warden-pg-fs-aurora-2 --region ap-south-2")


def test_an_aurora_failover_with_no_single_named_reader_prints_no_command():
    c = ctx(["CLUSTER aurora warden-pg-fs-aurora writer=warden-pg-fs-aurora-1 readers=[] status=available"])
    rb = build_runbook(alert(), ActionKind.failover_replica, backend="stack", context=c)
    assert rb.platform == "aurora" and rb.fix == [] and "exactly one reader" in rb.note


def test_terminate_connections_on_aurora_is_the_postgres_sql_aimed_at_the_writer():
    r = _report("fs-13", ActionKind.terminate_connections)
    assert r.data["runbook"]["platform"] == "aurora"
    sql = [f for f in r.data["fix_commands"] if f["kind"] == "sql"]
    assert sql and all(f["target"] == "writer" for f in sql)
    assert sql[0]["source"] == "runbook" and "pg_terminate_backend" in sql[0]["command"]
    assert any(f["source"] == "pattern:db_lock" and "IN (4077)" in f["command"] for f in sql)


def test_fix_commands_put_the_runbook_first_then_each_pattern():
    r = _report("fs-01")
    sources = [f["source"] for f in r.data["fix_commands"]]
    assert sources == ["runbook", "pattern:code_error_after_deploy"]
    assert all(f["kind"] == "shell" and "target" not in f for f in r.data["fix_commands"])
    md = r.markdown
    block = md[md.index("## Fix - exact commands"):]
    for f in r.data["fix_commands"]:
        assert f["command"] in block


def test_with_no_proposal_the_patterns_still_carry_their_fix():
    r = build_report(alert(), context=FAULTS["fs-27"][1], backend="stack", show_identifiers=False)
    assert r.data["fix_commands"] == [{"kind": "shell", "source": "pattern:schedule_off",
                                       "command": "aws events enable-rule --name warden-pg-fs-reconcile-5m "
                                                  "--region ap-south-2"}]


@pytest.mark.parametrize("fid,action", list(itertools.product(sorted(FAULTS), list(ActionKind))))
def test_no_stack_report_has_a_placeholder_or_a_command_the_harness_refuses(fid, action):
    r = _report(fid, action)
    assert not _HOLE.findall(r.markdown), (fid, action, _HOLE.findall(r.markdown))
    for f in r.data["fix_commands"]:
        assert not _HOLE.search(f["command"]), f
        assert allowed(f) is None, (fid, action, allowed(f))
    assert ACCT not in r.markdown


def test_commands_survive_the_reports_redaction_intact():
    """The report redacts everything; a fix command that came out masked would not run."""
    for fid in ("fs-05", "fs-08", "fs-18", "fs-19", "fs-07"):
        r = _report(fid, ActionKind.escalate_to_human)
        cmds = [f["command"] for f in r.data["fix_commands"]]
        assert cmds and not any("<" in c and "_1>" in c for c in cmds), (fid, cmds)
        for c in cmds:
            assert c in r.markdown
    policy = next(f["command"] for f in _report("fs-18", ActionKind.escalate_to_human).data["fix_commands"]
                  if "put-role-policy" in f["command"])
    words = shlex.split(policy)
    assert json.loads(words[words.index("--policy-document") + 1])["Statement"][0]["Action"] == \
        "secretsmanager:GetSecretValue"


def test_the_report_shows_the_code_level_finding():
    md = _report("fs-01").markdown
    section = md[md.index("## Code-level finding"):]
    assert "**`app.py:42`** in `handler`: `KeyError: 'sku'`" in section
    assert "```python\n40 | def handler(event, context):" in section
    assert "42 >|     sku = body['sku']" in section
    assert "start at `app.py:42` in `handler` (warden-pg-fs-checkout)" in section
    assert _report("fs-01").data["code"][0]["line"] == 42


def test_what_warden_read_lists_each_component_and_each_failed_reader():
    c = ctx(tool_errors=["sqs/warden-pg-fs-orders: AccessDenied on GetQueueAttributes"])
    md = _report(None, ActionKind.escalate_to_human, context=c).markdown
    section = md[md.index("## What WARDEN read"):md.index("## What WARDEN thinks")]
    assert "alert time ± 15 min" in section and "alert time ± 10 min" in section
    for reader in ("lambda", "dynamodb", "elasticache", "aurora", "alb", "apigw", "ecs", "k8s", "secret", "sns",
                   "eventbridge"):
        assert f"- {reader} `" in section and "read." in section, reader
    assert "- sqs `warden-pg-fs-orders,warden-pg-fs-notifications`" in section
    assert "**FAILED**: `sqs/warden-pg-fs-orders: AccessDenied on GetQueueAttributes`" in section
    assert "Not read: Redis itself" in section


@pytest.mark.parametrize("fid,platform", [("fs-07", "lambda"), ("fs-19", "alb"), ("fs-27", "eventbridge"),
                                          ("fs-08", "sns"), ("fs-11", "elasticache")])
def test_the_platform_comes_from_the_evidence_not_the_shared_labels(fid, platform):
    """Every alert of the app carries the same labels, so they cannot say what broke."""
    got, _ = platform_for(alert(), ActionKind.restart_pods, "stack", FAULTS[fid][1])
    assert got == platform


def test_a_healthy_stack_gets_no_runbook_commands_and_says_so():
    rb = build_runbook(alert(), ActionKind.restart_pods, backend="stack", context=ctx())
    assert rb.platform == "unknown" and rb.fix == [] and rb.check == [] and "could not tell" in rb.note


def test_a_failover_with_two_readers_named_is_not_aimed_by_guesswork():
    c = ctx([("CLUSTER aurora warden-pg-fs-aurora writer=warden-pg-fs-aurora-1 "
             "readers=[warden-pg-fs-aurora-2,warden-pg-fs-aurora-3] status=available")])
    rb = build_runbook(alert(), ActionKind.failover_replica, backend="stack", context=c)
    assert rb.fix == [] and "warden-pg-fs-aurora-2, warden-pg-fs-aurora-3" in rb.note


def test_shell_arithmetic_on_a_step_variable_is_never_a_fix_command():
    """`--replicas=$((CUR+1))` needs CUR from an earlier step: the harness could never run it."""
    from warden.reporting import _fix_commands
    got = _fix_commands(["kubectl -n shop scale deploy/x --replicas=$((CUR+1))",
                         ('aws lambda update-event-source-mapping --uuid "$(aws lambda list-event-source-mappings '
                          '--function-name warden-pg-fs-x --query X --output text --region ap-south-2)" --enabled '
                          '--region ap-south-2')], "runbook")
    assert [g["command"][:7] for g in got] == ["aws lam"], got


def test_ecs_and_kubernetes_counts_never_stand_in_for_each_other():
    """In a stack alert both are read; scaling ECS from a Deployment's replica count would be wrong."""
    from warden.runbook import _current_replicas
    both = ctx(metrics={"tasks_desired": 2.0, "replicas_desired__cart-worker": 1.0, "replicas_desired__catalog-api": 2.0})
    assert _current_replicas(both, "ecs") == 2
    assert _current_replicas(both, "kubernetes", "cart-worker") == 1
    assert _current_replicas(ctx(metrics={"replicas_desired": 3.0}), "ecs") is None


def test_no_rollout_undo_while_every_pod_of_that_deployment_is_ready():
    """Wave 4's healthy control (2026-09-26): 2/2 pods Ready, start-up readiness failures in the
    evidence, two revisions - and the probe pattern printed `rollout undo`, which rolled catalog-api
    back onto the previous revision's broken image when the harness applied it."""
    lines = [('LOG k8s/shop/catalog-api EVENT Unhealthy Pod/catalog-api-86d495f875-svtj2: Readiness probe '
              'failed: Get "http://10.0.1.5:8080/ready": dial tcp 10.0.1.5:8080: connect: connection refused'),
             "LOG k8s/shop/catalog-api ROLLOUT revision 10 (current): app:v1 created 2026-09-26T11:24:50Z",
             "LOG k8s/shop/catalog-api ROLLOUT revision 9: app:does-not-exist created 2026-09-26T11:26:50Z"]

    def undo(ready):
        r = build_report(alert(), context=ctx(lines, {"pods_total__catalog-api": 2.0,
                                                      "pods_ready__catalog-api": ready}),
                         backend="stack", show_identifiers=True)
        return [f for f in r.data["fix_commands"] if "rollout undo" in f["command"]]

    assert undo(2.0) == []
    assert undo(1.0), "a revision that is failing NOW is still rolled back"
