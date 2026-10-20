"""Dev is run as production (owner, 2026-10-16): its data can be restored. Every DynamoDB table the dev stack and the
runtime module make has point-in-time recovery on; WARDEN's own audit database keeps backups and cannot be deleted
by accident."""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
STACKS = (ROOT / "terraform" / "fullstack", ROOT / "terraform" / "modules" / "warden-runtime")


def _code(text: str) -> str:
    """Terraform with its comments removed (`#`, `//` and `/* */`; none of these stacks has them inside a string
    that matters here): a commented-out block must not count as configured (CodeRabbit, PR 35)."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"(#|//).*", "", text)


def _blocks(kind: str):
    for stack in STACKS:
        for tf in sorted(stack.glob("*.tf")):
            text = _code(tf.read_text(encoding="utf-8"))
            for m in re.finditer(rf'^resource "{kind}" "(\w+)" \{{', text, re.MULTILINE):
                end = re.search(r"^\}", text[m.end():], re.MULTILINE)
                yield f"{tf.relative_to(ROOT)}:{m.group(1)}", text[m.end():m.end() + end.start()]


def test_every_dynamodb_table_can_be_restored_to_a_point_in_time():
    tables = list(_blocks("aws_dynamodb_table"))
    assert tables, "no DynamoDB table found: the pattern no longer matches the stacks"
    bad = [name for name, body in tables
           if not re.search(r"point_in_time_recovery\s*\{\s*enabled\s*=\s*true\s*\}", body)]
    assert not bad, bad


def test_the_audit_database_keeps_backups_and_a_final_snapshot():
    blocks = dict(_blocks("aws_rds_cluster")) | dict(_blocks("aws_db_instance"))
    audit = {n: b for n, b in blocks.items() if "warden-runtime" in n}
    assert audit, "no audit database found in the runtime module"
    for name, body in audit.items():
        assert re.search(r"deletion_protection\s*=\s*true", body), name
        assert re.search(r"skip_final_snapshot\s*=\s*false", body), name
        value = re.search(r"backup_retention_period\s*=\s*(\S+)", body).group(1)
        assert value == "var.audit_db_backup_days", (name, value)
    # The variable can never be 0 (no automated backups): its validation asks for 7 days, or 1 on the AWS Free plan.
    variables = _code((ROOT / "terraform/modules/warden-runtime/variables.tf").read_text(encoding="utf-8"))
    block = variables.split('variable "audit_db_backup_days" {', 1)[1].split("\n}", 1)[0]
    condition = re.search(r"condition\s*=\s*(.+)", block).group(1).strip()
    assert condition == ("var.audit_db_backup_days >= 7 || (var.aws_free_plan && var.audit_db_backup_days >= 1)"), \
        condition


def test_a_commented_out_block_does_not_count():
    body = _code('resource "aws_dynamodb_table" "t" {\n  # point_in_time_recovery {\n  #   enabled = true\n  # }\n}')
    assert not re.search(r"point_in_time_recovery\s*\{\s*enabled\s*=\s*true\s*\}", body)


AUDIT_DAYS = 180  # B19 (owner, 2026-10-17): audit retention at least 180 days - logs, anchors, backups
RUNTIME = ROOT / "terraform" / "modules" / "warden-runtime"


def test_every_runtime_log_group_keeps_its_logs_at_least_180_days():
    groups = [(name, body) for name, body in _blocks("aws_cloudwatch_log_group") if "warden-runtime" in name]
    assert len(groups) >= 4, "the pattern no longer finds the runtime's log groups"
    short = [name for name, body in groups
             if int(re.search(r"retention_in_days\s*=\s*(\d+)", body).group(1)) < AUDIT_DAYS]
    assert not short, short
    # A Lambda without its own log group gets one from AWS that terraform does not hold to this; only the ack
    # function has none, and its role has no permission at all - it writes no log.
    code = {tf.name: _code(tf.read_text(encoding="utf-8")) for tf in RUNTIME.glob("*.tf")}
    functions = {m for text in code.values() for m in re.findall(r'^resource "aws_lambda_function" "(\w+)"', text, re.MULTILINE)}
    assert functions - {"front_door", "migrate"} == {"ack"}
    ack_role = re.search(r'resource "aws_iam_role" "ack" \{.*?^\}', code["frontdoor.tf"], re.DOTALL | re.MULTILINE).group(0)
    assert not re.search(r"\brole\s*=\s*aws_iam_role\.ack\.(?:id|name)\b", "".join(code.values()))  # no policy on it
    assert "inline_policy" not in ack_role
    assert "managed_policy_arns" not in ack_role


def test_anchors_and_the_witness_stay_locked_at_least_180_days():
    for tf, resource in (("anchors.tf", "anchors"), ("witness.tf", "witness")):
        text = _code((RUNTIME / tf).read_text(encoding="utf-8"))
        lock = re.search(rf'resource "aws_s3_bucket_object_lock_configuration" "{resource}" \{{.*?^\}}', text,
                         re.DOTALL | re.MULTILINE).group(0)
        assert re.search(r'mode\s*=\s*"COMPLIANCE"', lock), tf
        assert re.search(r"days\s*=\s*var\.anchor_retention_days", lock), tf
    runtime = _code((ROOT / "terraform" / "runtime" / "main.tf").read_text(encoding="utf-8"))
    days = re.search(r"\n\s*anchor_retention_days\s*=\s*(\d+)\n", runtime)
    assert days, "terraform/runtime/main.tf sets no anchor_retention_days: the module's 1-day default applies"
    assert int(days.group(1)) >= AUDIT_DAYS

