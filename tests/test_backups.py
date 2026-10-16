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
