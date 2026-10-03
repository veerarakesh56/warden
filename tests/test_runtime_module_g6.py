"""G6: the runtime module (terraform/modules/warden-runtime), held to the code it serves. Register C13: the alarm on
missing heartbeats reads the exact metric the worker publishes, and reads silence as failure."""

from __future__ import annotations

import pathlib
import re

from warden import runtime

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "terraform" / "modules" / "warden-runtime"


def _block(text: str, kind: str, name: str) -> str:
    start = text.index(f'resource "{kind}" "{name}"')
    return text[start:text.index("\n}\n", start)]


def test_the_heartbeat_alarm_reads_the_workers_metric_and_pages_on_silence():
    alarm = _block((MODULE / "heartbeat.tf").read_text(encoding="utf-8"), "aws_cloudwatch_metric_alarm", "heartbeat")
    assert re.search(r'treat_missing_data\s*=\s*"breaching"', alarm)
    assert re.search(r'comparison_operator\s*=\s*"LessThanThreshold"', alarm) and re.search(r"threshold\s*=\s*1\b", alarm)
    assert re.search(rf'metric_name\s*=\s*"{runtime.HEARTBEAT_METRIC}"', alarm)
    assert re.search(rf'dimensions\s*=\s*\{{ TaskQueue = "{runtime.TASK_QUEUE}" \}}', alarm)
    assert 'namespace           = "WARDEN/${var.environment}"' in alarm
    assert "alarm_actions       = [var.page_topic_arn]" in alarm


def test_the_alarm_period_is_the_workers_beat():
    variables = (MODULE / "variables.tf").read_text(encoding="utf-8")
    block = variables[variables.index('variable "heartbeat_period_seconds"'):]
    default = int(re.search(r"default\s*=\s*(\d+)", block).group(1))
    assert default == runtime.HEARTBEAT_EVERY.total_seconds()


def test_the_synthetic_alarm_pages_after_a_day_without_a_pass():
    alarm = _block((MODULE / "heartbeat.tf").read_text(encoding="utf-8"), "aws_cloudwatch_metric_alarm", "synthetic")
    assert re.search(rf'metric_name\s*=\s*"{runtime.SYNTHETIC_METRIC}"', alarm)
    assert re.search(r'treat_missing_data\s*=\s*"breaching"', alarm)
    period = int(re.search(r"period\s*=\s*(\d+)", alarm).group(1))
    periods = int(re.search(r"evaluation_periods\s*=\s*(\d+)", alarm).group(1))
    assert int(re.search(r"datapoints_to_alarm\s*=\s*(\d+)", alarm).group(1)) == periods
    # Longer than the synthetic's own day, within CloudWatch's seven-day limit for hourly periods (PutMetricAlarm).
    assert runtime.SYNTHETIC_EVERY.total_seconds() < period * periods <= 7 * 86400 and period >= 3600


def _module_text() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in sorted(MODULE.glob("*.tf")))


def test_every_secret_the_code_loads_has_a_slot_and_no_slot_is_unused():
    """Decision D5: the slots are exactly settings.SECRETS, named as settings.secret_id names them."""
    from warden import settings

    text = (MODULE / "secrets.tf").read_text(encoding="utf-8")
    block = text[text.index("toset(["):text.index("])", text.index("toset(["))]
    slots = set(re.findall(r'"([a-z0-9-]+)"', block))
    wanted = {settings.secret_id("dev", n).removeprefix("warden/dev/") for n in settings.SECRETS}
    assert slots == wanted
    assert 'name                    = "warden/${var.environment}/${each.key}"' in text
    assert "secret_string" not in _module_text()  # no secret value in Terraform, so none in its state


def test_the_audit_signer_is_an_ed25519_kms_key_and_the_anchors_are_locked():
    kms = _block((MODULE / "kms.tf").read_text(encoding="utf-8"), "aws_kms_key", "audit_signer")
    assert 'customer_master_key_spec = "ECC_NIST_EDWARDS25519"' in kms and 'key_usage                = "SIGN_VERIFY"' in kms
    anchors = (MODULE / "anchors.tf").read_text(encoding="utf-8")
    assert "object_lock_enabled = true" in anchors and 'mode = "COMPLIANCE"' in anchors
    assert 'status = "Enabled"' in anchors and anchors.count("= true") >= 5  # lock + the four public-access blocks
    assert '"aws:SecureTransport" = "false"' in anchors
    variables = (MODULE / "variables.tf").read_text(encoding="utf-8")
    block = variables[variables.index('variable "anchor_retention_days"'):]
    assert int(re.search(r"default\s*=\s*(\d+)", block).group(1)) == runtime_anchor_default_days()


def runtime_anchor_default_days() -> int:
    from warden import audit

    return audit.ANCHOR_RETENTION.days


def test_the_audit_database_keeps_point_in_time_recovery_and_is_reached_by_the_runtime_only():
    """Register O4: backups with point-in-time recovery, deletion protection, a final snapshot, encryption; the password
    is RDS-managed (never in Terraform); only the runtime's security group reaches port 5432."""
    db = _block((MODULE / "aurora.tf").read_text(encoding="utf-8"), "aws_rds_cluster", "audit")
    for line in ("manage_master_user_password         = true", "storage_encrypted                   = true",
                 "deletion_protection                 = true", "skip_final_snapshot                 = false",
                 "backup_retention_period             = var.audit_db_backup_days", "min_capacity             = 0"):
        assert line in db, line
    assert "master_password" not in db.replace("manage_master_user_password", "")
    variables = (MODULE / "variables.tf").read_text(encoding="utf-8")
    assert "condition     = var.audit_db_backup_days >= 7" in variables
    net = (MODULE / "network.tf").read_text(encoding="utf-8")
    ingress = _block(net, "aws_vpc_security_group_ingress_rule", "audit_db_from_runtime")
    assert "referenced_security_group_id = aws_security_group.runtime.id" in ingress and "5432" in ingress
    assert "cidr_ipv4" not in net.split('resource "aws_security_group" "audit_db"')[1]  # no address range reaches it


def test_the_worker_is_the_principal_the_actor_and_reader_trust_and_writes_nothing_itself():
    """A-P-5 / G6: the worker role is `warden-<env>-worker` - for the ops runtime the exact principal the templates
    trust - and holds no write to any watched resource: it reaches one only through an assumed actor session."""
    import json

    iam = (MODULE / "iam.tf").read_text(encoding="utf-8")
    worker = _block(iam, "aws_iam_role", "worker")
    assert 'name               = "warden-${var.environment}-worker"' in worker
    for name in ("actor-trust", "platform-reader-trust"):
        trust = json.loads((ROOT / "iam" / "templates" / f"{name}.json").read_text(encoding="utf-8"))
        assert {st["Principal"]["AWS"] for st in trust["Statement"]} == {"arn:aws:iam::${account}:role/warden-ops-worker"}
    assumable = iam[iam.index("assumable = flatten("):iam.index("])", iam.index("assumable = flatten("))]
    assert re.findall(r"role/warden-\$\{e\}-([a-z-]+)", assumable) == ["platform-reader", "actor"]
    actions = set(re.findall(r'"([a-z0-9-]+:[A-Za-z*]+)"', iam))
    assert not {a for a in actions if a.split(":")[0] in ("lambda", "ecs", "dynamodb", "events", "rds", "elasticache")}
    assert '"sts:AssumeRole", "sts:SetSourceIdentity", "sts:TagSession"' in iam and "Resource = local.assumable" in iam


def test_the_lambdas_assume_nothing_and_call_no_model():
    iam = (MODULE / "iam.tf").read_text(encoding="utf-8")
    policy = _block(iam, "aws_iam_role_policy", "lambda")
    assert "Statement = local.own" in policy
    own = iam[iam.index("  own = ["):iam.index("data \"aws_iam_policy_document\" \"ecs_tasks_trust\"")]
    assert "sts:" not in own and "bedrock:" not in own


def test_every_runtime_identity_reads_only_its_own_secrets_settings_and_metrics():
    from warden import runtime, settings

    iam = (MODULE / "iam.tf").read_text(encoding="utf-8")
    assert "secret:warden/${var.environment}/*" in iam  # settings.secret_id: warden/<env>/<name>
    assert settings.secret_id("dev", "WARDEN_GITHUB_TOKEN").startswith("warden/dev/")
    assert "parameter/warden/${var.environment}/env/*" in iam
    assert '"cloudwatch:namespace" = "WARDEN/${var.environment}"' in iam
    assert runtime.cloudwatch_publisher.__doc__ and "WARDEN/dev" in runtime.cloudwatch_publisher.__doc__
    for trust in ("ecs_tasks_trust", "lambda_trust"):
        block = iam[iam.index(f'data "aws_iam_policy_document" "{trust}"'):]
        assert 'variable = "aws:SourceAccount"' in block[:block.index("\n}\n")]

