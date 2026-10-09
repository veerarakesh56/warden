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
    wanted |= {settings.secret_id("dev", n, z).removeprefix("warden/dev/") for n in settings.PER_ZONE
               for z in settings.ZONE_SECRETS}  # register S15: each zone's own Temporal key
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
    # 7 days or more; fewer (1 at least) only when the root says the account is on the AWS Free plan, which refuses
    # longer retention (FreeTierRestrictionError, 2026-10-09). Never set in production.
    assert ("condition     = var.audit_db_backup_days >= 7 || (var.aws_free_plan && var.audit_db_backup_days >= 1)"
            in variables)
    root = (ROOT / "terraform" / "runtime" / "main.tf").read_text(encoding="utf-8")
    assert 'aws_free_plan            = lookup(local.tf, "aws_free_plan", "false") == "true"' in root
    net = (MODULE / "network.tf").read_text(encoding="utf-8")
    ingress = _block(net, "aws_vpc_security_group_ingress_rule", "audit_db_from_runtime")
    assert "referenced_security_group_id = aws_security_group.runtime.id" in ingress and "5432" in ingress
    assert "cidr_ipv4" not in net.split('resource "aws_security_group" "audit_db"')[1]  # no address range reaches it
    # EC2 accepts only a-zA-Z0-9 and . _-:/()#,@[]+=&;{}!$* and space in a rule's description (the first apply, 2026-10-09).
    for desc in re.findall(r'description\s*=\s*"([^"]*)"', net):
        assert re.fullmatch(r"[A-Za-z0-9 ._\-:/()#,@\[\]+=&;{}!$*]*", desc.replace("${var.environment}", "ops")), desc


def test_a_secret_the_owner_made_by_hand_is_adopted_not_created_again():
    """The Slack webhook's slot was made in the console before the first apply, which then failed with
    ResourceExistsException (2026-10-09). The root imports it - only an exact, single name match."""
    root = (ROOT / "terraform" / "runtime" / "main.tf").read_text(encoding="utf-8")
    assert 'adopt = ["slack-webhook"]' in root
    assert "to = module.runtime.aws_secretsmanager_secret.runtime[each.key]" in root
    assert 'if data.aws_secretsmanager_secrets.adopt[n].names == toset(["warden/${local.env}/${n}"])' in root


def _zones(iam: str) -> dict[str, dict]:
    """iam.tf's `zones` local: per zone, its secrets, the watched roles it assumes and whether it calls the model."""
    block = iam[iam.index("  zones = {"):iam.index("\n  }\n", iam.index("  zones = {"))]
    out = {}
    for zone, body in re.findall(r"^\s+(\w+)\s+= \{(.*)\}$", block, re.MULTILINE):
        lists = dict(re.findall(r"(\w+) = \[([^\]]*)\]", body))
        out[zone] = {k: re.findall(r'"([a-z0-9-]+)"', v) for k, v in lists.items()} | {"model": "model = true" in body}
    return out


def test_each_zone_is_a_principal_of_its_own_and_only_the_act_zone_may_act():
    """A-P-5 / S15: a task role per zone, `warden-<env>-<zone>` - for the ops runtime the exact principals the templates
    trust. Only the act zone may assume an actor; the read and notify zones (and act, which re-reads before it writes)
    a reader; only llm may call the model. No zone holds a write to any watched resource itself."""
    import json

    from warden import workflows

    iam = (MODULE / "iam.tf").read_text(encoding="utf-8")
    zones = _zones(iam)
    assert set(zones) == {"core", *workflows.ZONES}
    assert {z for z, v in zones.items() if "actor" in v["assumes"]} == {"act"}
    assert {z for z, v in zones.items() if "platform-reader" in v["assumes"]} == {"read", "notify", "act"}
    assert {z for z, v in zones.items() if v["model"]} == {"llm"}
    role = _block(iam, "aws_iam_role", "zone")
    assert "for_each             = local.zones" in role and 'name                 = "warden-${var.environment}-${each.key}"' in role
    reader = json.loads((ROOT / "iam" / "templates" / "platform-reader-trust.json").read_text(encoding="utf-8"))
    assert {p for st in reader["Statement"] for p in st["Principal"]["AWS"]} == {
        f"arn:aws:iam::${{account}}:role/warden-ops-{z}" for z in ("read", "notify", "act")}
    actor = json.loads((ROOT / "iam" / "templates" / "actor-trust.json").read_text(encoding="utf-8"))
    assert {st["Principal"]["AWS"] for st in actor["Statement"]} == {"arn:aws:iam::${account}:role/warden-ops-act"}
    actions = set(re.findall(r'"([a-z0-9-]+:[A-Za-z*]+)"', iam))
    assert not {a for a in actions if a.split(":")[0] in ("lambda", "ecs", "dynamodb", "events", "rds", "elasticache")}
    assert 'role/warden-${e}-${r}' in iam and "each.value.model && length(var.bedrock_model_arns) > 0" in iam


def test_the_lambdas_assume_nothing_call_no_model_and_read_only_their_secrets():
    from warden import settings

    iam = (MODULE / "iam.tf").read_text(encoding="utf-8")
    policy = _block(iam, "aws_iam_role_policy", "lambda")
    assert "concat(local.own," in policy and "local.lambda_secrets" in policy
    own = iam[iam.index("  own = ["):iam.index("  every_zone_secrets")]
    assert "sts:" not in own and "bedrock:" not in own and "secretsmanager:" not in own
    listed = re.findall(r'"([a-z0-9-]+)"', iam[iam.index("  lambda_secrets = ["):iam.index("]", iam.index("  lambda_secrets = ["))])
    used = {n for c in ("lambda-alarm", "lambda-alertmanager", "lambda-approval", "lambda-actor-use")
            for n in settings.loadable_for(c) & settings.SECRETS}
    assert set(listed) == {settings.secret_id("dev", n).removeprefix("warden/dev/") for n in used}


def test_each_zone_reads_exactly_the_secrets_its_worker_loads():
    """S15: iam.tf's per-zone secrets are settings.ZONE_SECRETS, named by settings.secret_id - the zone's own Temporal
    key included - so a zone's task role can read no secret another zone holds."""
    from warden import settings

    iam = (MODULE / "iam.tf").read_text(encoding="utf-8")
    every = re.findall(r'"([a-z0-9-]+)"', iam[iam.index("every_zone_secrets = ["):iam.index("]", iam.index("every_zone_secrets = ["))])
    for zone, v in _zones(iam).items():
        granted = set(every) | set(v["secrets"]) | {f"temporal-api-key-{zone}"}
        wanted = {settings.secret_id("dev", n, zone).removeprefix("warden/dev/") for n in settings.ZONE_SECRETS[zone]}
        assert granted == wanted, zone
    for policy in ("zone", "lambda"):  # each name exactly, not a prefix of another
        block = _block(iam, "aws_iam_role_policy", policy)
        assert '"${local.secret_arn}/${s}-??????"' in block and "secret_arn}/${s}*" not in block, policy



def _frontdoor() -> str:
    return (MODULE / "frontdoor.tf").read_text(encoding="utf-8")


def test_every_front_door_runs_a_handler_that_exists_from_the_digest_pinned_image():
    import importlib

    tf = _frontdoor()
    handlers = re.findall(r'handler = "(warden\.lambdas\.\w+)"', tf)
    assert sorted(h.rsplit(".", 1)[1] for h in handlers) == ["actor_use", "alarm", "alertmanager", "approval"]
    for h in handlers:
        module, name = h.rsplit(".", 1)
        assert callable(getattr(importlib.import_module(module), name))
    assert 'entry_point = ["/opt/warden/bin/python", "-m", "awslambdaric"]' in tf and "image_uri     = var.runtime_image" in tf
    assert 'can(regex("@sha256:[0-9a-f]{64}$", var.runtime_image))' in (MODULE / "variables.tf").read_text(encoding="utf-8")


def test_the_alarm_rule_sends_what_the_alarm_lambda_accepts_and_a_lost_alarm_pages():
    from warden import lambdas

    tf = _frontdoor()
    rule = _block(tf, "aws_cloudwatch_event_rule", "alarms")
    assert 'source        = ["aws.cloudwatch"]' in rule and '"detail-type" = ["CloudWatch Alarm State Change"]' in rule
    assert lambdas.alarm_event({"source": "aws.cloudwatch", "detail-type": "CloudWatch Alarm State Change",
                                "detail": {"alarmName": "warden-dev-x", "state": {"value": "OK",
                                                                                  "timestamp": "2026-10-04T00:00:00Z"}}},
                               "dev") is not None
    assert '{ prefix = "warden-${e}-" }' in rule
    target = _block(tf, "aws_cloudwatch_event_target", "alarms")
    assert "dead_letter_config" in target and "maximum_retry_attempts" in target
    page = _block(tf, "aws_cloudwatch_metric_alarm", "alarm_dlq")
    assert "alarm_actions       = [var.page_topic_arn]" in page


def test_the_api_throttles_logs_and_routes_exactly_what_the_page_and_the_webhook_serve():
    from warden import approval_page

    tf = _frontdoor()
    stage = _block(tf, "aws_apigatewayv2_stage", "front")
    assert "throttling_rate_limit  = var.api_rate_limit" in stage and "throttling_burst_limit = var.api_burst_limit" in stage
    assert "access_log_settings" in stage
    assert re.findall(r'"(GET /a/\{token\})", "(POST /a/\{token\}/\{step\})"', tf)
    assert 'route_key = "POST /alertmanager"' in tf
    # Every page step the page serves is a POST on /a/{token}/{step}; the shell is the GET.
    import inspect

    src = inspect.getsource(approval_page.ApprovalPage.handle)
    steps = set(re.findall(r'\("POST", "([a-z-]+)"\)', src))
    assert steps >= {"login-options", "login", "approve-options", "approve", "deny-options", "deny"}
    assert '("GET", "")' in src


def test_the_lambdas_get_the_names_the_runtime_reads():
    from warden import runtime

    tf = _frontdoor()
    names = set(re.findall(r"^\s+(WARDEN_[A-Z_]+)\s+=", tf, re.MULTILINE))
    assert names == {"WARDEN_ENV", "WARDEN_AUDIT_KMS_KEY_ID", "WARDEN_AUDIT_ANCHOR_BUCKET", "WARDEN_APPROVAL_RP_ID",
                     "WARDEN_AUDIT_DSN", "WARDEN_AUDIT_IAM_AUTH"}
    import inspect

    from warden import audit

    src = inspect.getsource(runtime) + inspect.getsource(audit)
    for name in names - {"WARDEN_ENV", "WARDEN_APPROVAL_RP_ID"}:
        assert f'"{name}"' in src, name


def test_the_runtime_image_is_digest_pinned_non_root_and_installs_the_runtime_extra():
    text = (ROOT / "Dockerfile.runtime").read_text(encoding="utf-8")
    plain = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    froms = re.findall(r"^FROM (\S+)", text, re.MULTILINE)
    assert froms and all("@sha256:" in f for f in froms)
    assert set(froms) <= set(re.findall(r"^FROM (\S+)", plain, re.MULTILINE))  # the same bases as the tool image
    assert "uv sync --locked --no-editable --extra runtime" in text and "USER warden" in text
    assert "check_package.py" in text
    py = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'^runtime = \["awslambdaric>=4\.1"', py, re.MULTILINE)
    # The SDK of every model provider the deploy may pick for the llm zone (qualified in data/providers.yaml).
    from warden.providers import load_qualified

    sync = re.search(r"uv sync --locked --no-editable(.*)", text).group(1)
    for provider in {e["provider"] for e in load_qualified()["qualified"]} - {"claude_cli", "bedrock"}:
        assert f"--extra {provider}" in sync, provider


def test_the_worker_runs_on_ec2_with_its_metadata_locked_and_its_own_role_only():
    """Requirement R20 (ECS on EC2, not Fargate) and the runtime's own safety: IMDSv2 one hop away and blocked from
    tasks, a read-only root as the image's non-root user, the worker's task role, and the settings the code reads."""
    from warden import runtime

    tf = (MODULE / "compute.tf").read_text(encoding="utf-8")
    assert 'requires_compatibilities = ["EC2"]' in tf and "FARGATE" not in tf.upper().replace("NOT FARGATE", "")
    lt = _block(tf, "aws_launch_template", "instances")
    assert 'http_tokens                 = "required"' in lt and "http_put_response_hop_limit = 1" in lt
    assert "ECS_AWSVPC_BLOCK_IMDS=true" in lt and "encrypted   = true" in lt
    task = _block(tf, "aws_ecs_task_definition", "zone")
    assert "task_role_arn            = aws_iam_role.zone[each.key].arn" in task and "readonlyRootFilesystem = true" in task
    assert "for_each                 = local.zones" in task
    uid = re.search(r"useradd --create-home --uid (\d+)", (ROOT / "Dockerfile.runtime").read_text(encoding="utf-8"))
    assert f'user                   = "{uid.group(1)}"' in task
    assert 'command                = ["worker", "--zone", each.key, "--platform", length(each.value.assumes) > 0 ? "aws" : "none"]' in task
    assert 'WARDEN_HEARTBEAT_NAMESPACE   = "WARDEN/${var.environment}"' in task
    template = re.search(r'WARDEN_AWS_ROLE_ARN_TEMPLATE = "([^"]+)"', task).group(1)
    assert "{env}" in template and "{role}" in template and template.startswith("arn:aws:iam::${local.account}:role/")
    import inspect

    from warden.platforms import aws

    assert '"WARDEN_AWS_ROLE_ARN_TEMPLATE"' in inspect.getsource(aws.from_environment)
    assert "WARDEN_HEARTBEAT_NAMESPACE" in inspect.getsource(runtime.cloudwatch_publisher)
    service = _block(tf, "aws_ecs_service", "zone")
    assert "rollback = true" in service and "security_groups = [aws_security_group.runtime.id]" in service


def test_the_audit_is_reached_as_its_writer_with_an_iam_token_and_only_migrate_reads_the_master_secret():
    """G6: no audit password exists. migrate.tf's Lambda - the one identity that reads the cluster's master secret -
    creates the schema and `warden_audit_writer`, a login that signs in only with an IAM token; every zone and Lambda
    connects as that writer, by rds-db:connect on that one database user."""
    from warden import lambdas

    mig = (MODULE / "migrate.tf").read_text(encoding="utf-8")
    iam = (MODULE / "iam.tf").read_text(encoding="utf-8")
    assert f'audit_writer = "{lambdas.AUDIT_WRITER}"' in mig
    assert "postgresql://${local.audit_writer}@" in mig and "sslmode=require" in mig and ":${" not in mig.split("postgresql://")[1].split("@")[0]
    assert 'Resource = aws_rds_cluster.audit.master_user_secret[0].secret_arn' in mig
    assert 'command     = ["warden.lambdas.migrate"]' in mig
    module = _module_text()
    assert module.count("master_user_secret[0].secret_arn") == 2  # the migrate role's grant and its environment
    assert '"rds-db:connect"' in iam and "dbuser:${aws_rds_cluster.audit.cluster_resource_id}/${local.audit_writer}" in iam
    for tf in ("compute.tf", "frontdoor.tf"):
        text = (MODULE / tf).read_text(encoding="utf-8")
        assert re.search(r'WARDEN_AUDIT_IAM_AUTH\s+= "1"', text) and re.search(r"WARDEN_AUDIT_DSN\s+= local.audit_dsn", text), tf
