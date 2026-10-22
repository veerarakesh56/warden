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
    assert re.search(r'comparison_operator\s*=\s*"LessThanThreshold"', alarm)
    assert re.search(r"threshold\s*=\s*1\b", alarm)
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
    assert runtime.SYNTHETIC_EVERY.total_seconds() < period * periods <= 7 * 86400
    assert period >= 3600


def _module_text() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in sorted(MODULE.glob("*.tf")))


def _slug(name: str, zone: str | None = None) -> str:
    from warden import settings

    return settings.secret_id("dev", name, zone).removeprefix("warden/dev/")


def test_every_secret_the_runtime_reads_has_a_slot_and_no_slot_is_unused():
    """Decision D5: the slots are exactly the secrets a zone or a Lambda of the runtime reads, named as
    settings.secret_id names them - each a secret the code loads. Secrets audit, 2026-10-16: 14 slots nobody read or
    set (a rotation's previous keys, other models' keys, Teams, PagerDuty, the audit's DSN and passphrase) went."""
    from warden import settings

    text = (MODULE / "secrets.tf").read_text(encoding="utf-8")
    block = text[text.index("toset(["):text.index("])", text.index("toset(["))]
    slots = set(re.findall(r'"([a-z0-9-]+)"', block))
    read = {(n, z) for z, names in settings.ZONE_SECRETS.items() for n in names}
    read |= {(n, None) for names in settings.LAMBDA_SECRETS.values() for n in names}
    assert {n for n, _ in read} <= settings.SECRETS
    assert slots == {_slug(n, z) for n, z in read}
    for gone in ("grafana-read-token", "audit-dsn", "audit-key-passphrase", "temporal-key-previous", "db-dsn",
                 "alertmanager-token", "pagerduty-routing-key", "gemini-api-key", "openai-api-key", "teams-webhook"):
        assert gone not in slots, gone
    assert 'name                    = "warden/${var.environment}/${each.key}"' in text
    assert "secret_string" not in _module_text()  # no secret value in Terraform, so none in its state


def test_the_audit_signer_is_an_ed25519_kms_key_and_the_anchors_are_locked():
    kms = _block((MODULE / "kms.tf").read_text(encoding="utf-8"), "aws_kms_key", "audit_signer")
    assert 'customer_master_key_spec = "ECC_NIST_EDWARDS25519"' in kms
    assert 'key_usage                = "SIGN_VERIFY"' in kms
    anchors = (MODULE / "anchors.tf").read_text(encoding="utf-8")
    assert "object_lock_enabled = true" in anchors
    assert 'mode = "COMPLIANCE"' in anchors
    assert 'status = "Enabled"' in anchors
    assert anchors.count("= true") >= 5  # lock + the four public-access blocks
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
    assert 'aws_free_plan = lookup(local.tf, "aws_free_plan", "false") == "true"' in " ".join(root.split())
    net = (MODULE / "network.tf").read_text(encoding="utf-8")
    ingress = _block(net, "aws_vpc_security_group_ingress_rule", "audit_db_from_runtime")
    assert "referenced_security_group_id = aws_security_group.runtime.id" in ingress
    assert "5432" in ingress
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
    """iam.tf's `zones` local: per zone, its secrets and the watched roles it assumes."""
    block = iam[iam.index("  zones = {"):iam.index("\n  }\n", iam.index("  zones = {"))]
    out = {}
    for zone, body in re.findall(r"^\s+(\w+)\s+= \{(.*)\}$", block, re.MULTILINE):
        lists = dict(re.findall(r"(\w+) = \[([^\]]*)\]", body))
        out[zone] = {k: re.findall(r'"([a-z0-9-]+)"', v) for k, v in lists.items()}
    return out


def _front_door_access(iam: str) -> dict[str, dict]:
    """iam.tf's `front_door_access` local: per Lambda, its secrets and whether it reads the approvers or puts metrics."""
    start = iam.index("  front_door_access = {")
    block = iam[start:iam.index("\n  }\n", start)]
    out = {}
    for name, body in re.findall(r"^\s+([\w-]+)\s+= \{(.*)\}$", block, re.MULTILINE):
        secrets = re.search(r"secrets = \[([^\]]*)\]", body).group(1)
        out[name] = {"secrets": set(re.findall(r'"([a-z0-9-]+)"', secrets)),
                     "approvers": "approvers = true" in body, "metrics": "metrics = true" in body}
    return out


def test_each_zone_is_a_principal_of_its_own_and_only_the_act_zone_may_act():
    """A-P-5 / S15: a task role per zone, `warden-<env>-<zone>` - for the ops runtime the exact principals the templates
    trust. Only the act zone may assume an actor; the read and notify zones (and act, which re-reads before it writes)
    a reader. No zone calls a model through AWS (no Bedrock, owner 2026-10-09: the llm zone reaches its provider's
    API with its key). No zone holds a write to any watched resource itself."""
    import json

    from warden import workflows

    iam = (MODULE / "iam.tf").read_text(encoding="utf-8")
    zones = _zones(iam)
    assert set(zones) == {"core", *workflows.ZONES}
    assert {z for z, v in zones.items() if "actor" in v["assumes"]} == {"act"}
    assert {z for z, v in zones.items() if "platform-reader" in v["assumes"]} == {"read", "notify", "act"}
    role = _block(iam, "aws_iam_role", "zone")
    assert "for_each             = local.zones" in role
    assert 'name                 = "warden-${var.environment}-${each.key}"' in role
    reader = json.loads((ROOT / "iam" / "templates" / "platform-reader-trust.json").read_text(encoding="utf-8"))
    assert {p for st in reader["Statement"] for p in st["Principal"]["AWS"]} == {
        f"arn:aws:iam::${{account}}:role/warden-${{runtime}}-{z}" for z in ("read", "notify", "act")}
    actor = json.loads((ROOT / "iam" / "templates" / "actor-trust.json").read_text(encoding="utf-8"))
    assert {st["Principal"]["AWS"] for st in actor["Statement"]} == {"arn:aws:iam::${account}:role/warden-${runtime}-act"}
    actions = set(re.findall(r'"([a-z0-9-]+:[A-Za-z*]+)"', iam))
    assert not {a for a in actions if a.split(":")[0] in ("lambda", "ecs", "dynamodb", "events", "rds", "elasticache")}
    assert 'role/warden-${e}-${r}' in iam
    # No Bedrock: no grant, variable or root input names it, and the runtime's boundary has no ceiling for it.
    module = _module_text().replace('variable "model_provider"', "")
    assert "bedrock:" not in module
    assert "bedrock_model_arns" not in module
    assert "bedrock" not in (ROOT / "terraform" / "runtime" / "main.tf").read_text(encoding="utf-8").lower()
    assert "bedrock" not in (ROOT / "iam" / "templates" / "runtime-boundary.json").read_text(encoding="utf-8")


# What each front door's handler reads from Secrets Manager, and the module that reads it - the map each Lambda's role
# is held to (secrets audit, 2026-10-16: all four shared one role, so the internet-facing approval page could read the
# webhook's Datadog keys). The audit's DSN is the Lambda's own environment (frontdoor.tf) and KMS signs: no secret.
READS = {
    "alarm": {"WARDEN_TEMPORAL_KEY": "codec.py", "WARDEN_TEMPORAL_API_KEY": "runtime_base.py"},
    "alertmanager": {"WARDEN_TEMPORAL_KEY": "codec.py", "WARDEN_TEMPORAL_API_KEY": "runtime_base.py",
                     "WARDEN_DATADOG_WEBHOOK_TOKEN": "lambdas.py", "WARDEN_DATADOG_API_KEY": "lambdas.py",
                     "WARDEN_DATADOG_APP_KEY": "lambdas.py"},
    "approval": {"WARDEN_TEMPORAL_KEY": "codec.py", "WARDEN_TEMPORAL_API_KEY": "runtime_base.py",
                 "WARDEN_SLACK_CLIENT_SECRET": "slack_login.py"},
    "actor-use": {},
}


def test_each_lambda_has_its_own_role_that_reads_only_what_its_handler_reads():
    from warden import settings

    iam = (MODULE / "iam.tf").read_text(encoding="utf-8")
    access = _front_door_access(iam)
    doors = re.findall(r"^    ([\w-]+)\s+= \{ handler = ", _frontdoor(), re.MULTILINE)
    assert set(access) == set(doors) == set(READS) == set(settings.LAMBDA_SECRETS)
    src = ROOT / "src" / "warden"
    for name, reads in READS.items():
        assert settings.LAMBDA_SECRETS[name] == set(reads), name
        assert access[name]["secrets"] == {_slug(n) for n in reads}, name
        for secret, module in reads.items():  # each grant has its reader
            assert f'"{secret}"' in (src / module).read_text(encoding="utf-8"), (name, secret, module)
    # Only the approval page asks who may approve; actor-use counts (UnapprovedActorUse, ApproverListChanged), and the
    # approval page counts a kill switch it turns on (/x: paging.killswitch_tripped).
    assert {n for n, a in access.items() if a["approvers"]} == {"approval"}
    assert {n for n, a in access.items() if a["metrics"]} == {"actor-use", "approval"}
    lambdas = (src / "lambdas.py").read_text(encoding="utf-8")
    assert lambdas.count("put_metric_data(") == 2
    assert lambdas.count("approver_policy()") == 1
    assert "approver_policy()" in lambdas.split("def approval_page")[1].split("\ndef ")[0]
    role, policy = _block(iam, "aws_iam_role", "front_door"), _block(iam, "aws_iam_role_policy", "front_door")
    assert "for_each             = local.front_door_access" in role
    assert 'name                 = "warden-${var.environment}-${each.key}-lambda"' in role
    assert "concat(local.audit_and_settings," in policy
    assert "local.own" not in policy
    assert 'resource "aws_iam_role" "lambda"' not in iam
    assert "aws_iam_role.lambda." not in _module_text()
    assert "role          = aws_iam_role.front_door[each.key].arn" in _frontdoor()
    shared = iam[iam.index("  audit_and_settings = ["):iam.index("  who_may_approve = {")]
    assert not re.search(r"sts:|bedrock:|secretsmanager:|cloudwatch:|/approvers", shared)


def test_each_lambdas_load_asks_for_exactly_its_roles_secrets(monkeypatch):
    """Each handler's own load (lambdas._configure), run with the environment the module gives it: the Secrets Manager
    reads it makes are exactly its role's grant - none refused (a read outside the grant stops the Lambda), none spare."""
    import os

    import boto3

    from warden import lambdas, settings

    lambda_env = _frontdoor().split("lambda_env = {")[1].split("}")[0]
    env = re.findall(r"^\s+(WARDEN_[A-Z_]+)\s+= ", lambda_env, re.MULTILINE)
    assert "WARDEN_AUDIT_DSN" in env  # the audit's address is set, never a secret read
    access = _front_door_access((MODULE / "iam.tf").read_text(encoding="utf-8"))

    class Ssm:
        def get_paginator(self, _):
            return type("P", (), {"paginate": lambda self, **kw: [{"Parameters": []}]})()

    class Secrets:
        def __init__(self):
            self.asked = []

        def get_secret_value(self, SecretId):
            self.asked.append(SecretId)
            return {"SecretString": "x"}

    monkeypatch.setattr(lambdas, "_CONFIGURED", set())
    saved = dict(os.environ)
    try:
        for name in access:
            os.environ.clear()
            os.environ.update({k: v for k, v in saved.items() if k not in settings.LOADABLE | settings.SECRETS})
            os.environ.update({k: "set-by-the-module" for k in env} | {"WARDEN_ENV": "dev"})
            sm = Secrets()
            monkeypatch.setattr(boto3, "client", lambda service, sm=sm, **kw: sm if service == "secretsmanager" else Ssm())
            lambdas._configure(f"lambda-{name}")
            assert {s.removeprefix("warden/dev/") for s in sm.asked} == access[name]["secrets"], name
    finally:  # what the loads set, gone with the test
        os.environ.clear()
        os.environ.update(saved)


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
    for policy in ("zone", "front_door"):  # each name exactly, not a prefix of another
        block = _block(iam, "aws_iam_role_policy", policy)
        assert '"${local.secret_arn}/${s}-??????"' in block, policy
        assert "secret_arn}/${s}*" not in block, policy


# Each zone secret, the module that reads it (or the modules, when one secret has more readers: one slot, never a second
# for the same credential), and the zones whose code reads it - the map each zone's task role is held to (secrets
# audit, 2026-10-16: the GitHub token was moved to a zone that never reads it). A secret added later is added here by
# name, with its readers and zones.
_EVERY = {"core", "read", "llm", "notify", "act", "critic"}
ZONE_READS = {
    "WARDEN_TEMPORAL_KEY": ("codec.py", _EVERY),
    "WARDEN_TEMPORAL_API_KEY": ("runtime_base.py", _EVERY),
    "WARDEN_STACK_DB_PRIMARY_RO_DSN": ("aws_stack.py", {"read"}),
    "WARDEN_STACK_DB_REPLICA_RO_DSN": ("aws_stack.py", {"read"}),
    "WARDEN_DATADOG_API_KEY": ("datadog.py", {"read"}),
    "WARDEN_DATADOG_APP_KEY": ("datadog.py", {"read"}),
    # The read-only GitHub token: one slot for every read-zone reader of GitHub (owner U3-7).
    "WARDEN_GITHUB_READ_TOKEN": (("tools.py",), {"read"}),
    "ANTHROPIC_API_KEY": ("providers.py", {"llm", "critic"}),
    "WARDEN_SLACK_BOT_TOKEN": ("chatops.py", {"notify"}),
    "WARDEN_SLACK_APP_TOKEN": ("discuss.py", {"notify"}),
    "WARDEN_SLACK_WEBHOOK": ("chatops.py", {"notify"}),
    "WARDEN_GITHUB_TOKEN": ("changes.py", {"notify"}),
    "WARDEN_DB_TERMINATE_DSN": ("platforms/db.py", {"act"}),
    # Eldane, the AI critic: its own signing key (its model key is the diagnosis's, above; owner 2026-10-17).
    "WARDEN_ELDANE_KEY": ("eldane.py", {"critic"}),
}


def test_each_zone_reads_exactly_the_secrets_its_code_reads():
    from warden import settings

    src = ROOT / "src" / "warden"
    held = {n: {z for z, names in settings.ZONE_SECRETS.items() if n in names}
            for n in set().union(*settings.ZONE_SECRETS.values())}
    assert set(held) == set(ZONE_READS), "a zone secret with no reader named here, or a reader with no grant"
    for name, (modules, zones) in ZONE_READS.items():
        assert held[name] == zones, name
        for module in (modules,) if isinstance(modules, str) else modules:
            assert name in (src / module).read_text(encoding="utf-8"), (name, module)
    iam = _zones((MODULE / "iam.tf").read_text(encoding="utf-8"))
    for zone, v in iam.items():
        assert {_slug(n, zone) for n, (_, zones) in ZONE_READS.items() if zone in zones} == (
            {"temporal-key", f"temporal-api-key-{zone}"} | set(v["secrets"])), zone


def test_the_github_token_is_the_notify_zones_whose_activities_read_it():
    """Its two readers, traced to the activities that run them: RemediationActivities.finish opens the change-record
    issue (changes.GitHubIssues, built by runtime._activities from WARDEN_GITHUB_TOKEN) and IncidentActivities.notify
    reads the deploys for the report (timeline.recent). Both run on the notify zone's queue."""
    import inspect

    from warden import activities, changes, runtime, settings, timeline, workflows

    assert "self._record_change(" in inspect.getsource(activities.RemediationActivities.finish)
    assert "self.changes.open(" in inspect.getsource(activities.RemediationActivities._record_change)
    assert "changes=from_environment()" in inspect.getsource(runtime._activities)
    assert '"WARDEN_GITHUB_TOKEN"' in inspect.getsource(changes.from_environment)
    assert "timeline.recent(" in inspect.getsource(activities.IncidentActivities.notify)
    assert '"WARDEN_GITHUB_TOKEN"' in inspect.getsource(timeline.recent)
    readers = {"finish", "notify"}
    assert {z for z, names in workflows.ZONES.items() if readers & set(names)} == {"notify"}
    assert {z for z, names in settings.ZONE_SECRETS.items() if "WARDEN_GITHUB_TOKEN" in names} == {"notify"}



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
    assert 'entry_point = ["/opt/warden/bin/python", "-m", "awslambdaric"]' in tf
    assert "image_uri     = var.runtime_image" in tf
    assert 'can(regex("@sha256:[0-9a-f]{64}$", var.runtime_image))' in (MODULE / "variables.tf").read_text(encoding="utf-8")


def test_the_alarm_rule_sends_what_the_alarm_lambda_accepts_and_a_lost_alarm_pages():
    from warden import lambdas

    tf = _frontdoor()
    rule = _block(tf, "aws_cloudwatch_event_rule", "alarms")
    assert 'source        = ["aws.cloudwatch"]' in rule
    assert '"detail-type" = ["CloudWatch Alarm State Change"]' in rule
    assert lambdas.alarm_event({"source": "aws.cloudwatch", "detail-type": "CloudWatch Alarm State Change",
                                "detail": {"alarmName": "warden-dev-x", "state": {"value": "OK",
                                                                                  "timestamp": "2026-10-04T00:00:00Z"}}},
                               "dev") is not None
    assert '{ prefix = "warden-${e}-" }' in rule
    target = _block(tf, "aws_cloudwatch_event_target", "alarms")
    assert "dead_letter_config" in target
    assert "maximum_retry_attempts" in target
    page = _block(tf, "aws_cloudwatch_metric_alarm", "alarm_dlq")
    assert "alarm_actions       = [var.page_topic_arn]" in page


def test_the_api_throttles_logs_and_routes_exactly_what_the_page_and_the_webhook_serve():
    from warden import approval_page

    tf = _frontdoor()
    stage = _block(tf, "aws_apigatewayv2_stage", "front")
    assert "throttling_rate_limit  = var.api_rate_limit" in stage
    assert "throttling_burst_limit = var.api_burst_limit" in stage
    assert "access_log_settings" in stage
    assert re.findall(r'"(GET /a/\{token\})", "(POST /a/\{token\}/\{step\})"', tf)
    assert re.search(r'route_key\s*=\s*"POST /alertmanager"', tf)
    # Every page step the page serves is a POST on /a/{token}/{step}; the shell is the GET.
    # The route table is in _approval, where handle sends every /a/ path.
    import inspect

    src = inspect.getsource(approval_page.ApprovalPage._approval)
    steps = set(re.findall(r'\("POST", "([a-z-]+)"\)', src))
    assert steps >= {"login-options", "login", "approve-options", "approve", "deny-options", "deny"}
    assert '("GET", "")' in src


def test_the_lambdas_get_the_names_the_runtime_reads():
    from warden import runtime_base as runtime  # where runtime's audit and policy readers live

    tf = _frontdoor()
    names = set(re.findall(r"^\s+(WARDEN_[A-Z_]+)\s+=", tf, re.MULTILINE))
    assert names == {"WARDEN_ENV", "WARDEN_AUDIT_KMS_KEY_ID", "WARDEN_AUDIT_ANCHOR_BUCKET", "WARDEN_APPROVAL_RP_ID",
                     "WARDEN_AUDIT_DSN", "WARDEN_AUDIT_IAM_AUTH", "WARDEN_HEARTBEAT_NAMESPACE", "WARDEN_PAGES_BUCKET"}
    import inspect

    from warden import audit, paging

    src = inspect.getsource(runtime) + inspect.getsource(audit) + inspect.getsource(paging)
    for name in names - {"WARDEN_ENV", "WARDEN_APPROVAL_RP_ID"}:
        assert f'"{name}"' in src, name


def test_the_runtime_image_is_digest_pinned_non_root_and_installs_the_runtime_extra():
    text = re.sub(r"\\\n\s*", "", (ROOT / "Dockerfile.runtime").read_text(encoding="utf-8"))  # continuations joined
    plain = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    froms = re.findall(r"^FROM (\S+)", text, re.MULTILINE)
    assert froms
    assert all("@sha256:" in f for f in froms)
    assert set(froms) <= set(re.findall(r"^FROM (\S+)", plain, re.MULTILINE))  # the same bases as the tool image
    assert "uv sync --locked --no-build --no-editable --extra runtime" in text
    assert "USER warden" in text
    assert "check_package.py" in text
    py = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'^runtime = \["awslambdaric>=4\.1"', py, re.MULTILINE)
    # The SDK of every model provider the deploy may pick for the llm zone (qualified in data/providers.yaml).
    from warden.providers import load_qualified

    sync = re.search(r"uv sync --locked --no-build --no-editable(.*)", text).group(1)
    for provider in {e["provider"] for e in load_qualified()["qualified"]} - {"claude_cli", "bedrock"}:
        assert f"--extra {provider}" in sync, provider


def test_the_worker_runs_on_fargate_with_its_own_role_only():
    """Requirement R20 (owner, 2026-10-14: Fargate, was EC2) and the runtime's own safety: each zone's task in its own
    micro-VM with no instance metadata service, a read-only root as the image's non-root user with /tmp its only
    writable place, the worker's task role, and the settings the code reads."""
    from warden import runtime

    tf = (MODULE / "compute.tf").read_text(encoding="utf-8")
    task = _block(tf, "aws_ecs_task_definition", "zone")
    assert 'requires_compatibilities = ["FARGATE"]' in task
    assert '"EC2"' not in task
    assert 'cpu_architecture        = "X86_64"' in task
    assert 'mountPoints            = [{ sourceVolume = "tmp", containerPath = "/tmp", readOnly = false }]' in task
    assert "linuxParameters" not in task  # Fargate has no tmpfs
    dockerfile = (ROOT / "Dockerfile.runtime").read_text(encoding="utf-8")
    # The volume takes the image's /tmp: Debian's 1777, checked at build (else it would be root's 0755).
    assert ('RUN useradd --create-home --uid 10001 warden \\\n'
            '    && test "$(stat -c \'%a %U\' /tmp)" = "1777 root"\nVOLUME ["/tmp"]\nUSER warden') in dockerfile
    service = _block(tf, "aws_ecs_service", "zone")
    assert 'capacity_provider = "FARGATE"' in service
    assert "force_new_deployment = true" in service  # the provider needs it
    # Never Spot (PR 44 review): no fallback to on-demand, and the heartbeat does not see one zone's gap.
    assert "FARGATE_SPOT" not in "\n".join(f.read_text(encoding="utf-8") for f in MODULE.glob("*.tf"))
    assert "placement_constraints" not in service
    assert "ordered_placement_strategy" not in service  # Fargate refuses them
    assert "task_role_arn            = aws_iam_role.zone[each.key].arn" in task
    assert "readonlyRootFilesystem = true" in task
    assert "for_each                 = local.zones" in task
    # Cost plan 2026-10-16: Container Insights was ~USD 40 a month of custom metrics nothing reads.
    assert re.search(r'name\s*=\s*"containerInsights"\s*value\s*=\s*"disabled"', _block(tf, "aws_ecs_cluster", "runtime"))
    uid = re.search(r"useradd --create-home --uid (\d+)", (ROOT / "Dockerfile.runtime").read_text(encoding="utf-8"))
    assert f'user                   = "{uid.group(1)}"' in task
    assert 'command                = ["worker", "--zone", each.key, "--platform", length(each.value.platforms) > 0 ? join(",", each.value.platforms) : "none"]' in task
    assert 'WARDEN_HEARTBEAT_NAMESPACE   = "WARDEN/${var.environment}"' in task
    template = re.search(r'WARDEN_AWS_ROLE_ARN_TEMPLATE = "([^"]+)"', task).group(1)
    assert "{env}" in template
    assert "{role}" in template
    assert template.startswith("arn:aws:iam::${local.account}:role/")
    import inspect

    from warden.platforms import aws

    assert '"WARDEN_AWS_ROLE_ARN_TEMPLATE"' in inspect.getsource(aws.from_environment)
    assert "WARDEN_HEARTBEAT_NAMESPACE" in inspect.getsource(runtime.cloudwatch_publisher)
    assert "rollback = true" in service
    assert "security_groups = [aws_security_group.runtime.id]" in service


def test_the_audit_is_reached_as_its_writer_with_an_iam_token_and_only_migrate_reads_the_master_secret():
    """G6: no audit password exists. migrate.tf's Lambda - the one identity that reads the cluster's master secret -
    creates the schema and `warden_audit_writer`, a login that signs in only with an IAM token; every zone and Lambda
    connects as that writer, by rds-db:connect on that one database user."""
    from warden import lambdas

    mig = (MODULE / "migrate.tf").read_text(encoding="utf-8")
    iam = (MODULE / "iam.tf").read_text(encoding="utf-8")
    assert f'audit_writer = "{lambdas.AUDIT_WRITER}"' in mig
    assert "postgresql://${local.audit_writer}@" in mig
    assert "sslmode=require" in mig
    assert ":${" not in mig.split("postgresql://")[1].split("@")[0]
    assert 'Resource = local.audit_db.master_secret' in mig
    assert 'command     = ["warden.lambdas.migrate"]' in mig
    module = _module_text()
    assert module.count("master_user_secret[0].secret_arn") == 2  # the migrate role's grant and its environment
    assert '"rds-db:connect"' in iam
    assert "dbuser:${local.audit_db.resource_id}/${local.audit_writer}" in iam
    for tf in ("compute.tf", "frontdoor.tf"):
        text = (MODULE / tf).read_text(encoding="utf-8")
        assert re.search(r'WARDEN_AUDIT_IAM_AUTH\s+= "1"', text), tf
        assert re.search(r"WARDEN_AUDIT_DSN\s+= local.audit_dsn", text), tf


def test_on_the_aws_free_plan_the_audit_is_one_private_rds_instance_with_the_same_protections():
    """The Free plan creates Aurora only in express configuration (no VPC, an internet gateway, not settable from the
    AWS provider; FreeTierRestrictionError, 2026-10-09). A lab on it gets one RDS PostgreSQL instance of a Free plan
    class instead - in the same private subnets and security group, never public, with register O4's protections - and
    everything else reads the database through local.audit_db, whichever exists."""
    aurora = (MODULE / "aurora.tf").read_text(encoding="utf-8")
    assert "count                               = var.aws_free_plan ? 0 : 1" in _block(aurora, "aws_rds_cluster", "audit")
    db = _block(aurora, "aws_db_instance", "audit")
    for line in ("count                               = var.aws_free_plan ? 1 : 0", 'instance_class                      = "db.t4g.micro"',
                 "manage_master_user_password         = true", "iam_database_authentication_enabled = true",
                 "storage_encrypted                   = true", "deletion_protection                 = true",
                 "skip_final_snapshot                 = false", "publicly_accessible                 = false",
                 "backup_retention_period             = var.audit_db_backup_days",
                 "db_subnet_group_name                = aws_db_subnet_group.audit.name",
                 "vpc_security_group_ids              = [aws_security_group.audit_db.id]"):
        assert line in db, line
    assert "master_password" not in db.replace("manage_master_user_password", "")
    others = "\n".join(f.read_text(encoding="utf-8") for f in MODULE.glob("*.tf") if f.name != "aurora.tf")
    assert "aws_rds_cluster.audit" not in others
    assert "aws_db_instance.audit" not in others


def test_no_ec2_instance_is_left_to_run_the_workers():
    """Fargate (owner, 2026-10-14): the EC2 group, its launch template, capacity provider, instance role and profile,
    the instances' group and the AMI lookup are gone, and the cluster's only provider is FARGATE."""
    module = "\n".join(f.read_text(encoding="utf-8") for f in MODULE.glob("*.tf"))
    for gone in ("aws_autoscaling_group", "aws_launch_template", "aws_ecs_capacity_provider", "aws_iam_instance_profile",
                 'aws_security_group" "instances"', "ecs/optimized-ami", "worker_instance_types", "worker_tasks_per_instance"):
        assert gone not in module, gone
    cluster = " ".join(_block(module, "aws_ecs_cluster_capacity_providers", "runtime").split())
    assert 'capacity_providers = ["FARGATE"]' in cluster


def test_the_runtime_reaches_out_on_https_temporal_clouds_port_and_the_audit_only():
    """Every worker timed out connecting to Temporal Cloud with only 443 open (2026-10-09): its endpoints listen on
    7233. Out: 443 and 7233 anywhere, 5432 to the audit database's group, nothing else; in: nothing. Every egress rule
    sits in the group's own blocks - a separate egress rule resource was deleted by the group's next in-place update,
    and the audit became unreachable (2026-10-09)."""
    net = (MODULE / "network.tf").read_text(encoding="utf-8")
    sg = _block(net, "aws_security_group", "runtime")
    ports = sorted(int(p) for p in re.findall(r"from_port\s*=\s*(\d+)", sg))
    assert ports == [443, 5432, 5432, 7233]
    # The second 5432: the watched databases' public endpoints (Aurora express), only when switched on (2026-10-15).
    assert 'dynamic "egress"' in sg
    assert "for_each = var.watched_db_egress ? [1] : []" in sg
    assert "security_groups = [aws_security_group.audit_db.id]" in sg
    assert "ingress" not in sg
    module = "\n".join(f.read_text(encoding="utf-8") for f in MODULE.glob("*.tf"))
    assert "aws_vpc_security_group_egress_rule" not in module


def test_only_the_notify_zone_posts_for_real():
    """chatops.py is dry-run unless WARDEN_CHATOPS_LIVE=1, which is never loaded from SSM: the runtime's first
    incident ran end to end and its report was dropped silently (2026-10-09). The notify zone - and no other - has it."""
    compute = (MODULE / "compute.tf").read_text(encoding="utf-8")
    assert compute.count("WARDEN_CHATOPS_LIVE") == 1
    assert 'each.key == "notify" ? { WARDEN_CHATOPS_LIVE = "1" } : {}' in compute


def test_paused_the_runtime_keeps_its_audit_and_stops_its_spend():
    """Between test windows (owner, 2026-10-10): no worker task or instance, no NAT gateway, no alarm intake and no
    self-page for the silent workers; the audit, its key, the secrets, the witness and the anchors are untouched."""
    compute = (MODULE / "compute.tf").read_text(encoding="utf-8")
    # Removed, not scaled: no service and no capacity provider association while paused (Fargate bills per task).
    assert "count = var.paused ? 0 : 1" in " ".join(_block(compute, "aws_ecs_cluster_capacity_providers", "runtime").split())
    assert "for_each = var.paused ? {} : local.zones" in " ".join(compute.split())
    front = (MODULE / "frontdoor.tf").read_text(encoding="utf-8")
    assert 'state       = var.paused ? "DISABLED" : "ENABLED"' in _block(front, "aws_cloudwatch_event_rule", "alarms")
    beat = (MODULE / "heartbeat.tf").read_text(encoding="utf-8")
    assert beat.count("actions_enabled     = !var.paused") == 2
    net = (ROOT / "terraform" / "runtime" / "network.tf").read_text(encoding="utf-8")
    assert "count  = local.paused ? 0 : var.nat_gateways" in net
    assert "count         = local.paused ? 0 : var.nat_gateways" in net
    assert "count                  = local.paused ? 0 : 2" in net
    # Nothing that holds the audit or a key changes with it.
    others = "\n".join((MODULE / f).read_text(encoding="utf-8") for f in ("aurora.tf", "kms.tf", "anchors.tf",
                                                                           "witness.tf", "secrets.tf"))
    assert "paused" not in others


CONFIG_TF = ROOT / "terraform" / "runtime" / "config.tf"


def _config_check():
    """scripts/check_live_config.py, whose needed_types() reads the types the undo uses from platforms/aws.py."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("check_live_config", ROOT / "scripts" / "check_live_config.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _config_blocks(text: str, head: str) -> list[str]:
    import re

    return [m.group(0) for m in re.finditer(rf"^{head} \{{.*?^\}}", text, re.DOTALL | re.MULTILINE)]


def test_the_recorder_is_adopted_and_never_created():
    """B15: each Config resource exists only with an import block over the same keys, so an instance Terraform
    plans is always an import of one that exists - a name that is not in the account fails the plan instead of
    creating a second recorder. Nothing is managed until SSM names the recorder; nothing is destroyed by Terraform."""
    import re

    text = CONFIG_TF.read_text(encoding="utf-8")
    resources = {re.search(r'"(aws_config_\w+)" "this"', b).group(1): b
                 for b in _config_blocks(text, r'resource "aws_config_\w+" "this"')}
    assert set(resources) == {"aws_config_configuration_recorder", "aws_config_delivery_channel",
                              "aws_config_configuration_recorder_status"}
    imports = {re.search(r"to\s*=\s*(aws_config_\w+)\.this\[each\.key\]", b).group(1):
               re.search(r"for_each\s*=\s*(\S+)", b).group(1) for b in _config_blocks(text, "import")}
    for kind, block in resources.items():
        for_each = re.search(r"for_each\s*=\s*(\S+)", block).group(1)
        assert imports.get(kind) == for_each, (kind, imports.get(kind), for_each)
        assert "prevent_destroy = true" in block, kind
        assert "count" not in re.findall(r"^\s*(\w+)\s*=", block, re.MULTILINE), kind
    # Adopted as it is (CodeRabbit, PR 112): the owner's recorder definition and channel settings are never written
    # over - no recording group, mode or channel option in this configuration, and every change to them ignored.
    for kind in ("aws_config_configuration_recorder", "aws_config_delivery_channel"):
        assert re.search(r"ignore_changes\s*=\s*all\b", resources[kind]), kind
    for setting in ("recording_group", "recording_mode", "s3_kms_key_arn", "sns_topic_arn", "snapshot_delivery"):
        assert setting not in text, setting
    assert re.search(r"is_enabled\s*=\s*true", resources["aws_config_configuration_recorder_status"])
    # Started only when its channel is there too (Config refuses a recorder with no delivery channel).
    assert "config_status = length(local.config_channel) == 0 ? toset([]) : local.config_recorder" in " ".join(
        text.split())
    assert 'compact([lookup(local.tf, "config_recorder_name", "")])' in text  # off until SSM names it


def test_the_deploy_role_can_adopt_the_recorder_and_keep_it_on_but_never_change_stop_or_delete_it():
    """B15 (CodeRabbit, PR 112): no identity policy of the runtime deploy role writes the recorder or the channel,
    stops or deletes either, or passes a role to Config - and the boundary allows no more than the reads and a start."""
    import json

    allows = [st for kind in ("deploy", "deploy-ec2", "deploy-guard", "deploy-config")
              for st in json.loads((ROOT / "iam" / "ops" / f"{kind}.json").read_text(encoding="utf-8"))["Statement"]
              if st["Effect"] == "Allow"]
    grants = [a for st in allows for a in ([st["Action"]] if isinstance(st["Action"], str) else st["Action"])]
    config = sorted(a for a in grants if a.startswith("config:"))
    assert config == ["config:DescribeConfigurationRecorderStatus", "config:DescribeConfigurationRecorders",
                      "config:DescribeDeliveryChannels", "config:ListTagsForResource",
                      "config:StartConfigurationRecorder"]
    # No whole statement - resource or condition - passes a role to Config: compared as values, not as substrings.
    def values(x):
        return [x] if isinstance(x, str) else list(x or [])

    services = {v for st in allows for keys in st.get("Condition", {}).values()
                for key, want in keys.items() if key == "iam:PassedToService" for v in values(want)}
    assert "config.amazonaws.com" not in services
    roles = [r for st in allows for r in values(st.get("Resource")) if r.startswith("arn:aws:iam::")]
    assert not [r for r in roles if r.endswith("/AWSServiceRoleForConfig")]
    boundary = json.loads((ROOT / "iam" / "ops" / "boundary.json").read_text(encoding="utf-8"))
    ceiling = next(st for st in boundary["Statement"] if st.get("Sid") == "CeilingRegional")
    assert sorted(a for a in ceiling["Action"] if a.startswith("config:")) == [
        "config:Describe*", "config:ListTagsForResource", "config:StartConfigurationRecorder"]
    assert "AWSServiceRoleForConfig" not in json.dumps(boundary)


def test_setup_says_to_attach_the_config_policy_before_the_recorder_is_named():
    """scripts/render_env_iam.py renders iam/ops/deploy-config.json; a person creates and attaches it, as every other
    deploy-role policy (CodeRabbit, PR 112). SETUP's runtime step 1 says so, before tf/config_recorder_name is set."""
    setup = (ROOT / "docs" / "SETUP.md").read_text(encoding="utf-8")
    step = setup[setup.index("1. Create `WardenEnvBoundary-ops`"):setup.index("2. Create the state bucket")]
    assert "`WardenEnvDeployConfig-ops` from `iam/ops/deploy-config.json`" in step
    assert "attach it\n   to `warden-ops-deploy` before setting `tf/config_recorder_name`" in step
