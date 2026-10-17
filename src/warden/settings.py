"""Per-environment secrets from Secrets Manager and plain values from SSM Parameter Store - never a file on disk.

Decision D5 / requirement R32 (2026-10-03): every secret is a Secrets Manager secret `warden/<env>/<name>` (for
WARDEN_SLACK_WEBHOOK, `warden/<env>/slack-webhook`), so it can be rotated and its reads are in CloudTrail; SSM holds
only the plain values (cluster, log group, region, model). A secret name in SSM is ignored, never loaded.


v2 Phase 1.5 (2026-09-27). `WARDEN_ENV=<env>` makes WARDEN read `/warden/<env>/env/<NAME>` (one
paginated call, decrypted) and set each NAME as an environment variable the rest of WARDEN already
reads. The parameters are SecureString for secrets, String for plain values; standard tier, which is
free. Access is the caller's IAM identity: in production a worker's task role, in the lab the
owner's short-lived `aws login` session. No credential is ever stored by WARDEN.

Rules:
- A real environment variable wins over SSM, which wins over the code default. Setting a value
  explicitly always takes precedence over the store.
- Only names on `LOADABLE` are loaded. Never loaded, by design: the switches that arm live actions
  (`WARDEN_CHATOPS_LIVE`, `WARDEN_MOCK`; and the retired `WARDEN_REMEDIATION`, `WARDEN_DB_DRY_RUN`, still
  refused so an old parameter can never mean anything) - arming stays a person's act on the command line - and anything that redirects where WARDEN reads or sends
  (`*_PATH`, `WARDEN_BASE_URL`, `WARDEN_PROVIDER`), so a parameter cannot re-point model traffic.
- No `WARDEN_ENV`: nothing happens and no AWS client is built. Every existing flow is unchanged.

ponytail: loaded once per process; a long-running MCP server needs a restart to see a rotated webhook.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

from .environments import default_environment_policies, names

# Renamed 2026-10-16 so each name says the one grant it carries (naming audit items 6-7): the "admin" DSN was always
# the least-privilege terminate role's (pg_signal_backend, platforms/db.py), and the Aurora "writer"/"reader" DSNs are
# read-only logins to the primary and the replica instance - "writer" read as the privilege, not the endpoint. An old
# name set in the environment is still read for one release, with a WARNING naming the new one (getenv).
RENAMED = {"WARDEN_DB_ADMIN_DSN": "WARDEN_DB_TERMINATE_DSN",
           "WARDEN_STACK_DB_WRITER_DSN": "WARDEN_STACK_DB_PRIMARY_RO_DSN",
           "WARDEN_STACK_DB_READER_DSN": "WARDEN_STACK_DB_REPLICA_RO_DSN"}
_OLD_NAME = {new: old for old, new in RENAMED.items()}
# Their Secrets Manager slots keep the old names until terraform/modules/warden-runtime renames them (secrets.tf and
# iam.tf, owned separately): until then each new name is read from its old slot, so a deployed runtime reads the same
# secret it read before and its task roles need no change.
_SLOT = {new: old.lower().removeprefix("warden_").replace("_", "-") for old, new in RENAMED.items()}

LOADABLE = frozenset({
    "WARDEN_SLACK_BOT_TOKEN", "WARDEN_SLACK_CHANNEL", "WARDEN_SLACK_WEBHOOK", "WARDEN_TEAMS_WEBHOOK", "WARDEN_WEBHOOK_URL",
    "WARDEN_DB_DSN", "WARDEN_DB_TERMINATE_DSN", "WARDEN_STACK_DB_PRIMARY_RO_DSN", "WARDEN_STACK_DB_REPLICA_RO_DSN",
    "GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "WARDEN_AWS_CLUSTER", "WARDEN_AWS_LOG_GROUP", "WARDEN_AWS_REGION", "WARDEN_MODEL",
    "WARDEN_AUDIT_KEY_PASSPHRASE", "WARDEN_TEMPORAL_KEY",
    "WARDEN_TEMPORAL_API_KEY", "WARDEN_TEMPORAL_ADDRESS", "WARDEN_TEMPORAL_NAMESPACE",
    "WARDEN_GITHUB_TOKEN", "WARDEN_CHANGE_REPO", "WARDEN_TEMPORAL_KEY_PREVIOUS",
    "WARDEN_HEARTBEAT_NAMESPACE", "WARDEN_AWS_READER_ROLE_ARN", "WARDEN_AWS_ACTOR_ROLE_ARN", "WARDEN_AWS_ROLE_ARN_TEMPLATE",
    "WARDEN_AUDIT_DSN", "WARDEN_AUDIT_KMS_KEY_ID", "WARDEN_AUDIT_ANCHOR_BUCKET", "WARDEN_AUDIT_ANCHOR_DAYS",
    "WARDEN_PAGERDUTY_ROUTING_KEY",
    "WARDEN_ALERTMANAGER_TOKEN", "WARDEN_ALERTMANAGER_TOKEN_PREVIOUS", "WARDEN_ALERTMANAGER_URL", "WARDEN_APPROVAL_RP_ID",
    "WARDEN_SLACK_CLIENT_ID", "WARDEN_SLACK_CLIENT_SECRET", "WARDEN_EXPECTED_DOWN",
    "WARDEN_SLACK_APP_TOKEN", "WARDEN_DISCUSS_CHANNEL", "WARDEN_RECORD_VIEWERS",
    # Each environment's own alerts and discussion channels, `env=channel[,env=channel]` (by_environment): a dev
    # incident is told only in dev's, a prod one only in prod's (owner, 2026-10-16).
    "WARDEN_SLACK_CHANNELS", "WARDEN_DISCUSS_CHANNELS",
    # Datadog (datadog.py): its site is plain; the API key and the scoped, read-only application key are secrets.
    "WARDEN_DATADOG_SITE", "WARDEN_DATADOG_API_KEY", "WARDEN_DATADOG_APP_KEY", "WARDEN_DATADOG_WEBHOOK_TOKEN",
    # X-Ray (xray.py) and which tools a run reads: plain. Grafana's reader (grafana.py) is not loaded from the store:
    # WARDEN's own runtime reads Datadog only (owner, 2026-10-16); an adopter sets WARDEN_GRAFANA_* in the process.
    "WARDEN_XRAY", "WARDEN_EVIDENCE_TOOLS", "WARDEN_COMMITS", "WARDEN_HISTORY_IN_PROMPT",
    # Whose changes WARDEN never proposes to undo - a security team, a break-glass identity (platforms/aws.py): plain,
    # comma-separated. Not loadable before 2026-10-14, so the cloud runtime could never be told (gap audit).
    "WARDEN_NEVER_REVERT_PRINCIPALS",
    # Each environment's EKS cluster, `env=cluster[,env=cluster]` (aws_stack.eks_cluster_of): a Kubernetes alert that
    # does not name its cluster - a Datadog monitor grouped by workload - is read in its environment's (2026-10-15).
    "WARDEN_EKS_CLUSTERS",
    # The watched database's DSNs carry no password: each read signs an IAM token in the incident's reader role
    # (aws_stack.iam_dsn).
    "WARDEN_STACK_DB_IAM_AUTH",
})


# Loaded only for the commands that use them (audit A-B-L17): a diagnosis run and the MCP server have no use for the
# terminate role's DSN or the audit key's passphrase, and a process that never holds a secret cannot leak it.
RESTRICTED: dict[str, frozenset[str]] = {
    "WARDEN_DB_TERMINATE_DSN": frozenset({"worker"}),
    "WARDEN_AUDIT_KEY_PASSPHRASE": frozenset({"worker", "incident", "intake", "status", "approve", "killswitch", "audit",
                                              "label"}),
    "WARDEN_TEMPORAL_KEY": frozenset({"worker", "incident", "intake", "status", "approve", "mcp", "lambda-alarm", "lambda-alertmanager", "lambda-approval"}),
    "WARDEN_TEMPORAL_API_KEY": frozenset({"worker", "incident", "intake", "status", "approve", "mcp", "lambda-alarm", "lambda-alertmanager", "lambda-approval"}),
    "WARDEN_TEMPORAL_KEY_PREVIOUS": frozenset({"worker", "incident", "intake", "status", "approve", "mcp", "lambda-alarm", "lambda-alertmanager", "lambda-approval"}),
    "WARDEN_GITHUB_TOKEN": frozenset({"worker"}),
    # Only the worker writes to AWS or beats; no other command needs to know the roles (audit A-P-5, register C13).
    "WARDEN_AWS_READER_ROLE_ARN": frozenset({"worker"}),
    "WARDEN_AWS_ACTOR_ROLE_ARN": frozenset({"worker"}),
    "WARDEN_AWS_ROLE_ARN_TEMPLATE": frozenset({"worker"}),
    "WARDEN_HEARTBEAT_NAMESPACE": frozenset({"worker"}),
    # The commands that open the audit (runtime.open_audit) and the ones that read it.
    "WARDEN_AUDIT_DSN": frozenset({"worker", "incident", "intake", "status", "approve", "killswitch", "audit",
                                   "label", "usage", "lambda-alarm", "lambda-alertmanager", "lambda-approval",
                                   "lambda-actor-use"}),
    # The Alertmanager webhook's bearer secrets: only the Lambda that checks them (register S5).
    "WARDEN_ALERTMANAGER_TOKEN": frozenset({"lambda-alertmanager"}),
    # Paging (decision D13): only what sends messages - the worker, and a manual run that emits its report.
    "WARDEN_PAGERDUTY_ROUTING_KEY": frozenset({"worker", "run"}),
    "WARDEN_ALERTMANAGER_TOKEN_PREVIOUS": frozenset({"lambda-alertmanager"}),
    # Sign in with Slack (slack_login.py): only the approval page asks Slack who is there.
    "WARDEN_SLACK_CLIENT_ID": frozenset({"lambda-approval"}),
    "WARDEN_SLACK_CLIENT_SECRET": frozenset({"lambda-approval"}),
    # The discussion channel's listener (discuss.py): the notify zone's worker alone holds the connection.
    "WARDEN_SLACK_APP_TOKEN": frozenset({"worker"}),
    # Who besides the approvers may read WARDEN's records (records.py): only the page that shows them reads it.
    "WARDEN_RECORD_VIEWERS": frozenset({"lambda-approval"}),
    # Datadog's read keys: the read zone's worker reads evidence with them, and the webhook's Lambda asks with them
    # whether a monitor is alerting (webhooks.datadog_alerting). The test stack's agent sends with a key of its own.
    "WARDEN_DATADOG_API_KEY": frozenset({"worker", "lambda-alertmanager"}),
    "WARDEN_DATADOG_APP_KEY": frozenset({"worker", "lambda-alertmanager"}),
    "WARDEN_DATADOG_WEBHOOK_TOKEN": frozenset({"lambda-alertmanager"}),
}


# The loadable names that are secrets (decision D5): read from Secrets Manager only, never from SSM. One line per
# service, each service's webhooks before its tokens (Sonar secrets:S7314, 2026-10-16, took a webhook's name written
# after a token's for a PagerDuty token).
SECRETS = frozenset({
    "WARDEN_SLACK_WEBHOOK", "WARDEN_SLACK_BOT_TOKEN", "WARDEN_SLACK_APP_TOKEN", "WARDEN_SLACK_CLIENT_SECRET",
    "WARDEN_TEAMS_WEBHOOK", "WARDEN_WEBHOOK_URL", "WARDEN_PAGERDUTY_ROUTING_KEY",
    "WARDEN_DB_DSN", "WARDEN_DB_TERMINATE_DSN", "WARDEN_STACK_DB_PRIMARY_RO_DSN", "WARDEN_STACK_DB_REPLICA_RO_DSN",
    "WARDEN_AUDIT_DSN", "WARDEN_AUDIT_KEY_PASSPHRASE",
    "GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "WARDEN_TEMPORAL_KEY", "WARDEN_TEMPORAL_KEY_PREVIOUS", "WARDEN_TEMPORAL_API_KEY",
    "WARDEN_GITHUB_TOKEN",
    "WARDEN_ALERTMANAGER_TOKEN", "WARDEN_ALERTMANAGER_TOKEN_PREVIOUS",
    "WARDEN_DATADOG_WEBHOOK_TOKEN", "WARDEN_DATADOG_API_KEY", "WARDEN_DATADOG_APP_KEY",
})


# Register S15: what each trust zone's worker reads in WARDEN's own cloud runtime - and so the only secrets its task
# role may read, and the only slots terraform/modules/warden-runtime makes (secrets.tf, iam.tf). Every zone holds the
# payload codec key and its own Temporal service account's key. The audit's address is the module's own setting
# (WARDEN_AUDIT_DSN, compute.tf) and the cloud signs with KMS, so neither is a secret there. A secret the code can load
# but no zone uses (another model's key, Teams, PagerDuty, a rotation's previous key) has no slot until it is used:
# add it here and to secrets.tf and iam.tf together (secrets audit, 2026-10-16: 14 slots never set or read).
_EVERY_ZONE = frozenset({"WARDEN_TEMPORAL_KEY", "WARDEN_TEMPORAL_API_KEY"})
ZONE_SECRETS: dict[str, frozenset[str]] = {
    "core": _EVERY_ZONE,
    "read": _EVERY_ZONE | {"WARDEN_STACK_DB_PRIMARY_RO_DSN", "WARDEN_STACK_DB_REPLICA_RO_DSN",
                           "WARDEN_DATADOG_API_KEY", "WARDEN_DATADOG_APP_KEY"},
    "llm": _EVERY_ZONE | {"ANTHROPIC_API_KEY"},
    # GitHub: the change-record issue `finish` writes (changes.py) and the deploys `notify` reads into the report
    # (timeline.recent) - both notify-zone activities (workflows.ZONES).
    "notify": _EVERY_ZONE | {"WARDEN_SLACK_WEBHOOK", "WARDEN_SLACK_BOT_TOKEN", "WARDEN_SLACK_APP_TOKEN",
                             "WARDEN_GITHUB_TOKEN"},
    "act": _EVERY_ZONE,
}
# The runtime's Lambdas (lambdas.py), each with a role of its own that reads exactly these (iam.tf front_door_access;
# tests/test_runtime_module_g6.py runs each handler's load and holds the two together). Every one but actor-use reaches
# Temporal (runtime.connect: the codec key and its API key); the webhook Lambda checks Datadog's bearer secret and asks
# Datadog whether the monitor is alerting; the approval page signs in with Slack. actor-use reads the audit only.
LAMBDA_SECRETS: dict[str, frozenset[str]] = {
    "alarm": frozenset({"WARDEN_TEMPORAL_KEY", "WARDEN_TEMPORAL_API_KEY"}),
    "alertmanager": frozenset({"WARDEN_TEMPORAL_KEY", "WARDEN_TEMPORAL_API_KEY", "WARDEN_DATADOG_WEBHOOK_TOKEN",
                               "WARDEN_DATADOG_API_KEY", "WARDEN_DATADOG_APP_KEY"}),
    "approval": frozenset({"WARDEN_TEMPORAL_KEY", "WARDEN_TEMPORAL_API_KEY", "WARDEN_SLACK_CLIENT_SECRET"}),
    "actor-use": frozenset(),
}
# One per zone: each zone's own Temporal Cloud service account, so Temporal's audit log names the zone that called.
PER_ZONE = frozenset({"WARDEN_TEMPORAL_API_KEY"})


def secret_id(env: str, name: str, zone: str | None = None) -> str:
    """`warden/<env>/<name>`: WARDEN_SLACK_WEBHOOK -> warden/<env>/slack-webhook, GEMINI_API_KEY -> .../gemini-api-key;
    a PER_ZONE name read by one zone's worker gets the zone: warden/<env>/temporal-api-key-read; a RENAMED name keeps
    its old slot (_SLOT)."""
    slug = _SLOT.get(name) or name.lower().removeprefix("warden_").replace("_", "-")
    return f"warden/{names(env).env}/{slug}" + (f"-{zone}" if name in PER_ZONE and zone in ZONE_SECRETS else "")


def load(env: str | None = None, *, only: frozenset[str] | None = None, ssm: Any = None,
         secrets: Any = None, zone: str | None = None) -> list[str]:
    """Plain values from SSM and secrets from Secrets Manager, for the names `only` allows; the NAMES loaded. `zone`:
    the trust zone a worker serves, whose own Temporal key it reads (S15)."""
    env = env if env is not None else os.environ.get("WARDEN_ENV")
    if not env:
        return []
    allowed = LOADABLE if only is None else LOADABLE & only
    loaded = load_from_ssm(env, client=ssm, only=allowed)
    # A renamed secret set under its old name is a real environment variable too, and wins over the store.
    wanted = sorted(n for n in SECRETS & allowed if n not in os.environ and _OLD_NAME.get(n, n) not in os.environ)
    if wanted and secrets is None:
        import boto3  # only when an environment is actually named

        secrets = boto3.client("secretsmanager")
    def fetch(name: str) -> Any:
        try:
            return secrets.get_secret_value(SecretId=secret_id(env, name, zone))
        except Exception as exc:  # a secret this environment does not have is simply not loaded; others raise
            if _code(exc) == "ResourceNotFoundException":
                return None
            raise

    if wanted:
        from concurrent.futures import ThreadPoolExecutor

        # Fetched at the same time, not one after another: five in a row were 1.3 s of the approval page's cold
        # start (measured 2026-10-14). Each is still its own call under the caller's own permission, and a failure
        # of any still raises - `map` hands the results back in order and re-raises the first error it meets.
        with ThreadPoolExecutor(max_workers=min(8, len(wanted))) as pool:
            values = list(pool.map(fetch, wanted))
        for name, value in zip(wanted, values, strict=True):
            if value is not None and isinstance(value.get("SecretString"), str):
                os.environ[name] = value["SecretString"]
                loaded.append(name)
    return sorted(loaded)


def getenv(name: str) -> str:
    """The environment's value of `name` - or, for one release, of its pre-2026-10-16 name (RENAMED), with a WARNING
    that names the new one. "" when neither is set."""
    value = os.environ.get(name, "")
    old = _OLD_NAME.get(name)
    if not value and old and os.environ.get(old):
        logging.getLogger("warden.settings").warning(
            "%s is deprecated: set %s instead (renamed 2026-10-16; the old name stops being read in the next release)",
            old, name)
        value = os.environ[old]
    return value


# A Slack channel's id (a public channel C..., a private one G...), as discuss.Turn holds it.
SLACK_CHANNEL = r"[CG][A-Z0-9]{6,20}"


def by_environment(name: str, shape: str = SLACK_CHANNEL) -> dict[str, str]:
    """The setting `name` as {environment: value}, from `env=value[,env=value]`; {} when it is not set. Strict, as it
    routes one environment's incidents: each environment an application one of environments.yaml, named once, each
    value of `shape` and no value shared by two environments. Anything else raises ValueError, so a worker given a
    bad map refuses to start and never sends to a guess."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return {}
    known = default_environment_policies().known_environments
    out: dict[str, str] = {}
    for pair in raw.split(","):
        env, sep, value = (part.strip() for part in pair.partition("="))
        if not sep or env not in known or env in out or not re.fullmatch(shape, value) or value in out.values():
            raise ValueError(f"{name}: {pair.strip()!r} is not one `environment=id` pair for a distinct id, each "
                             f"environment once, from {', '.join(known)}")
        out[env] = value
    return out


def _code(exc: Exception) -> str:
    return str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))


def loadable_for(command: str, zone: str | None = None) -> frozenset[str]:
    """The names a command may load: every LOADABLE one, less the restricted ones it does not use - and for one trust
    zone's worker, less every secret another zone holds (S15)."""
    allowed = frozenset(n for n in LOADABLE if command in RESTRICTED.get(n, (command,)))
    if command.startswith("lambda-"):
        allowed -= SECRETS - LAMBDA_SECRETS.get(command.removeprefix("lambda-"), frozenset())
    return allowed - (SECRETS - ZONE_SECRETS[zone]) if zone in ZONE_SECRETS else allowed


def load_from_ssm(env: str | None = None, *, client: Any = None, only: frozenset[str] | None = None) -> list[str]:
    """Load this environment's plain values into os.environ; return the NAMES loaded, never values. `only`: the
    names this process may load (loadable_for); every LOADABLE one when not given. Secrets are not read here."""
    allowed = (LOADABLE if only is None else LOADABLE & only) - SECRETS
    env = env if env is not None else os.environ.get("WARDEN_ENV")
    if not env:
        return []
    root = names(env).ssm + "env/"
    if client is None:
        import boto3  # only when an environment is actually named

        client = boto3.client("ssm")
    loaded: list[str] = []
    for page in client.get_paginator("get_parameters_by_path").paginate(
            Path=root, Recursive=False, WithDecryption=True):
        for param in page.get("Parameters", []):
            name = param["Name"][len(root):]
            if name in allowed and name not in os.environ:
                os.environ[name] = param["Value"]
                loaded.append(name)
    return sorted(loaded)
