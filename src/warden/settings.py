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

import os
from typing import Any

from .environments import names

LOADABLE = frozenset({
    "WARDEN_SLACK_BOT_TOKEN", "WARDEN_SLACK_CHANNEL", "WARDEN_SLACK_WEBHOOK", "WARDEN_TEAMS_WEBHOOK", "WARDEN_WEBHOOK_URL",
    "WARDEN_DB_DSN", "WARDEN_DB_ADMIN_DSN", "WARDEN_STACK_DB_WRITER_DSN", "WARDEN_STACK_DB_READER_DSN",
    "GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "WARDEN_AWS_CLUSTER", "WARDEN_AWS_LOG_GROUP", "WARDEN_AWS_REGION", "WARDEN_MODEL",
    "WARDEN_AUDIT_KEY_PASSPHRASE", "WARDEN_TEMPORAL_KEY",
    "WARDEN_TEMPORAL_API_KEY", "WARDEN_TEMPORAL_ADDRESS", "WARDEN_TEMPORAL_NAMESPACE",
    "WARDEN_GITHUB_TOKEN", "WARDEN_CHANGE_REPO", "WARDEN_TEMPORAL_KEY_PREVIOUS",
    "WARDEN_HEARTBEAT_NAMESPACE", "WARDEN_AWS_READER_ROLE_ARN", "WARDEN_AWS_ACTOR_ROLE_ARN",
    "WARDEN_AUDIT_DSN",
})


# Loaded only for the commands that use them (audit A-B-L17): a diagnosis run and the MCP server have no use for the
# terminate role's DSN or the audit key's passphrase, and a process that never holds a secret cannot leak it.
RESTRICTED: dict[str, frozenset[str]] = {
    "WARDEN_DB_ADMIN_DSN": frozenset({"worker"}),
    "WARDEN_AUDIT_KEY_PASSPHRASE": frozenset({"worker", "incident", "intake", "status", "approve", "killswitch", "audit",
                                              "label"}),
    "WARDEN_TEMPORAL_KEY": frozenset({"worker", "incident", "intake", "status", "approve", "mcp"}),
    "WARDEN_TEMPORAL_API_KEY": frozenset({"worker", "incident", "intake", "status", "approve", "mcp"}),
    "WARDEN_TEMPORAL_KEY_PREVIOUS": frozenset({"worker", "incident", "intake", "status", "approve", "mcp"}),
    "WARDEN_GITHUB_TOKEN": frozenset({"worker"}),
    # Only the worker writes to AWS or beats; no other command needs to know the roles (audit A-P-5, register C13).
    "WARDEN_AWS_READER_ROLE_ARN": frozenset({"worker"}),
    "WARDEN_AWS_ACTOR_ROLE_ARN": frozenset({"worker"}),
    "WARDEN_HEARTBEAT_NAMESPACE": frozenset({"worker"}),
    # The commands that open the audit (runtime.open_audit) and the ones that read it.
    "WARDEN_AUDIT_DSN": frozenset({"worker", "incident", "intake", "status", "approve", "killswitch", "audit",
                                   "label", "usage"}),
}


# The loadable names that are secrets (decision D5): read from Secrets Manager only, never from SSM.
SECRETS = frozenset({
    "WARDEN_SLACK_BOT_TOKEN", "WARDEN_SLACK_WEBHOOK", "WARDEN_TEAMS_WEBHOOK", "WARDEN_WEBHOOK_URL",
    "WARDEN_DB_DSN", "WARDEN_DB_ADMIN_DSN", "WARDEN_STACK_DB_WRITER_DSN", "WARDEN_STACK_DB_READER_DSN",
    "GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "WARDEN_AUDIT_KEY_PASSPHRASE", "WARDEN_TEMPORAL_KEY", "WARDEN_TEMPORAL_API_KEY", "WARDEN_GITHUB_TOKEN",
    "WARDEN_TEMPORAL_KEY_PREVIOUS", "WARDEN_AUDIT_DSN",
})


def secret_id(env: str, name: str) -> str:
    """`warden/<env>/<name>`: WARDEN_SLACK_WEBHOOK -> warden/<env>/slack-webhook, GEMINI_API_KEY -> .../gemini-api-key."""
    return f"warden/{names(env).env}/" + name.lower().removeprefix("warden_").replace("_", "-")


def load(env: str | None = None, *, only: frozenset[str] | None = None, ssm: Any = None,
         secrets: Any = None) -> list[str]:
    """Plain values from SSM and secrets from Secrets Manager, for the names `only` allows; the NAMES loaded."""
    env = env if env is not None else os.environ.get("WARDEN_ENV")
    if not env:
        return []
    allowed = LOADABLE if only is None else LOADABLE & only
    loaded = load_from_ssm(env, client=ssm, only=allowed)
    wanted = sorted(n for n in SECRETS & allowed if n not in os.environ)
    if wanted and secrets is None:
        import boto3  # only when an environment is actually named

        secrets = boto3.client("secretsmanager")
    for name in wanted:
        try:
            value = secrets.get_secret_value(SecretId=secret_id(env, name))
        except Exception as exc:  # a secret this environment does not have is simply not loaded; others raise
            if _code(exc) == "ResourceNotFoundException":
                continue
            raise
        if isinstance(value.get("SecretString"), str):
            os.environ[name] = value["SecretString"]
            loaded.append(name)
    return sorted(loaded)


def _code(exc: Exception) -> str:
    return str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))


def loadable_for(command: str) -> frozenset[str]:
    """The names a command may load: every LOADABLE one, less the restricted ones it does not use."""
    return frozenset(n for n in LOADABLE if command in RESTRICTED.get(n, (command,)))


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
