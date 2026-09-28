"""Per-environment secrets and account values, from SSM Parameter Store - never from a file on disk.

v2 Phase 1.5 (2026-09-27). `WARDEN_ENV=<env>` makes WARDEN read `/warden/<env>/env/<NAME>` (one
paginated call, decrypted) and set each NAME as an environment variable the rest of WARDEN already
reads. The parameters are SecureString for secrets, String for plain values; standard tier, which is
free. Access is the caller's IAM identity: in production a worker's task role, in the lab the
owner's short-lived `aws login` session. No credential is ever stored by WARDEN.

Rules:
- A real environment variable wins over SSM, which wins over the code default. Setting a value
  explicitly always takes precedence over the store.
- Only names on `LOADABLE` are loaded. Never loaded, by design: the switches that arm live actions
  (`WARDEN_REMEDIATION`, `WARDEN_CHATOPS_LIVE`, `WARDEN_MOCK`, `WARDEN_DB_DRY_RUN`) - arming stays a
  person's act on the command line - and anything that redirects where WARDEN reads or sends
  (`*_PATH`, `WARDEN_BASE_URL`, `WARDEN_PROVIDER`), so a parameter cannot re-point model traffic.
- No `WARDEN_ENV`: nothing happens and no AWS client is built. Every existing flow is unchanged.

ponytail: loaded once per process; a long-running MCP server needs a restart to see a rotated webhook.
"""

from __future__ import annotations

import os
from typing import Any

from .environments import names

LOADABLE = frozenset({
    "WARDEN_SLACK_WEBHOOK", "WARDEN_TEAMS_WEBHOOK", "WARDEN_WEBHOOK_URL",
    "WARDEN_DB_DSN", "WARDEN_DB_ADMIN_DSN", "WARDEN_STACK_DB_WRITER_DSN", "WARDEN_STACK_DB_READER_DSN",
    "GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "WARDEN_AWS_CLUSTER", "WARDEN_AWS_LOG_GROUP", "WARDEN_AWS_REGION", "WARDEN_MODEL",
    "WARDEN_AUDIT_KEY_PASSPHRASE",
})


def load_from_ssm(env: str | None = None, *, client: Any = None) -> list[str]:
    """Load this environment's parameters into os.environ; return the NAMES loaded, never values."""
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
            if name in LOADABLE and name not in os.environ:
                os.environ[name] = param["Value"]
                loaded.append(name)
    return sorted(loaded)
