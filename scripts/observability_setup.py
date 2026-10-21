"""Make WARDEN's narrow Datadog credentials from broader setup ones; store them in AWS.

    python scripts/observability_setup.py --env ops --stack dev --site ap1.datadoghq.com

Asks for three keys, in this order, each typed at a prompt that does not echo it or given one per line on stdin
(piped from a secret manager): the Datadog API key the runtime reads with; a Datadog application key that may manage
application keys (`user_app_keys`; used only here); and a second, different Datadog API key the test stack's agent
sends with. Two API keys, not one (secrets audit, 2026-10-16): the agent's key sits in the test stack's cluster, and
one leaked there must not also be the runtime's - each is revoked in Datadog without touching the other. Nothing is
read from disk (naming audit item 24, 2026-10-16: these used to be plaintext files in ~/.warden, which outlived
"revoke after" whenever that was forgotten; the deprecated --keys-dir folder of them was removed, owner B28). Then,
every step safe to run again - each object found by its name, a new key replacing the old, never a second
one beside it:

- Datadog: a new application key `warden-read` with read scopes only (SCOPES), stored, then the older ones of that
  name deleted (a key's value is shown only when it is made, so it is replaced, not reused). The runtime's API key and
  the scoped key go in `warden/<env>/datadog-api-key` and `-app-key`; the agent's API key in the persistent
  `warden-<stack>-datadog-api-key` the test stack's agent reads; the site in both environments' settings.
- X-Ray and the deploy commits as evidence (WARDEN_XRAY=1, WARDEN_COMMITS=1).

WARDEN's own runtime reads Datadog only (owner, 2026-10-16): Grafana is not set up here.
Prints names and what happened to them, never a key. Revoke the setup application key after.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
import urllib.parse
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "scripts")]

from datadog_setup import Datadog, credential

NAME = "warden-read"
# Datadog's API, read 2026-10-14: POST /api/v2/current_user/application_keys with
# {"data": {"type": "application_keys", "attributes": {"name", "scopes"}}} - the value is data.attributes.key, in that
# answer only; GET the same path with `filter` lists them, DELETE .../{id} removes one; needs `user_app_keys`.
# https://docs.datadoghq.com/api/latest/key-management/ . The scope names are Datadog's permission names
# (https://docs.datadoghq.com/account_management/rbac/permissions/ , read the same day): logs, spans, metrics, events
# and monitors (webhooks.datadog_alerting reads a monitor's state).
# logs_read_index_data beside logs_read_data: Datadog's permissions page (read 2026-10-14) says reading logs needs
# both; read-only, like the rest.
SCOPES = ("logs_read_data", "logs_read_index_data", "apm_read", "timeseries_query", "events_read", "monitors_read")


def _code(exc: Exception) -> str:
    return str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))


class Store:
    """Secrets Manager and SSM as this script writes them: put, or make and tag when missing."""

    def __init__(self, aws: Any) -> None:
        self.sm, self.ssm, self.done = aws("secretsmanager"), aws("ssm"), []

    def slot(self, name: str, value: str) -> None:  # a secret Terraform made empty: its value only
        self.sm.put_secret_value(SecretId=name, SecretString=value)
        self.done.append(f"secret {name}: updated")

    def secret(self, name: str, value: str, env: str) -> None:  # persistent: outlives the stack it serves
        try:
            self.sm.put_secret_value(SecretId=name, SecretString=value)
            self.done.append(f"secret {name}: updated")
        except Exception as exc:
            if _code(exc) != "ResourceNotFoundException":
                raise
            self.sm.create_secret(Name=name, SecretString=value, Tags=_tags(env))
            self.done.append(f"secret {name}: created")

    def param(self, name: str, value: str, env: str) -> None:
        # SSM refuses tags with Overwrite, so tags go on when it is made, and a value on its own after.
        try:
            self.ssm.put_parameter(Name=name, Value=value, Type="String", Tags=_tags(env))
            self.done.append(f"setting {name}: created")
        except Exception as exc:
            if _code(exc) != "ParameterAlreadyExists":
                raise
            self.ssm.put_parameter(Name=name, Value=value, Type="String", Overwrite=True)
            self.done.append(f"setting {name}: updated")


def _tags(env: str) -> list[dict[str, str]]:
    return [{"Key": "Project", "Value": "warden"}, {"Key": "Environment", "Value": env}]


def datadog_key(dd: Datadog) -> tuple[str, list[str]]:
    """A new `warden-read` key; returns its value and the ids of older ones still to delete (none: see below)."""
    # Datadog refuses a second key of the same name (409, live 2026-10-14), and a key whose value was never stored -
    # an earlier run that stopped half-way - can never be used: so the older ones go first, then the new one is made.
    listed = dd.call("GET", "/api/v2/current_user/application_keys?"
                     + urllib.parse.urlencode({"filter": NAME, "page[size]": 100})).get("data") or []
    for k in listed:
        if (k.get("attributes") or {}).get("name") == NAME:
            dd.call("DELETE", f"/api/v2/current_user/application_keys/{k['id']}")
    made = dd.call("POST", "/api/v2/current_user/application_keys",
                   {"data": {"type": "application_keys", "attributes": {"name": NAME, "scopes": list(SCOPES)}}})["data"]
    return made["attributes"]["key"], []


def main(argv: list[str] | None = None, *, aws: Any = None, dd_call: Any = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--env", required=True, help="the runtime's environment (its secrets and settings)")
    p.add_argument("--stack", required=True, help="the watched test environment (its persistent secrets)")
    p.add_argument("--site", required=True, help="the Datadog site, e.g. the one in the account's address")
    p.add_argument("--region", help="the AWS region (default: the profile's)")
    args = p.parse_args(argv)
    dd = Datadog(args.site, credential("the Datadog API key the runtime reads with"),
                 credential("the Datadog application key that may manage application keys (user_app_keys)"),
                 dd_call)
    agent_key = credential("a second Datadog API key, for the test stack's agent to send with")
    if agent_key == dd.keys[0]:
        raise SystemExit("the agent's Datadog API key is the runtime's: make a second API key in Datadog "
                         "(Organization Settings, API Keys) and give that one; nothing was changed")
    if aws is None:
        import boto3

        def aws(service: str) -> Any:
            return boto3.client(service, region_name=args.region)
    store, env, stack = Store(aws), args.env, args.stack

    # Each new key is stored before the old ones go: a failed run leaves a working one stored.
    api_key = dd.keys[0]
    app_key, old = datadog_key(dd)
    store.slot(f"warden/{env}/datadog-app-key", app_key)
    for kid in old:
        dd.call("DELETE", f"/api/v2/current_user/application_keys/{kid}")
    print(f"datadog application key {NAME}: made with {', '.join(SCOPES)}; {len(old)} older deleted")
    store.slot(f"warden/{env}/datadog-api-key", api_key)
    store.secret(f"warden-{stack}-datadog-api-key", agent_key, stack)
    store.param(f"/warden/{env}/env/WARDEN_DATADOG_SITE", args.site, env)
    store.param(f"/warden/{stack}/tf/datadog_site", args.site, stack)

    # X-Ray and the deploy commits: no keys, only switched on.
    store.param(f"/warden/{env}/env/WARDEN_XRAY", "1", env)
    store.param(f"/warden/{env}/env/WARDEN_COMMITS", "1", env)

    for line in store.done:
        print(line)
    print("Restart the runtime (runtime.yml restart) so the workers read the new values, and redeploy the test stack's "
          "apps so its agent sends with its own key; then revoke the Datadog application key given above.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
