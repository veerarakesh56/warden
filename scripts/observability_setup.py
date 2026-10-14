"""Make WARDEN's narrow Datadog and Grafana Cloud credentials from the owner's admin ones, and store every secret and
setting in AWS.

    python scripts/observability_setup.py --env ops --stack dev --site ap1.datadoghq.com

Reads three local files the owner saved (~/.warden, or --keys-dir): datadog-api-key.txt (the API key),
datadog-app-key.txt (an unrestricted application key, used only here) and grafana-admin-token.txt (a Grafana Cloud
access-policy token on the org with accesspolicies:read/write/delete and stacks:read). Then, every step safe to run
again - each object found by its name, a new key replacing the old, never a second one beside it:

- Datadog: a new application key `warden-read` with read scopes only (SCOPES), stored, then the older ones of that
  name deleted (a key's value is shown only when it is made, so it is replaced, not reused). The API key and the
  scoped key go in `warden/<env>/datadog-api-key` and `-app-key`; the API key also in the persistent
  `warden-<stack>-datadog-api-key` the test stack's agent reads; the site in both environments' settings.
- Grafana Cloud: policies `warden-read` and `warden-write` on the org's one stack, a new 90-day token on each, stored,
  then the older tokens deleted. The read token and the Loki, Tempo and Prometheus addresses and users for the
  runtime; `<stack id>:<write token>` and the OTLP address for the test stack's collector.
- X-Ray and the deploy commits as evidence (WARDEN_XRAY=1, WARDEN_COMMITS=1).

Prints names and what happened to them, never a key or token. Revoke the admin keys after.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "scripts")]

from datadog_setup import Datadog

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
# Grafana Cloud's API, read 2026-10-14 (https://grafana.com/docs/grafana-cloud/developer-resources/api-reference/
# cloud-api/): /api/v1/accesspolicies and /api/v1/tokens, each with the `region` query parameter (where the stack
# runs, its regionSlug); a list answers {"items": [...]}; a new token's value is `token`, in that answer only.
# Stacks: /api/instances ({"items": [...]}) and /api/instances/<slug>/connections (its `otlpHttpUrl`).
GRAFANA = "https://grafana.com/api"
POLICIES = {"warden-read": ["metrics:read", "logs:read", "traces:read"],
            "warden-write": ["metrics:write", "logs:write", "traces:write"]}
TOKEN_DAYS = 90


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


class Grafana:
    def __init__(self, token: str, call: Any = None) -> None:
        self.token, self._call = token, call or self._http

    def _http(self, method: str, url: str, body: dict | None) -> Any:
        req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json",
                                              "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=20) as resp:  # nosec B310 - https to grafana.com
            return json.loads(resp.read() or b"{}")

    def call(self, method: str, path: str, query: dict | None = None, body: dict | None = None) -> Any:
        return self._call(method, GRAFANA + path + (f"?{urllib.parse.urlencode(query)}" if query else ""), body)


def grafana_stack(g: Grafana) -> dict:
    stacks = g.call("GET", "/instances").get("items") or []
    if len(stacks) != 1:
        raise SystemExit(f"the Grafana token's org has {len(stacks)} stacks; this script expects exactly one")
    return stacks[0]


def grafana_token(g: Grafana, stack: dict, name: str, scopes: list[str], now: datetime) -> tuple[str, str, str, str]:
    """The policy made, or brought to `scopes` on the stack, and a new token on it. Returns (what happened to the
    policy, the token, the policy id, the token id); the older tokens go once it is stored (grafana_retire)."""
    region = {"region": stack["regionSlug"]}
    body = {"scopes": scopes, "realms": [{"type": "stack", "identifier": str(stack["id"]), "labelPolicies": []}]}
    found = [p for p in g.call("GET", "/v1/accesspolicies", {**region, "name": name}).get("items") or []
             if p.get("name") == name]
    if found:
        pid = found[0]["id"]
        g.call("POST", f"/v1/accesspolicies/{pid}", region, {"displayName": name, **body})
        what = "updated"
    else:
        pid = g.call("POST", "/v1/accesspolicies", region, {"name": name, "displayName": name, **body})["id"]
        what = "created"
    stamp = now.strftime("%Y%m%d%H%M%S")
    made = g.call("POST", "/v1/tokens", region, {
        "accessPolicyId": pid, "name": f"{name}-{stamp}", "displayName": f"{name} {stamp}",
        "expiresAt": (now + timedelta(days=TOKEN_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")})
    return what, made["token"], pid, made["id"]


def grafana_retire(g: Grafana, stack: dict, pid: str, keep: str) -> int:
    region = {"region": stack["regionSlug"]}
    old = [t["id"] for t in g.call("GET", "/v1/tokens", {**region, "accessPolicyId": pid}).get("items") or []
           if t["id"] != keep]
    for tid in old:
        g.call("DELETE", f"/v1/tokens/{tid}", region)
    return len(old)


def grafana_urls(g: Grafana, stack: dict) -> dict[str, str]:
    """The read addresses as grafana.py joins them: Prometheus' query API under /api/prom (its remote write is
    /api/prom/push), Loki at its root (/loki/api/v1/...), Tempo under /tempo (Grafana Cloud's Tempo data source
    address). The OTLP gateway from the stack's connections, else its documented pattern, with /otlp: the collector's
    otlphttp exporter adds /v1/traces, /v1/metrics, /v1/logs."""
    tempo = stack["htInstanceUrl"].rstrip("/")
    try:
        otlp = (g.call("GET", f"/instances/{stack['slug']}/connections").get("otlpHttpUrl") or "").rstrip("/")
    except Exception:  # noqa: BLE001 - the connections read is a convenience; the pattern is the fallback
        otlp = ""
    otlp = otlp or f"https://otlp-gateway-{stack['regionSlug']}.grafana.net"
    return {"METRICS_URL": stack["hmInstancePromUrl"].rstrip("/") + "/api/prom",
            "METRICS_USER": str(stack["hmInstancePromId"]),
            "LOGS_URL": stack["hlInstanceUrl"].rstrip("/"), "LOGS_USER": str(stack["hlInstanceId"]),
            "TRACES_URL": tempo if tempo.endswith("/tempo") else tempo + "/tempo",
            "TRACES_USER": str(stack["htInstanceId"]),
            "otlp": otlp if otlp.endswith("/otlp") else otlp + "/otlp"}


def _read(path: pathlib.Path) -> str:
    value = path.read_text(encoding="utf-8-sig").strip()
    if not value:
        raise SystemExit(f"{path} is empty")
    return value


def main(argv: list[str] | None = None, *, aws: Any = None, dd_call: Any = None, grafana_call: Any = None,
         now: datetime | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--env", required=True, help="the runtime's environment (its secrets and settings)")
    p.add_argument("--stack", required=True, help="the watched test environment (its persistent secrets)")
    p.add_argument("--site", required=True, help="the Datadog site, e.g. the one in the account's address")
    p.add_argument("--region", help="the AWS region (default: the profile's)")
    p.add_argument("--keys-dir", default=str(pathlib.Path.home() / ".warden"), help="where the admin key files are")
    args = p.parse_args(argv)
    keys = pathlib.Path(args.keys_dir)
    dd = Datadog(args.site, _read(keys / "datadog-api-key.txt"), _read(keys / "datadog-app-key.txt"), dd_call)
    g = Grafana(_read(keys / "grafana-admin-token.txt"), grafana_call)
    if aws is None:
        import boto3

        def aws(service: str) -> Any:
            return boto3.client(service, region_name=args.region)
    store, env, stack, now = Store(aws), args.env, args.stack, now or datetime.now(UTC)

    # Datadog. Each new key or token is stored before the old ones go: a failed run leaves a working one stored.
    api_key = dd.keys[0]
    app_key, old = datadog_key(dd)
    store.slot(f"warden/{env}/datadog-app-key", app_key)
    for kid in old:
        dd.call("DELETE", f"/api/v2/current_user/application_keys/{kid}")
    print(f"datadog application key {NAME}: made with {', '.join(SCOPES)}; {len(old)} older deleted")
    store.slot(f"warden/{env}/datadog-api-key", api_key)
    store.secret(f"warden-{stack}-datadog-api-key", api_key, stack)
    store.param(f"/warden/{env}/env/WARDEN_DATADOG_SITE", args.site, env)
    store.param(f"/warden/{stack}/tf/datadog_site", args.site, stack)

    # Grafana Cloud.
    gs = grafana_stack(g)
    urls = grafana_urls(g, gs)
    made = {name: grafana_token(g, gs, name, scopes, now) for name, scopes in POLICIES.items()}
    store.slot(f"warden/{env}/grafana-read-token", made["warden-read"][1])
    store.secret(f"warden-{stack}-grafana-otlp-auth", f"{gs['id']}:{made['warden-write'][1]}", stack)
    for name, (what, _, pid, tid) in made.items():
        print(f"grafana access policy {name}: {what}; new token, {grafana_retire(g, gs, pid, tid)} older deleted")
    for k, v in urls.items():
        if k != "otlp":
            store.param(f"/warden/{env}/env/WARDEN_GRAFANA_{k}", v, env)
    store.param(f"/warden/{stack}/tf/grafana_otlp_url", urls["otlp"], stack)

    # X-Ray and the deploy commits: no keys, only switched on.
    store.param(f"/warden/{env}/env/WARDEN_XRAY", "1", env)
    store.param(f"/warden/{env}/env/WARDEN_COMMITS", "1", env)

    for line in store.done:
        print(line)
    print("Restart the runtime (runtime.yml restart) so the workers read the new values; then revoke the admin keys.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
