"""Set Datadog up for WARDEN, as code (owner, 2026-10-14: "set the total ... logs traces monitoring and dashboards ...
and also alerts too for warden to see and immediately work on them").

    python scripts/datadog_setup.py --env ops --stack dev

In one run, and again idempotently - every object is found by its name and updated, never duplicated:
- the `warden` webhook: Datadog POSTs WARDEN's payload template (webhooks.DATADOG_PAYLOAD) to the approval domain's
  `/datadog`, with a bearer token made here, stored in `warden/<env>/datadog-webhook-token` in the same step, and
  never printed;
- monitors on the test stack's cluster - each app's error logs, container restarts, unavailable replicas - each
  notifying `@webhook-warden`;
- a dashboard of the same signals.

Keys: asked for, never read from a file by default - the API key, then an application key that may write the webhook
integration, monitors and dashboards (used only here: revoke it after). Each is typed at a prompt that does not echo
it, or given one per line on stdin (piped from a secret manager). WARDEN_DATADOG_API_KEY_FILE and
WARDEN_DATADOG_SETUP_KEY_FILE still name plaintext files for one release, read with a warning (2026-10-16: the
defaults ~/.warden/datadog-*.txt were plaintext admin keys on disk). The site and the approval domain come from the
environment's plain settings. Nothing secret is printed.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from warden import web
from warden.datadog import SITES
from warden.webhooks import DATADOG_PAYLOAD

WEBHOOK = "warden"
TAG = "managed-by:warden"
APPS = ("catalog-api", "cart-worker")


def credential(label: str, file: str | os.PathLike[str] | None = None) -> str:
    """One credential a setup script needs: typed at a prompt that does not echo it, or one line on stdin when stdin
    is not a terminal (piped from a secret manager). A file is read only when one is named, with a warning (naming
    audit item 24, 2026-10-16: an admin token saved in ~/.warden/*.txt outlived the "revoke after" step whenever that
    step was forgotten)."""
    if file:
        path = pathlib.Path(file)
        print(f"WARNING: {label} is read from the plaintext file {path}; delete the file once the key is revoked, and "
              "next time paste the key at the prompt instead (a file is read only until the next release)",
              file=sys.stderr)
        value = path.read_text(encoding="utf-8-sig").strip()
    elif sys.stdin.isatty():
        import getpass

        value = getpass.getpass(f"{label} (not shown as you type): ").strip()
    else:
        value = sys.stdin.readline().strip()
    if not value:
        raise SystemExit(f"{label} was not given: nothing was changed")
    return value


def monitors(stack: str) -> list[dict[str, Any]]:
    """The monitors WARDEN watches on the test stack: each names its service and environment in tags the webhook
    carries (webhooks._DD_LABELS)."""
    note = (f"{{{{#is_alert}}}}WARDEN is diagnosing this.{{{{/is_alert}}}} @webhook-{WEBHOOK}")
    out = [{"name": f"warden {stack}: {app} error logs", "type": "log alert",
            "query": f'logs("service:{app} status:error env:{stack}").index("*").rollup("count").last("5m") > 10',
            "message": note, "tags": [TAG, f"env:{stack}", f"service:{app}"], "priority": 2,
            "options": {"notify_no_data": False, "include_tags": True}} for app in APPS]
    out.append({"name": f"warden {stack}: container restarts", "type": "query alert",
                # Grouped by the cluster and namespace too: an alert then names the cluster WARDEN signs in to
                # (webhooks' kube_cluster_name -> eks_cluster), not only the workload (2026-10-15).
                "query": f"change(max(last_5m),last_5m):sum:kubernetes.containers.restarts{{kube_namespace:shop,"
                         f"env:{stack}}} by {{kube_cluster_name,kube_namespace,kube_deployment,service}} > 0",
                "message": note, "tags": [TAG, f"env:{stack}"], "priority": 2,
                "options": {"notify_no_data": False, "include_tags": True}})
    out.append({"name": f"warden {stack}: unavailable replicas", "type": "query alert",
                "query": f"max(last_5m):max:kubernetes_state.deployment.replicas_unavailable{{kube_namespace:shop,"
                         f"env:{stack}}} by {{kube_cluster_name,kube_namespace,kube_deployment,service}} > 0",
                "message": note, "tags": [TAG, f"env:{stack}"], "priority": 2,
                "options": {"notify_no_data": False, "include_tags": True}})
    return out


def dashboard(stack: str) -> dict[str, Any]:
    def graph(title: str, query: str) -> dict:
        return {"definition": {"type": "timeseries", "title": title, "requests": [{"q": query, "display_type": "line"}]}}

    return {"title": f"WARDEN {stack}: the test stack", "layout_type": "ordered", "tags": [],
            "description": "Made by scripts/datadog_setup.py - the signals WARDEN's monitors watch.",
            "widgets": [graph("Container restarts", f"sum:kubernetes.containers.restarts{{kube_namespace:shop,env:{stack}}}"
                                                     " by {kube_deployment}"),
                        graph("Unavailable replicas", "max:kubernetes_state.deployment.replicas_unavailable"
                                                      f"{{kube_namespace:shop,env:{stack}}} by {{kube_deployment}}"),
                        graph("CPU by deployment", f"avg:kubernetes.cpu.usage.total{{kube_namespace:shop,env:{stack}}}"
                                                   " by {kube_deployment}"),
                        graph("Memory by deployment", "avg:kubernetes.memory.usage"
                                                      f"{{kube_namespace:shop,env:{stack}}} by {{kube_deployment}}")]}


class Datadog:
    def __init__(self, site: str, api_key: str, app_key: str, call: Any = None) -> None:
        if site not in SITES:
            raise SystemExit(f"{site!r} is not one of Datadog's sites")
        self.base, self.keys = f"https://api.{site}", (api_key, app_key)
        self._call = call or self._http

    def _http(self, method: str, url: str, body: dict | None) -> Any:
        req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"DD-API-KEY": self.keys[0], "DD-APPLICATION-KEY": self.keys[1],
                                              "Content-Type": "application/json", "Accept": "application/json"})
        with web.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read() or b"{}")

    def call(self, method: str, path: str, body: dict | None = None) -> Any:
        return self._call(method, self.base + path, body)


def ensure_webhook(dd: Datadog, url: str, token: str) -> str:
    body = {"name": WEBHOOK, "url": url, "payload": json.dumps(DATADOG_PAYLOAD), "encode_as": "json",
            "custom_headers": json.dumps({"Authorization": f"Bearer {token}"})}
    try:
        dd.call("GET", f"/api/v1/integration/webhooks/configuration/webhooks/{WEBHOOK}")
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
        dd.call("POST", "/api/v1/integration/webhooks/configuration/webhooks", body)
        return "created"
    dd.call("PUT", f"/api/v1/integration/webhooks/configuration/webhooks/{WEBHOOK}",
            {k: v for k, v in body.items() if k != "name"})
    return "updated"


def ensure_monitors(dd: Datadog, stack: str) -> list[str]:
    done = []
    for m in monitors(stack):
        found = [x for x in dd.call("GET", "/api/v1/monitor?" + urllib.parse.urlencode({"name": m["name"]})) or []
                 if x.get("name") == m["name"]]
        if found:
            dd.call("PUT", f"/api/v1/monitor/{found[0]['id']}", m)
            done.append(f"updated {m['name']}")
        else:
            dd.call("POST", "/api/v1/monitor", m)
            done.append(f"created {m['name']}")
    return done


def ensure_dashboard(dd: Datadog, stack: str) -> str:
    board = dashboard(stack)
    listed = dd.call("GET", "/api/v1/dashboard").get("dashboards") or []
    same = [d for d in listed if d.get("title") == board["title"]]
    if same:
        dd.call("PUT", f"/api/v1/dashboard/{same[0]['id']}", board)
        return "updated"
    dd.call("POST", "/api/v1/dashboard", board)
    return "created"


def main(argv: list[str] | None = None, *, aws: Any = None, call: Any = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--env", required=True, help="the runtime's environment (its secrets and settings)")
    p.add_argument("--stack", required=True, help="the watched environment the monitors are for")
    p.add_argument("--domain", default="", help="the approval domain, where the setting is not in Parameter Store")
    p.add_argument("--monitors-only", action="store_true",
                   help="update the monitors alone: the webhook and its token are left as they are (a new token would "
                        "be refused by a warm webhook Lambda until it restarts)")
    args = p.parse_args(argv)
    if aws is None:
        import boto3

        aws = boto3.client
    sm, ssm = aws("secretsmanager"), aws("ssm")
    env = args.env
    site = ssm.get_parameter(Name=f"/warden/{env}/env/WARDEN_DATADOG_SITE")["Parameter"]["Value"].strip()
    domain = ""
    if not args.monitors_only:
        domain = args.domain.strip() or ssm.get_parameter(
            Name=f"/warden/{env}/env/WARDEN_APPROVAL_RP_ID")["Parameter"]["Value"].strip()
        if not re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", domain):
            raise SystemExit(f"{domain!r} is not a domain name")
    # Both keys from the person running this: the operator may store secrets, never read them back.
    api_key = credential("the Datadog API key", os.environ.get("WARDEN_DATADOG_API_KEY_FILE"))
    app_key = credential("the Datadog application key that may write the webhook, monitors and dashboards",
                         os.environ.get("WARDEN_DATADOG_SETUP_KEY_FILE"))
    dd = Datadog(site, api_key, app_key, call)
    if args.monitors_only:
        for line in ensure_monitors(dd, args.stack):
            print(f"monitor {line}")
        return 0
    token = secrets.token_urlsafe(32)
    # The token is stored before the webhook carries it: a webhook that sends a token WARDEN does not hold is refused.
    sm.put_secret_value(SecretId=f"warden/{env}/datadog-webhook-token", SecretString=token)
    print(f"webhook {WEBHOOK}: {ensure_webhook(dd, f'https://{domain}/datadog', token)}")
    for line in ensure_monitors(dd, args.stack):
        print(f"monitor {line}")
    print(f"dashboard: {ensure_dashboard(dd, args.stack)}")
    print("The webhook Lambda reads the new token on its next cold start; redeploy (runtime.yml restart) to be sure.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
