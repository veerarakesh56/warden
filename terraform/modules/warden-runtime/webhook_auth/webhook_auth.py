"""The webhook routes' gate at the API Gateway (Sonar terraform:S6333, owner 2026-10-20): an HTTP API Lambda REQUEST
authorizer in front of POST /alertmanager and POST /datadog.

A request reaches the alertmanager function only if its Authorization header is `Bearer <the route's secret>`, compared
in constant time with the current secret and, during a rotation, the previous one. The function keeps its own check
(webhooks.authorized) and everything after it; this adds a layer and weakens nothing. A request with no Authorization
header is refused by the gateway before this runs (identity source). A secret this environment does not have, or one
that cannot be read, matches nothing: the gate fails closed.

Standard library and boto3 (in Lambda's Python runtime) only; no VPC, no image.
"""

import hmac
import os

import boto3
from botocore.exceptions import BotoCoreError, ClientError

# The secrets each route accepts: warden/<env>/<name>, as settings.secret_id names them.
ROUTE_SECRETS = {
    "POST /alertmanager": ("alertmanager-token", "alertmanager-token-previous"),
    "POST /datadog": ("datadog-webhook-token",),
}
_CLIENT = []


def _secret(name):
    """Read for every request, never remembered: a secret rotated out stops opening the route at once (the gateway's
    own result cache is off too, TTL 0). A webhook comes a few times an hour; the read costs a few milliseconds."""
    if not _CLIENT:
        _CLIENT.append(boto3.client("secretsmanager"))
    try:
        return _CLIENT[0].get_secret_value(SecretId=f"warden/{os.environ['WARDEN_ENV']}/{name}")["SecretString"]
    except (ClientError, BotoCoreError):  # missing, not readable or unreachable: nothing matches it
        return ""


def handler(event, context):
    names = ROUTE_SECRETS.get(event.get("routeKey"), ())
    header = (event.get("headers") or {}).get("authorization") or ""
    if not names or not header.startswith("Bearer "):
        return {"isAuthorized": False}
    given = header[len("Bearer "):].encode()
    # Every secret is compared, whatever the first gives, so the time taken says nothing about which one matched: the
    # whole list of answers is built before it is read (any() over a generator would stop at the first match).
    values = [_secret(name) for name in names]
    results = [hmac.compare_digest(given, value.encode()) for value in values if value]
    return {"isAuthorized": True in results}
