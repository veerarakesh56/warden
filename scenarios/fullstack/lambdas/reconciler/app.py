"""warden-dev-reconciler - EventBridge every 5 min. Reads the Aurora READER, records in Redis.

As user DB_USER (catalog, read-only) with an IAM token; DB_HOST empty means the `reader` endpoint
in the metadata secret SECRET_ARN.

Feature flag RECONCILER_FF_1 (set by the stack) picks the lookup: by_id (orders of the last hour plus a
primary-key lookup) or by_customer (per-customer totals for 30 customers in one statement).
"""
import functools
import json
import logging
import os
import random
import time

import boto3
import psycopg
import redis
from redis.backoff import NoBackoff
from redis.retry import Retry

log = logging.getLogger()
log.setLevel(logging.INFO)

SECRETS = boto3.client("secretsmanager")
RDS = boto3.client("rds")
TOKEN_REUSE_S = 540  # an IAM token is valid for 15 min; never hand out one older than 9
_tokens: dict[tuple[str, str], tuple[str, float]] = {}

BY_CUSTOMER = """
SELECT c.customer_id,
       (SELECT count(*) FROM orders o WHERE o.customer_id = c.customer_id) AS orders
FROM unnest(%s::text[]) AS c(customer_id)
"""


@functools.cache
def _meta():
    return json.loads(SECRETS.get_secret_value(SecretId=os.environ["SECRET_ARN"])["SecretString"])

# The load picks (which customer or order id to look up) come from the operating system's CSPRNG (Sonar python:S2245):
# never seeded, so nothing can replay or predict them, and nothing here needs them reproducible.
_RNG = random.SystemRandom()


def _token(host, user):
    hit = _tokens.get((host, user))
    if hit and time.monotonic() - hit[1] < TOKEN_REUSE_S:
        return hit[0]
    token = RDS.generate_db_auth_token(DBHostname=host, Port=5432, DBUsername=user, Region=RDS.meta.region_name)
    _tokens[(host, user)] = (token, time.monotonic())
    return token


def handler(event, context):
    lookup = os.environ.get("RECONCILER_FF_1", "by_id")
    host = os.environ.get("DB_HOST") or _meta()["reader"]
    user = os.environ["DB_USER"]  # named for the environment (warden_<env>_catalog); no default
    with psycopg.connect(host=host, dbname=os.environ.get("DB_NAME", "shop"), user=user,
                         password=_token(host, user), port=5432, connect_timeout=5, sslmode="require",
                         application_name="reconciler") as conn:
        count = conn.execute(
            "SELECT count(*) FROM orders WHERE created_at > now() - interval '1 hour'").fetchone()[0]
        if lookup == "by_customer":
            customers = [f"cust-{_RNG.randint(1, 50000)}" for _ in range(30)]
            checked = len(conn.execute(BY_CUSTOMER, (customers,)).fetchall())
        else:
            checked = len(conn.execute("SELECT order_id FROM orders WHERE order_id = ANY(%s)",
                                       ([f"seed-{_RNG.randint(1, 3000000)}" for _ in range(30)],)).fetchall())
    # Every option set, not left to redis-py's defaults (8.0: RESP3, 10 retries with backoff, keepalive, 5 s
    # timeouts): RESP2, one try, no keepalive, 3 s timeouts. TLS checks the certificate and host name.
    cache = redis.Redis(host=os.environ["REDIS_HOST"], port=6379, ssl=True, ssl_cert_reqs="required",
                        ssl_check_hostname=True, protocol=2, retry=Retry(NoBackoff(), 0), socket_keepalive=False,
                        socket_timeout=3, socket_connect_timeout=3)
    cache.set("reconcile:last", json.dumps({"at": int(time.time()), "orders_last_hour": count}), ex=3600)
    log.info("reconciled lookup=%s orders_last_hour=%d checked=%d", lookup, count, checked)
    return {"orders_last_hour": count, "checked": checked}
