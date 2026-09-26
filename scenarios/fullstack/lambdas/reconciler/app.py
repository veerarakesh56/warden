"""warden-pg-fs-reconciler - EventBridge every 5 min. Reads the Aurora READER, records in Redis.

As user DB_USER (catalog, read-only) with an IAM token; DB_HOST empty means the `reader` endpoint
in the metadata secret SECRET_ARN.

Fault flag RECONCILE_LOOKUP (scenarios/ops_fullstack.py FLAGS; terraform sets the baseline):
  by_id        baseline: orders of the last hour (index on created_at) + a primary-key lookup
  by_customer  fs-16: per-customer totals for 30 customers in ONE statement - one index probe each
               while orders_customer_id_idx exists, one full scan of `orders` each once it is gone
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


def _token(host, user):
    hit = _tokens.get((host, user))
    if hit and time.monotonic() - hit[1] < TOKEN_REUSE_S:
        return hit[0]
    token = RDS.generate_db_auth_token(DBHostname=host, Port=5432, DBUsername=user, Region=RDS.meta.region_name)
    _tokens[(host, user)] = (token, time.monotonic())
    return token


def handler(event, context):
    lookup = os.environ.get("RECONCILE_LOOKUP", "by_id")
    host = os.environ.get("DB_HOST") or _meta()["reader"]
    user = os.environ.get("DB_USER", "catalog")
    with psycopg.connect(host=host, dbname=os.environ.get("DB_NAME", "shop"), user=user,
                         password=_token(host, user), port=5432, connect_timeout=5, sslmode="require",
                         application_name="reconciler") as conn:
        count = conn.execute(
            "SELECT count(*) FROM orders WHERE created_at > now() - interval '1 hour'").fetchone()[0]
        if lookup == "by_customer":
            customers = [f"cust-{random.randint(1, 50000)}" for _ in range(30)]
            checked = len(conn.execute(BY_CUSTOMER, (customers,)).fetchall())
        else:
            checked = len(conn.execute("SELECT order_id FROM orders WHERE order_id = ANY(%s)",
                                       ([f"seed-{random.randint(1, 3000000)}" for _ in range(30)],)).fetchall())
    cache = redis.Redis(host=os.environ["REDIS_HOST"], port=6379, socket_timeout=3, socket_connect_timeout=3)
    cache.set("reconcile:last", json.dumps({"at": int(time.time()), "orders_last_hour": count}), ex=3600)
    log.info("reconciled lookup=%s orders_last_hour=%d checked=%d", lookup, count, checked)
    return {"orders_last_hour": count, "checked": checked}
