"""warden-pg-fs-order-processor - SQS warden-pg-fs-orders -> INSERT into Aurora (writer).

In the VPC, out through the NAT gateway to Aurora's internet access gateway. DB_HOST from the
environment (fs-14/fs-15 repoint it); empty means the host in the metadata secret SECRET_ARN.
No password: the function's role signs an IAM token as DB_USER (rds-db:connect), reused for 9 of
its 15 minutes.

An unparseable message is logged with its traceback and reported as a batch item failure, so it
alone is retried and, after maxReceiveCount, lands in the DLQ (fs-06). A database error fails the
whole batch: it is not the message's fault.
"""
import functools
import json
import logging
import os
import time

import boto3
import psycopg

log = logging.getLogger()
log.setLevel(logging.INFO)

SECRETS = boto3.client("secretsmanager")
RDS = boto3.client("rds")
TOKEN_REUSE_S = 540  # an IAM token is valid for 15 min; never hand out one older than 9
_tokens: dict[tuple[str, str], tuple[str, float]] = {}


def _parse(raw):
    order = json.loads(raw)
    return {"order_id": str(order["order_id"]), "cart_id": str(order["cart_id"]),
            "customer_id": str(order["customer_id"]), "sku": str(order["sku"]), "qty": int(order["qty"])}


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


def _connect():
    host = os.environ.get("DB_HOST") or _meta()["host"]
    user = os.environ.get("DB_USER", "app")
    return psycopg.connect(host=host, dbname=os.environ.get("DB_NAME", "shop"), user=user,
                           password=_token(host, user), port=5432, connect_timeout=5, sslmode="require")


def handler(event, context):
    orders, failures = [], []
    for record in event.get("Records", []):
        try:
            orders.append(_parse(record["body"]))
        except (ValueError, KeyError, TypeError):
            log.exception("unparseable order message id=%s", record.get("messageId"))
            failures.append({"itemIdentifier": record["messageId"]})

    if orders:
        with _connect() as conn:
            for o in orders:
                conn.execute("INSERT INTO orders (order_id, cart_id, customer_id, sku, qty) "
                             "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (order_id) DO NOTHING",
                             (o["order_id"], o["cart_id"], o["customer_id"], o["sku"], o["qty"]))
    log.info("processed orders=%d rejected=%d", len(orders), len(failures))
    return {"batchItemFailures": failures}
