"""warden-pg-fs-order-processor - SQS warden-pg-fs-orders -> INSERT into Aurora (writer).

In the VPC. DB_HOST from the environment (fs-14/fs-15 repoint it), credentials from the secret
SECRET_ARN, fetched per invocation so a rotated secret is picked up on the next batch.

An unparseable message is logged with its traceback and reported as a batch item failure, so it
alone is retried and, after maxReceiveCount, lands in the DLQ (fs-06). A database error fails the
whole batch: it is not the message's fault.
"""
import json
import logging
import os

import boto3
import psycopg

log = logging.getLogger()
log.setLevel(logging.INFO)

SECRETS = boto3.client("secretsmanager")


def _parse(raw):
    order = json.loads(raw)
    return {"order_id": str(order["order_id"]), "cart_id": str(order["cart_id"]),
            "customer_id": str(order["customer_id"]), "sku": str(order["sku"]), "qty": int(order["qty"])}


def _connect():
    creds = json.loads(SECRETS.get_secret_value(SecretId=os.environ["SECRET_ARN"])["SecretString"])
    return psycopg.connect(host=os.environ["DB_HOST"], dbname=os.environ.get("DB_NAME", "shop"),
                           user=creds["username"], password=creds["password"], port=5432,
                           connect_timeout=5, sslmode="require")


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
