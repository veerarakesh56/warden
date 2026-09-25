"""warden-pg-fs-checkout - behind API Gateway (POST /checkout, GET /health), alias `live`.

Validates the order JSON, writes it to DynamoDB (TABLE_NAME), publishes an order event to SNS.

Fault flags (names from scenarios/ops_fullstack.py FLAGS; terraform sets the baseline values):
  CHECKOUT_PAYLOAD_SCHEMA  v1 | v2. v2 is the fs-01 regression: it reads each item's `sku_id`, a
                           field real payloads do not have, so every real checkout raises
                           KeyError: 'sku_id'. The harness publishes it as a new version + alias.
  DDB_EXTRA_LATENCY_MS     latency injected before the DynamoDB call (fs-02).
The Lambda runtime's log format already carries level + ISO timestamp; an unhandled exception is
logged with its traceback by the runtime.
"""
import json
import logging
import os
import time
import uuid

import boto3

log = logging.getLogger()
log.setLevel(logging.INFO)

TABLE = boto3.resource("dynamodb").Table(os.environ.get("TABLE_NAME", "unset"))
SNS = boto3.client("sns")


def _resp(status, body):
    return {"statusCode": status, "headers": {"Content-Type": "application/json"}, "body": json.dumps(body)}


def _valid(body):
    return (isinstance(body, dict) and isinstance(body.get("cart_id"), str)
            and isinstance(body.get("items"), list) and body["items"]
            and all(isinstance(i, dict) and isinstance(i.get("sku"), str) and isinstance(i.get("qty"), int)
                    and i["qty"] > 0 for i in body["items"]))


def _items(body):
    if os.environ.get("CHECKOUT_PAYLOAD_SCHEMA", "v1") == "v2":
        return [{"sku": item["sku_id"], "qty": item["qty"]} for item in body["items"]]
    return [{"sku": item["sku"], "qty": item["qty"]} for item in body["items"]]


def handler(event, context):
    if event.get("routeKey") == "GET /health":
        return _resp(200, {"status": "ok"})
    try:
        body = json.loads(event.get("body") or "")
    except ValueError:
        return _resp(400, {"error": "body must be JSON"})
    if not _valid(body):
        return _resp(400, {"error": "expected {cart_id: str, items: [{sku: str, qty: int > 0}]}"})

    slow_ms = int(os.environ.get("DDB_EXTRA_LATENCY_MS", "0"))
    if slow_ms:
        time.sleep(slow_ms / 1000)

    order_id = str(uuid.uuid4())
    items = _items(body)
    TABLE.put_item(Item={"cart_id": body["cart_id"], "order_id": order_id, "items": json.dumps(items),
                         "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    SNS.publish(TopicArn=os.environ["TOPIC_ARN"],
                Message=json.dumps({"order_id": order_id, "cart_id": body["cart_id"], "items": items}))
    log.info("checkout accepted order_id=%s cart_id=%s items=%d", order_id, body["cart_id"], len(items))
    return _resp(201, {"order_id": order_id})
