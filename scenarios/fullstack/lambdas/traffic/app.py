"""warden-pg-fs-traffic - EventBridge every minute. The load generator.

Per run: CHECKOUTS_PER_MIN x POST {API_URL}/checkout, the same number of GET {ALB_URL}/orders, and
ORDERS_PER_MIN order messages onto the orders queue. Tiny payloads. Failures are logged, never
raised: the generator must keep generating while the stack is broken.
"""
import json
import logging
import os
import random
import urllib.error
import urllib.request
import uuid

import boto3

log = logging.getLogger()
log.setLevel(logging.INFO)

SQS = boto3.client("sqs")
SKUS = [f"sku-{n}" for n in range(1, 21)]


def _call(method, url, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except OSError as exc:
        log.error("%s %s failed: %s", method, url, exc)
        return 0


def handler(event, context):
    n_checkout = int(os.environ.get("CHECKOUTS_PER_MIN", "10"))
    n_orders = int(os.environ.get("ORDERS_PER_MIN", "10"))
    statuses = {"checkout": [], "orders": []}
    for _ in range(n_checkout):
        cart = f"cart-{random.randint(1, 500)}"
        payload = {"cart_id": cart, "items": [{"sku": random.choice(SKUS), "qty": random.randint(1, 3)}]}
        statuses["checkout"].append(_call("POST", os.environ["API_URL"] + "/checkout", payload))
        statuses["orders"].append(_call("GET", os.environ["ALB_URL"] + "/orders"))
    for _ in range(n_orders):
        order = {"order_id": str(uuid.uuid4()), "cart_id": f"cart-{random.randint(1, 500)}",
                 "customer_id": f"cust-{random.randint(1, 50000)}",
                 "sku": random.choice(SKUS), "qty": random.randint(1, 3)}
        SQS.send_message(QueueUrl=os.environ["ORDERS_QUEUE_URL"], MessageBody=json.dumps(order))
    bad = {k: sum(1 for s in v if not 200 <= s < 300) for k, v in statuses.items()}
    level = logging.ERROR if any(bad.values()) else logging.INFO
    log.log(level, "traffic sent checkout=%d orders_get=%d queued=%d failed=%s",
            n_checkout, n_checkout, n_orders, json.dumps(bad))
    return bad
