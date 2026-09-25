"""The one container image of the Wave 4 stack. APP_ROLE picks what it is:

  orders-api   ECS behind the ALB. GET /orders reads the Aurora WRITER (DB_* from Secrets Manager),
               cached in Redis for 30 s. GET /health answers without touching a dependency.
  catalog-api  EKS. GET /catalog reads Redis + the Aurora READER. /health and /ready on 8080.
               Validates its config at start and exits with a clear error on a bad value (fs-22).
  cart-worker  EKS. Touches Redis in a loop; /health on 8080 for its probes.

Fault flags (env): ALLOC_MB - allocate and hold this much memory at start (fs-20).
Framework-free on purpose: http.server from the stdlib, psycopg, redis. Nothing else.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import psycopg
import redis

ROLE = os.environ.get("APP_ROLE", "orders-api")
log = logging.getLogger(ROLE)

_held: list[bytearray] = []  # fs-20: memory that is never released


def setup_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s", "%Y-%m-%dT%H:%M:%SZ")
    fmt.converter = time.gmtime
    handler.setFormatter(fmt)
    logging.basicConfig(level=logging.INFO, handlers=[handler])


def int_setting(name: str, default: int, low: int, high: int) -> int:
    """A config value from the environment (ConfigMap catalog-config on EKS). Invalid = exit."""
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError:
        value = None
    if value is None or not low <= value <= high:
        log.error("invalid configuration: %s=%r must be an integer between %d and %d; refusing to start",
                  name, raw, low, high)
        sys.exit(2)
    return value


def cache() -> redis.Redis:
    return redis.Redis(host=os.environ["REDIS_HOST"], port=6379, socket_timeout=2,
                       socket_connect_timeout=2, decode_responses=True)


def db_connect() -> psycopg.Connection:
    # A connection per request, deliberately: credentials are checked on every connect, so a
    # rotated password (fs-21) and a full pool (fs-12) show up on the next request.
    return psycopg.connect(host=os.environ["DB_HOST"], dbname=os.environ.get("DB_NAME", "shop"),
                           user=os.environ["DB_USER"], password=os.environ["DB_PASSWORD"],
                           port=int(os.environ.get("DB_PORT", "5432")), connect_timeout=5,
                           sslmode="require")


def recent_orders() -> list[dict]:
    key = "orders:recent"
    hit = cache().get(key)
    if hit is not None:
        return json.loads(hit)
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT order_id, cart_id, sku, qty FROM orders ORDER BY created_at DESC LIMIT 20").fetchall()
    orders = [{"order_id": r[0], "cart_id": r[1], "sku": r[2], "qty": r[3]} for r in rows]
    cache().set(key, json.dumps(orders), ex=30)
    return orders


def catalog(page_size: int, ttl: int) -> list[dict]:
    key = f"catalog:top:{page_size}"
    hit = cache().get(key)
    if hit is not None:
        return json.loads(hit)
    with db_connect() as conn:
        rows = conn.execute("SELECT sku, sum(qty) FROM orders GROUP BY sku ORDER BY 2 DESC LIMIT %s",
                            (page_size,)).fetchall()
    items = [{"sku": r[0], "sold": int(r[1])} for r in rows]
    cache().set(key, json.dumps(items), ex=ttl)
    return items


class Handler(BaseHTTPRequestHandler):
    routes: ClassVar[dict] = {}

    def do_GET(self) -> None:
        route = self.routes.get(self.path.split("?")[0])
        if route is None:
            return self.reply(404, {"error": "not found"})
        try:
            self.reply(200, route())
        except Exception as exc:
            log.exception("GET %s failed", self.path)
            self.reply(500, {"error": type(exc).__name__})

    def reply(self, status: int, body: object) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args) -> None:  # probes every few seconds: not worth a line
        pass


def ready() -> dict:
    cache().ping()
    return {"status": "ready"}


def cart_worker_loop(interval: int) -> None:
    n = 0
    while True:
        try:
            r = cache()
            n = r.incr("cart-worker:ticks")
            r.set("cart-worker:heartbeat", int(time.time()), ex=120)
            if n % 12 == 0:
                log.info("cart-worker alive ticks=%d", n)
        except Exception:
            log.exception("cart-worker could not reach the cache")
        time.sleep(interval)


def main() -> None:
    setup_logging()
    alloc = int_setting("ALLOC_MB", 0, 0, 65536)
    if alloc:
        log.info("allocating %d MiB working set", alloc)
        block = bytearray(alloc * 1024 * 1024)
        for i in range(0, len(block), 4096):  # touch every page, or the kernel never commits it
            block[i] = 1
        _held.append(block)

    health = {"/health": lambda: {"status": "ok", "role": ROLE}}
    if ROLE == "orders-api":
        Handler.routes = {**health, "/orders": recent_orders}
    elif ROLE == "catalog-api":
        page_size = int_setting("CATALOG_PAGE_SIZE", 20, 1, 100)
        ttl = int_setting("CATALOG_CACHE_TTL_S", 60, 1, 3600)
        Handler.routes = {**health, "/ready": ready, "/catalog": lambda: catalog(page_size, ttl)}
    elif ROLE == "cart-worker":
        interval = int_setting("CART_WORKER_INTERVAL_S", 5, 1, 300)
        threading.Thread(target=cart_worker_loop, args=(interval,), daemon=True).start()
        Handler.routes = health
    else:
        log.error("invalid configuration: APP_ROLE=%r is not orders-api, catalog-api or cart-worker", ROLE)
        sys.exit(2)

    port = int(os.environ.get("PORT", "8080"))
    log.info("%s listening on %d", ROLE, port)
    ThreadingHTTPServer(("", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
