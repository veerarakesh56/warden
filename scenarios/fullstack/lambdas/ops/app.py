"""warden-pg-fs-ops - in the VPC, invoked by the harness ONLY (no trigger). Redis admin commands,
because ElastiCache is unreachable from outside the VPC.

  {"op": "info"}                                      -> memory/eviction figures
  {"op": "fill", "prefix": "filler:", "mb": 400}      -> write filler keys (TTL 1 h, so volatile-lru evicts them)
  {"op": "flush_prefix", "prefix": "filler:"}         -> delete every key under the prefix

The payload is scenarios/ops_fullstack.py's ops_invoke contract.

Only prefixes starting with "filler:" are accepted: this function never deletes application keys.
"""
import logging
import os

import redis

log = logging.getLogger()
log.setLevel(logging.INFO)

CHUNK = 100 * 1024  # bytes per filler value


def _info(r):
    info = r.info()
    keys = ("used_memory", "maxmemory", "maxmemory_policy", "evicted_keys", "connected_clients")
    return {k: info.get(k) for k in keys}


def handler(event, context):
    r = redis.Redis(host=os.environ["REDIS_HOST"], port=6379, socket_timeout=10, socket_connect_timeout=5)
    cmd = event.get("op")
    prefix = event.get("prefix", "filler:")
    if cmd in ("fill", "flush_prefix") and not prefix.startswith("filler:"):
        raise ValueError(f"refusing prefix {prefix!r}: only filler:* keys may be written or deleted")

    if cmd == "info":
        return _info(r)
    if cmd == "fill":
        total = int(event.get("mb", 400)) * 1024 * 1024 // CHUNK
        value = b"x" * CHUNK
        written = 0
        try:
            for start in range(0, total, 50):
                pipe = r.pipeline(transaction=False)
                for i in range(start, min(start + 50, total)):
                    pipe.set(f"{prefix}{i}", value, ex=3600)
                pipe.execute()
                written = min(start + 50, total)
        except redis.exceptions.ResponseError:
            log.exception("fill stopped by the server after %d keys", written)
        log.info("fill prefix=%s keys=%d", prefix, written)
        return {"written": written, **_info(r)}
    if cmd == "flush_prefix":
        deleted = 0
        batch = []
        for key in r.scan_iter(match=f"{prefix}*", count=1000):
            batch.append(key)
            if len(batch) >= 500:
                deleted += r.delete(*batch)
                batch = []
        if batch:
            deleted += r.delete(*batch)
        log.info("flush prefix=%s deleted=%d", prefix, deleted)
        return {"deleted": deleted, **_info(r)}
    raise ValueError(f"unknown op {cmd!r}: expected info, fill or flush_prefix")
