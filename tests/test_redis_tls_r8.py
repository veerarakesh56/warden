"""Register R8-O2: the proving ground's Redis takes TLS in transit as well as at rest, and every client of it in the
benchmark apps connects with TLS - a server that requires TLS refuses a plain client, so the two move together."""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_redis_takes_tls_in_transit_and_every_app_client_uses_it():
    data = (ROOT / "terraform" / "fullstack" / "data.tf").read_text(encoding="utf-8")
    group = data[data.index('resource "aws_elasticache_replication_group" "redis"'):]
    group = group[:group.index("\n}\n")]
    assert re.search(r"transit_encryption_enabled = true\b", group) and re.search(r"at_rest_encryption_enabled = true\b", group)
    clients = [(p, line) for p in (ROOT / "scenarios" / "fullstack").rglob("*.py")
               for line in p.read_text(encoding="utf-8").splitlines() if "redis.Redis(" in line]
    assert len(clients) >= 3, clients
    assert all("ssl=True" in line for _, line in clients), [str(p) for p, line in clients if "ssl=True" not in line]
