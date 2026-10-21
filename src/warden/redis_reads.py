"""The data inside an ElastiCache Redis (or Valkey) cache, read by WARDEN itself when it can reach it (U3-5).

Until this, the report said "Not read: the data inside the Redis cache itself": WARDEN read the cache's settings,
events and CloudWatch metrics from AWS, never the server. When the runtime is given a DSN for the cache
(WARDEN_STACK_REDIS_RO_DSN) and can reach it, the stack backend now reads three things from the server:

- INFO          memory, clients, evictions, rejected connections, the node's role and its link to its primary;
- SLOWLOG GET   the slowest recent commands, at most SLOWLOG_MAX of them;
- CLIENT LIST   how many clients there are, how many sit idle, and the longest-idle few.

⛔ READ-ONLY BY CONSTRUCTION. Every command goes through `ReadOnlyRedis.run`, which refuses anything outside ALLOWED
before a byte is sent - not a deny-list of dangerous commands, an allow-list of three. The wrapper hands out no client
and has no pass-through, so no other method of redis-py can be reached through it. The cache's own access control is
the second wall: the DSN's user should be one whose ACL allows exactly these three (see the PR's laptop steps).

⛔ QUARANTINED. A cache holds what applications put in it, and its answers name clients. Only AWS-shaped facts leave
this module: numbers, and single tokens that match a fixed shape (a command NAME, never its arguments, which hold keys
and values; a role; a version). A client's address is masked with redaction.py's own IP patterns, its name and user
(set by the application) are never copied, and every list is bounded.

⛔ TLS, VERIFIED. The DSN must be `rediss://`: the certificate and the host name are checked, with redis-py 8's
options stated, not defaulted (PR 53): RESP2, one try, no keepalive, short timeouts.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote, urlsplit

from .redaction import PATTERNS

SLOWLOG_MAX = 10          # slow commands read and listed
CLIENTS_LISTED = 5        # longest-idle clients listed one by one
CLIENTS_READ_MAX = 10_000  # clients counted at most: a huge list is summarised from its first part, and said so
IDLE_SECS = int(os.environ.get("WARDEN_DB_TERMINATE_IDLE_SECS", "300"))  # the "stuck connection" bar database.py uses
TIMEOUT_S = float(os.environ.get("WARDEN_DB_CONNECT_TIMEOUT", "4.0"))
DEFAULT_PORT = 6379

INFO, SLOWLOG_GET, CLIENT_LIST = "INFO", "SLOWLOG GET", "CLIENT LIST"
# The only commands WARDEN sends. (name, number of arguments after it).
ALLOWED: dict[str, int] = {INFO: 0, SLOWLOG_GET: 1, CLIENT_LIST: 0}


class RefusedCommand(ValueError):
    """A command outside ALLOWED: refused before anything is sent."""


def allowed(command: str, *args: Any) -> bool:
    """Is `command args...` one of the three reads, with the arguments it may have?"""
    name = " ".join(str(command).split()).upper()
    if name not in ALLOWED or len(args) != ALLOWED[name]:
        return False
    if name == SLOWLOG_GET:
        n = args[0]
        return isinstance(n, int) and not isinstance(n, bool) and 1 <= n <= SLOWLOG_MAX
    return True


class ReadOnlyRedis:
    """A Redis connection that can only INFO, SLOWLOG GET and CLIENT LIST."""

    __slots__ = ("__client",)

    def __init__(self, client: Any) -> None:
        self.__client = client

    def run(self, command: str, *args: Any) -> Any:
        if not allowed(command, *args):
            raise RefusedCommand(f"refused: {' '.join(str(command).split()).upper()[:40]} is not a read WARDEN makes")
        # redis-py splits a multi-word first argument ("SLOWLOG GET") into the command and its subcommand, and
        # parses the answer with that command's own callback (INFO: a dict; SLOWLOG GET and CLIENT LIST: lists).
        return self.__client.execute_command(" ".join(str(command).split()).upper(), *args)

    def close(self) -> None:
        self.__client.close()


def connect(dsn: str) -> ReadOnlyRedis:
    """A TLS connection to the DSN's server, every client option stated (PR 53), wrapped read-only."""
    import redis
    from redis.backoff import NoBackoff
    from redis.retry import Retry

    host, port, user, password = parse_dsn(dsn)
    return ReadOnlyRedis(redis.Redis(
        host=host, port=port, username=user, password=password,
        ssl=True, ssl_cert_reqs="required", ssl_check_hostname=True,
        protocol=2, retry=Retry(NoBackoff(), 0), socket_keepalive=False,
        socket_timeout=TIMEOUT_S, socket_connect_timeout=TIMEOUT_S, decode_responses=True))


def parse_dsn(dsn: str) -> tuple[str, int, str | None, str | None]:
    """(host, port, user, password) of a `rediss://host[:port]` DSN, the user and password in its user part. Anything
    else - a plain `redis://` above all - is refused: the read crosses the network, so it is encrypted and the server
    checked."""
    parts = urlsplit(dsn.strip())
    if parts.scheme != "rediss" or not parts.hostname:
        raise ValueError("the cache DSN must be rediss://host[:port] (TLS); no other form is read")
    port = parts.port or DEFAULT_PORT
    return (parts.hostname, port, unquote(parts.username) if parts.username else None,
            unquote(parts.password) if parts.password else None)


def dsn_host(dsn: str) -> str:
    return parse_dsn(dsn)[0]


# --------------------------------------------------------------------------- reading


_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,31}")
_COMMAND = re.compile(r"[A-Za-z][A-Za-z0-9_.|-]{0,31}")
_IP_PATTERNS = [(label, p) for label, p in PATTERNS if label in ("IPV4", "IPV6")]

# INFO fields copied as metrics: numbers only, under `redis_info_<field>`.
INFO_FIELDS = ("connected_clients", "blocked_clients", "rejected_connections", "evicted_keys", "expired_keys",
               "used_memory", "maxmemory", "mem_fragmentation_ratio", "instantaneous_ops_per_sec",
               "keyspace_hits", "keyspace_misses", "connected_slaves", "master_last_io_seconds_ago",
               "master_link_down_since_seconds")


def _token(value: Any, shape: re.Pattern[str] = _TOKEN) -> str:
    text = str(value if value is not None else "")
    return text if shape.fullmatch(text) else "?"


def _number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def mask_addr(addr: Any) -> str:
    """A client's address as redaction.py masks an IP - `<IPV4>` / `<IPV6>` - with the port dropped; anything that is
    not an IP (a socket path, a name) is `<ADDR>`. The address itself never leaves this module."""
    text = str(addr or "")
    if not text:
        return "-"
    for label, pattern in _IP_PATTERNS:
        if pattern.search(text):
            return f"<{label}>"
    return "<ADDR>"


def read(conn: ReadOnlyRedis, name: str, lines: list[str] | None = None,
         metrics: dict[str, float] | None = None) -> tuple[list[str], dict[str, float]]:
    """INFO, SLOWLOG GET and CLIENT LIST from one server, as evidence lines and metrics. Each read lands in `lines` and
    `metrics` as it completes, so a caller that passes its own keeps what was read before a later command failed."""
    lines = [] if lines is None else lines
    metrics = {} if metrics is None else metrics
    _info(conn.run(INFO), name, lines, metrics)
    _slowlog(conn.run(SLOWLOG_GET, SLOWLOG_MAX), name, lines, metrics)
    _clients(conn.run(CLIENT_LIST), name, lines, metrics)
    return lines, metrics


def _info(info: Any, name: str, lines: list[str], metrics: dict[str, float]) -> None:
    if not isinstance(info, dict):
        raise TypeError("INFO did not answer a mapping")
    for field in INFO_FIELDS:
        v = _number(info.get(field))
        if v is not None:
            metrics[f"redis_info_{field}"] = v
    used, cap = metrics.get("redis_info_used_memory"), metrics.get("redis_info_maxmemory")
    if used is not None and cap:
        metrics["redis_info_memory_used_pct"] = 100.0 * used / cap
    pct = metrics.get("redis_info_memory_used_pct")
    lines.append(
        f"REDIS {name} info role={_token(info.get('role'))} version={_token(info.get('redis_version'))} "
        f"policy={_token(info.get('maxmemory_policy'))} "
        f"clients={_fmt(metrics.get('redis_info_connected_clients'))} "
        f"blocked={_fmt(metrics.get('redis_info_blocked_clients'))} "
        f"memory_used_pct={'-' if pct is None else f'{pct:.0f}'} "
        f"evicted={_fmt(metrics.get('redis_info_evicted_keys'))} "
        f"rejected={_fmt(metrics.get('redis_info_rejected_connections'))} "
        f"link={_token(info.get('master_link_status', '-')) if info.get('role') == 'slave' else '-'}")


def _fmt(v: float | None) -> str:
    return "-" if v is None else f"{v:.0f}"


def _slowlog(entries: Any, name: str, lines: list[str], metrics: dict[str, float]) -> None:
    if not isinstance(entries, list):
        raise TypeError("SLOWLOG GET did not answer a list")
    entries = [e for e in entries if isinstance(e, dict)][:SLOWLOG_MAX]
    metrics["redis_slowlog_entries"] = float(len(entries))
    durations = [d for e in entries if (d := _number(e.get("duration"))) is not None]
    if durations:
        metrics["redis_slowlog_max_us"] = max(durations)
    for e in entries:
        words = str(e.get("command") or "").split()
        at = _number(e.get("start_time"))
        when = datetime.fromtimestamp(at, UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if at is not None else "?"
        # The command's NAME only: its arguments are the application's keys and values.
        lines.append(f"REDIS {name} slow cmd={_token(words[0].upper() if words else '', _COMMAND)} "
                     f"args={max(len(words) - 1, 0)} duration_us={_fmt(_number(e.get('duration')))} at={when} "
                     f"client={mask_addr(e.get('client_address'))}")


def _clients(clients: Any, name: str, lines: list[str], metrics: dict[str, float]) -> None:
    if not isinstance(clients, list):
        raise TypeError("CLIENT LIST did not answer a list")
    rows = [c for c in clients[:CLIENTS_READ_MAX] if isinstance(c, dict)]
    idle = [(_number(c.get("idle")) or 0.0, c) for c in rows]
    stuck = [x for x in idle if x[0] >= IDLE_SECS]
    blocked = sum(1 for c in rows if "b" in str(c.get("flags") or ""))
    metrics.update({"redis_clients_listed": float(len(rows)), "redis_clients_idle": float(len(stuck)),
                    "redis_clients_blocked": float(blocked)})
    if idle:
        metrics["redis_clients_max_idle_s"] = max(i for i, _ in idle)
    lines.append(f"REDIS {name} clients listed={len(rows)} idle_over_{IDLE_SECS}s={len(stuck)} blocked={blocked}"
                 + (f" (first {CLIENTS_READ_MAX} of {len(clients)})" if len(clients) > CLIENTS_READ_MAX else ""))
    for secs, c in _longest(idle):
        lines.append(f"REDIS {name} client id={_token(c.get('id'))} idle={secs:.0f}s "
                     f"age={_fmt(_number(c.get('age')))}s cmd={_token(c.get('cmd'), _COMMAND)} "
                     f"flags={_token(c.get('flags'))} addr={mask_addr(c.get('addr'))}")


def _longest(idle: Iterable[tuple[float, dict]]) -> list[tuple[float, dict]]:
    return sorted(idle, key=lambda x: -x[0])[:CLIENTS_LISTED]
