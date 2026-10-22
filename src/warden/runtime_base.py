"""The light half of runtime.py: connect to Temporal, read the approver policy, open the audit - without importing the
worker, the activities or the workflows. The approval Lambda (lambdas.approval_page, which also serves the records
pages) needs only these, and importing the rest cost its cold start most of its page time (2.5 s, live 2026-10-14).
runtime.py re-exports every name here; the configuration is documented there."""

from __future__ import annotations

import os
import pathlib
import re
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from . import approvals, audit

if TYPE_CHECKING:
    from temporalio.client import Client


def _path(env: str, default: str | None = None) -> pathlib.Path:
    value = os.environ.get(env) or default
    if not value:
        raise RuntimeError(f"{env} is not set")
    return pathlib.Path(value).expanduser()


def audit_target() -> str | pathlib.Path:
    """The shared PostgreSQL audit when WARDEN_AUDIT_DSN is set (the runtime's Aurora: a Secrets Manager secret,
    since a DSN may carry a password), else the SQLite file WARDEN_AUDIT_DB."""
    dsn = os.environ.get("WARDEN_AUDIT_DSN", "").strip()
    if dsn:
        if not audit._is_postgres(dsn):
            raise RuntimeError("WARDEN_AUDIT_DSN must be a postgresql:// DSN")
        return dsn
    db = _path("WARDEN_AUDIT_DB", "~/.warden/audit.db")
    db.parent.mkdir(parents=True, exist_ok=True)
    return db


def approver_policy() -> approvals.ApproverPolicy:
    """Who may approve what: the file WARDEN_APPROVERS, or - in the cloud runtime, where a Lambda has no such file - the
    SSM parameter /warden/<env>/approvers (public keys and tiers only; nothing in it is secret)."""
    if os.environ.get("WARDEN_APPROVERS"):
        return approvals.ApproverPolicy.load(_path("WARDEN_APPROVERS"))
    env = os.environ.get("WARDEN_ENV", "").strip()
    if not env:
        raise RuntimeError("WARDEN_APPROVERS is not set, and no WARDEN_ENV names the SSM parameter to read instead")
    import boto3

    from .environments import names, region

    name = names(env).ssm + "approvers"
    text = boto3.client("ssm", region_name=region()).get_parameter(Name=name)["Parameter"]["Value"]
    return approvals.ApproverPolicy.loads(text)


def audit_signer() -> Any:
    """The key that signs checkpoints: the runtime's KMS Ed25519 key when WARDEN_AUDIT_KMS_KEY_ID names one (register
    S12 - nobody, WARDEN included, can export it), else the local key file WARDEN_AUDIT_KEY."""
    key_id = os.environ.get("WARDEN_AUDIT_KMS_KEY_ID", "").strip()
    if key_id:
        import boto3

        from .environments import region

        return audit.KmsSigner(key_id, boto3.client("kms", region_name=region()))
    passphrase = os.environ.get("WARDEN_AUDIT_KEY_PASSPHRASE", "").encode() or None
    return audit.load_private_key(_path("WARDEN_AUDIT_KEY"), passphrase)


def audit_anchor() -> Any:
    """Where each checkpoint is also written, out of the database's reach: the S3 Object Lock bucket
    WARDEN_AUDIT_ANCHOR_BUCKET (register S12), for WARDEN_AUDIT_ANCHOR_DAYS days (default 1, the lab's)."""
    bucket = os.environ.get("WARDEN_AUDIT_ANCHOR_BUCKET", "").strip()
    if not bucket:
        return None
    import boto3

    from .environments import region

    days = int(os.environ.get("WARDEN_AUDIT_ANCHOR_DAYS", "1"))
    if days < 1:
        raise RuntimeError("WARDEN_AUDIT_ANCHOR_DAYS must be at least 1")
    return audit.S3Anchor(bucket, boto3.client("s3", region_name=region()), retain=timedelta(days=days))


def open_audit() -> audit.AuditLog:
    from . import egress

    log = audit.AuditLog(audit_target(), key=audit_signer(), anchor=audit_anchor())
    egress.ledger_to(log)  # the egress ledger's rows go on the signed audit too (egress.record)
    return log


_LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


async def connect(address: str | None = None, key: bytes | None = None) -> Client:
    """A client for the configured server. Temporal Cloud authenticates by API key over TLS; any server off this
    machine without a key is refused, never tried (register S15): a worker that talked to a server anyone could
    reach would take its tasks - and its plans - from anyone."""
    target = address or os.environ.get("WARDEN_TEMPORAL_ADDRESS", "127.0.0.1:7233")
    api_key = os.environ.get("WARDEN_TEMPORAL_API_KEY")
    host = target.rsplit(":", 1)[0]  # host:port, or [ipv6]:port
    if host not in _LOOPBACK and not api_key:
        raise RuntimeError(f"refusing an unauthenticated connection to {host}: set WARDEN_TEMPORAL_API_KEY "
                           "(register S15)")
    if host not in _LOOPBACK:
        only_the_namespace_endpoint(target)
    # Imported here, not at the top: a records page (/r) never reaches Temporal, and the client is 0.4 s of imports.
    from temporalio.client import Client

    from . import codec

    options: dict[str, Any] = {"namespace": os.environ.get("WARDEN_TEMPORAL_NAMESPACE", "default"),
                               "data_converter": codec.data_converter(key)}
    if api_key:
        options.update(api_key=api_key, tls=True)
    return await Client.connect(target, **options)


# A Temporal Cloud namespace is `name.account`; its own endpoint is `<name>.<account>.tmprl.cloud:7233`.
_NAMESPACE = re.compile(r"[a-z0-9][a-z0-9-]{0,61}\.[a-z0-9]{1,32}")


def only_the_namespace_endpoint(target: str) -> None:
    """B23 (owner, 2026-10-20): the API key goes to the configured namespace's own Temporal Cloud endpoint and nowhere
    else. A changed WARDEN_TEMPORAL_ADDRESS - a typo, a copied value, a poisoned parameter - would otherwise hand the
    key, and every task, to whatever answers there. Refused before any connection.

    Honest limit: this is the code's check, not the network's. The runtime's security group allows port 7233 to any
    address (a security group cannot name a host; PrivateLink or a DNS firewall would, and cost money - owner,
    2026-10-20), so code that skipped this function could still reach another host on that port."""
    namespace = os.environ.get("WARDEN_TEMPORAL_NAMESPACE", "")
    if not _NAMESPACE.fullmatch(namespace):
        raise RuntimeError("refusing to reach Temporal: WARDEN_TEMPORAL_NAMESPACE is not a Temporal Cloud namespace "
                           "(name.account) (B23)")
    if target.lower() != f"{namespace}.tmprl.cloud:7233":
        raise RuntimeError(f"refusing to reach Temporal at {target.rsplit(':', 1)[0]}: only the namespace's own "
                           "Temporal Cloud endpoint, <name>.<account>.tmprl.cloud:7233, receives the API key (B23)")
