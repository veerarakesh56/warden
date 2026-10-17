"""Item 4: the Kubernetes and database platforms in the cloud runtime (2026-10-17). Before, the runtime started its
workers with `--platform aws` only, so an EKS pod problem or a database session problem could only escalate.

What is held here, each with a weaker version that fails (the plant checks):
- reads go through the environment's platform-reader role, never an actor session;
- each write goes through an actor session minted for that one approved plan, and only to that plan's target;
- a write without an approved plan never falls back to the reader's identity;
- an environment with no cluster or database configured reads and writes nothing - and never crashes the worker;
- the terminate login signs in with a plan's IAM token only: a DSN carrying a password is refused.
"""

from __future__ import annotations

import types

import pytest
from psycopg.conninfo import conninfo_to_dict

import warden.k8s_backend
import warden.platforms
from fakes import HUNTER2
from test_platform_db import APP, _Conn
from test_platform_k8s import NS, _Apps, _Hpas
from warden import identity
from warden.platforms import NotConfigured, RoutedPlatform, Unconfigured
from warden.platforms import db as dbp
from warden.platforms import k8s as k8sp

WHO = {"incident": "inc-7", "plan_hash": "c" * 64, "approvers": ["owner"]}
TEMPLATE = "arn:aws:iam::111122223333:role/warden-{env}-{role}"
SCALE = {"namespace": NS, "deployment": "orders", "replicas": 3}


# --------------------------------------------------------------------------- Kubernetes, one platform

def _two_identities():
    reader, actor, minted = _Apps(), _Apps(), []
    p = k8sp.KubernetesPlatform(apps=reader, namespace=NS, autoscaling=_Hpas(),
                                writer=lambda who: minted.append(who) or actor)
    return p, reader, actor, minted


def test_reads_never_mint_an_actor_and_writes_go_only_through_the_plans_actor():
    p, reader, actor, minted = _two_identities()
    snap = p.live("k8s_scale", {"deployment": "orders"})["state"]
    assert minted == [] and p.healthy("orders") and minted == [], "a read used the actor"
    assert "scaled deployment/orders" in p.apply("k8s_scale", SCALE, snapshot=snap, who=WHO)
    assert minted == [WHO] and reader.patches == [] and [n for n, _ in actor.patches] == ["orders"]
    p.rollback("k8s_scale", SCALE, snap, who=WHO)
    assert reader.patches == [] and len(actor.patches) == 2 and minted == [WHO, WHO]


def test_a_write_without_an_approved_plan_is_refused_never_sent_as_the_reader():
    for who in (None, {**WHO, "approvers": []}):
        p, reader, actor, minted = _two_identities()
        with pytest.raises(k8sp.KubernetesPlatformRefused) as e:
            p.apply("k8s_restart", {"namespace": NS, "deployment": "orders"}, who=who)
        assert e.value.nothing_changed and minted == [] and reader.patches == actor.patches == []


def test_the_actor_cannot_act_outside_the_plans_target():
    p, reader, actor, _ = _two_identities()
    bound = p._for_write(WHO, "orders")
    for name, ns in (("payments", NS), ("orders", "kube-system")):
        with pytest.raises(k8sp.KubernetesPlatformRefused, match="not this plan's target"):
            bound.patch_namespaced_deployment(name, ns, {"spec": {}})
    with pytest.raises(k8sp.KubernetesPlatformRefused, match="namespace"):
        p.apply("k8s_restart", {"namespace": "kube-system", "deployment": "orders"}, who=WHO)
    assert actor.patches == [] and reader.patches == []
    # Without a writer (in a cluster, a kubeconfig) the one client is held to the target as well.
    legacy = k8sp.KubernetesPlatform(apps=reader, namespace=NS, autoscaling=_Hpas())
    with pytest.raises(k8sp.KubernetesPlatformRefused):
        legacy._for_write(None, "orders").patch_namespaced_deployment("payments", NS, {})


def test_an_actor_session_that_cannot_be_minted_changes_nothing():
    p = k8sp.KubernetesPlatform(apps=_Apps(), namespace=NS, autoscaling=_Hpas(),
                                writer=lambda who: (_ for _ in ()).throw(RuntimeError("AccessDenied")))
    with pytest.raises(k8sp.KubernetesPlatformRefused) as e:
        p.apply("k8s_restart", {"namespace": NS, "deployment": "orders"}, who=WHO)
    assert e.value.nothing_changed


# --------------------------------------------------------------------------- the cloud factories

class _Signed:
    """An ApiClient stand-in: who signed its token."""

    def __init__(self, signer):
        self.signer = signer


class _ClusterApps(_Apps):
    def __init__(self, api, log):
        super().__init__()
        self.signer, self.log = api.signer, log

    def read_namespaced_deployment(self, name, ns, **kw):
        self.log.append(("read", self.signer))
        return super().read_namespaced_deployment(name, ns, **kw)

    def patch_namespaced_deployment(self, name, ns, body, **kw):
        self.log.append(("patch", self.signer))
        return super().patch_namespaced_deployment(name, ns, body, **kw)


class _Sts:
    pass


class _Eks:
    def describe_cluster(self, name):
        return {"cluster": {"arn": f"arn:aws:eks:here:111122223333:cluster/{name}", "endpoint": "https://api.example",
                            "certificateAuthority": {"data": ""}}}


@pytest.fixture
def cloud(monkeypatch):
    """The cloud runtime's environment, every AWS call faked: who signed what is recorded."""
    import boto3
    from kubernetes import client

    log, sessions = [], []
    monkeypatch.setenv("WARDEN_AWS_ROLE_ARN_TEMPLATE", TEMPLATE)
    monkeypatch.setenv("WARDEN_K8S_NAMESPACE", NS)
    monkeypatch.setattr(boto3, "client", lambda service, **kw: _Sts())
    reader_rds = types.SimpleNamespace(
        meta=types.SimpleNamespace(region_name="here"),
        generate_db_auth_token=lambda DBHostname, Port, DBUsername: f"reader-token-{DBUsername}",
        describe_db_clusters=lambda DBClusterIdentifier: {"DBClusters": [{"DbClusterResourceId": "cluster-RID"}]})
    readers = {}

    def reader_clients(sts, where, arn):
        readers[arn] = True
        return lambda service: {"eks": _Eks(), "sts": f"reader-sts:{arn}", "rds": reader_rds}[service]

    def actor_session(sts, **kw):
        sessions.append(kw)
        return {"aws_session_token": f"actor-{len(sessions)}"}

    def session_clients(creds, where):
        token = creds["aws_session_token"]
        rds = types.SimpleNamespace(
            generate_db_auth_token=lambda DBHostname, Port, DBUsername: f"{token}-token-{DBUsername}")
        return lambda service: {"sts": f"actor-sts:{token}", "rds": rds}[service]

    monkeypatch.setattr(warden.platforms, "reader_clients", reader_clients)
    monkeypatch.setattr(warden.platforms, "session_clients", session_clients)
    monkeypatch.setattr(identity, "actor_session", actor_session)
    monkeypatch.setattr(warden.k8s_backend, "eks_api_client", lambda described, sts, cluster: _Signed(sts))
    monkeypatch.setattr(client, "AppsV1Api", lambda api: _ClusterApps(api, log))
    monkeypatch.setattr(client, "AutoscalingV2Api", lambda api: _Hpas())
    return types.SimpleNamespace(log=log, sessions=sessions, readers=readers)


def test_eks_reads_in_the_reader_role_and_writes_in_the_plans_actor_session(cloud, monkeypatch):
    monkeypatch.setenv("WARDEN_EKS_CLUSTERS", "dev=warden-dev-eks")
    routed = RoutedPlatform(k8s=k8sp.eks_from_environment())
    live = routed.live("k8s_scale", {"deployment": "orders"}, environment="dev")
    assert live["deployment"] == {"orders"} and "warden-dev-eks" in live["state"]["server"]
    assert {s for _, s in cloud.log} == {"reader-sts:" + TEMPLATE.format(env="dev", role="platform-reader")}
    assert cloud.sessions == [], "a read minted an actor session"
    routed.apply("k8s_scale", SCALE, snapshot=live["state"], who=WHO, environment="dev")
    [session] = cloud.sessions
    assert session["role_arn"] == TEMPLATE.format(env="dev", role="actor") and session["incident"] == "inc-7"
    assert session["approvers"] == ["owner"] and session["plan_hash"] == WHO["plan_hash"]
    # Its session policy names the one cluster and grants no write of AWS's: Kubernetes RBAC decides the rest.
    assert session["actions"] == ["eks:DescribeCluster"]
    assert session["resources"] == ["arn:aws:eks:here:111122223333:cluster/warden-dev-eks"]
    assert [s for op, s in cloud.log if op == "patch"] == ["actor-sts:actor-1"]


def test_an_environment_without_a_cluster_reads_and_changes_nothing_and_never_crashes(cloud, monkeypatch):
    monkeypatch.setenv("WARDEN_EKS_CLUSTERS", "dev=warden-dev-eks")
    routed = RoutedPlatform(k8s=k8sp.eks_from_environment())
    for env in ("prod", "not-an-environment"):
        assert routed.live("k8s_scale", {"deployment": "orders"}, environment=env) == {}
        assert not routed.healthy_for("k8s_scale", "orders", environment=env)
        with pytest.raises(NotConfigured) as e:
            routed.apply("k8s_scale", SCALE, snapshot={}, who=WHO, environment=env)
        assert e.value.nothing_changed
    monkeypatch.delenv("WARDEN_EKS_CLUSTERS")
    assert isinstance(k8sp.eks_from_environment().for_environment("dev"), Unconfigured)
    assert cloud.log == [] and cloud.sessions == []


DSN_RO = "postgresql://warden_dev_ro@warden-dev-aurora.cluster-abc123.here.rds.example:5432/shop"
DSN_TERMINATE = "postgresql://warden_dev_terminate@warden-dev-aurora.cluster-abc123.here.rds.example:5432/shop"
IDLE = {"database": "orders", "min_idle_seconds": 300, "max_sessions": 5}


class _Closable(_Conn):
    closed = False

    def close(self):
        self.closed = True


@pytest.fixture
def db_cloud(cloud, monkeypatch):
    conns = []

    def connect(dsn):
        conns.append((conninfo_to_dict(dsn), _Closable(me=conninfo_to_dict(dsn)["user"])))
        return conns[-1][1]

    monkeypatch.setattr(dbp, "adapter_for", lambda engine: types.SimpleNamespace(connect=connect))
    monkeypatch.setenv("WARDEN_DB_ENVIRONMENT", "dev")
    monkeypatch.setenv("WARDEN_DB_APP_USERS", ",".join(APP))
    cloud.conns = conns
    return cloud


def test_db_reads_as_the_monitor_login_and_closes_as_the_terminate_login_in_the_plans_session(db_cloud, monkeypatch):
    monkeypatch.setenv("WARDEN_STACK_DB_PRIMARY_RO_DSN", DSN_RO)
    monkeypatch.setenv("WARDEN_DB_TERMINATE_DSN", DSN_TERMINATE)
    routed = RoutedPlatform(db=dbp.db_from_environment())
    assert routed.live("db_terminate_idle_in_tx", {}, environment="dev")["database"] == {"orders"}
    assert routed.healthy_for("db_terminate_idle_in_tx", "orders", environment="dev") is False  # two stuck sessions
    [(read, reader_conn)] = db_cloud.conns
    assert (read["user"], read["password"]) == ("warden_dev_ro", "reader-token-warden_dev_ro")
    assert db_cloud.sessions == [], "a read minted an actor session"
    out = routed.apply("db_terminate_idle_in_tx", IDLE, who=WHO, environment="dev")
    assert "closed 2 session(s)" in out
    [session] = db_cloud.sessions
    assert session["role_arn"] == TEMPLATE.format(env="dev", role="actor") and session["incident"] == "inc-7"
    assert session["actions"] == ["rds-db:connect"]
    assert session["resources"] == ["arn:aws:rds-db:here:111122223333:dbuser:cluster-RID/warden_dev_terminate"]
    [_, (write, writer_conn)] = db_cloud.conns
    assert (write["user"], write["password"]) == ("warden_dev_terminate", "actor-1-token-warden_dev_terminate")
    assert writer_conn.killed == [101, 102] and reader_conn.killed == [], "a close went through the reader's login"
    assert not any("pg_terminate_backend" in sql for sql, _ in reader_conn.sql)
    assert writer_conn.closed, "the plan's connection outlived its close"


def test_the_terminate_login_never_signs_in_with_a_standing_password(db_cloud, monkeypatch):
    monkeypatch.setenv("WARDEN_DB_TERMINATE_DSN", DSN_TERMINATE.replace("_terminate@", f"_terminate:{HUNTER2}@"))
    p = dbp.db_from_environment().for_environment("dev")
    assert isinstance(p, Unconfigured) and "password" in p.why
    with pytest.raises(NotConfigured):
        p.apply("db_terminate_idle_in_tx", IDLE, who=WHO)
    assert db_cloud.conns == [] and db_cloud.sessions == []


def test_a_zone_without_a_login_or_an_environment_without_a_database_closes_nothing(db_cloud, monkeypatch):
    monkeypatch.setenv("WARDEN_STACK_DB_PRIMARY_RO_DSN", DSN_RO)  # the read zone: no terminate login
    monkeypatch.delenv("WARDEN_DB_TERMINATE_DSN", raising=False)
    read_zone = dbp.db_from_environment()
    with pytest.raises(dbp.DatabasePlatformRefused) as e:
        read_zone.for_environment("dev").apply("db_terminate_idle_in_tx", IDLE, who=WHO)
    assert e.value.nothing_changed and db_cloud.sessions == []
    assert isinstance(read_zone.for_environment("prod"), Unconfigured)
    monkeypatch.delenv("WARDEN_STACK_DB_PRIMARY_RO_DSN")
    assert isinstance(dbp.db_from_environment().for_environment("dev"), Unconfigured)
    monkeypatch.setenv("WARDEN_DB_TERMINATE_DSN", DSN_TERMINATE)  # the act zone: no read login, reads nothing
    assert dbp.db_from_environment().for_environment("dev").live("db_terminate_idle_in_tx", {}) == {}
    assert db_cloud.conns == []


def test_a_terminate_dsn_that_names_no_cluster_endpoint_is_refused():
    with pytest.raises(dbp.DatabasePlatformRefused):
        dbp.dbuser_arn(None, "postgresql://warden_dev_terminate@10.0.0.5:5432/shop", TEMPLATE)


# --------------------------------------------------------------------------- the worker

def test_every_platform_starts_in_the_cloud_with_no_cluster_or_database_configured(cloud, monkeypatch):
    from warden import cli

    for name in ("WARDEN_EKS_CLUSTERS", "WARDEN_DB_ENVIRONMENT", "WARDEN_DB_TERMINATE_DSN"):
        monkeypatch.delenv(name, raising=False)
    routed = cli._platform("all")
    assert routed.live("k8s_restart", {"deployment": "orders"}, environment="dev") == {}
    assert routed.live("db_terminate_idle_in_tx", {}, environment="dev") == {}
    assert cli._platform_choice("aws,k8s") == {"aws", "k8s"} and cli._platform("none") is None
    for bad in ("", "aws,ssh", "everything"):
        with pytest.raises(Exception, match="none, all, or a list"):
            cli._platform_choice(bad)
