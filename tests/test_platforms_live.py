"""The Kubernetes and database platforms in the cloud runtime. Before, the runtime started its
workers with `--platform aws` only, so an EKS pod problem or a database session problem could only escalate.

What is held here, each with a weaker version that fails (the plant checks):
- reads go through the environment's platform-reader role, never an actor session;
- each write goes through an actor session minted for that one approved plan, and only to that plan's target;
- a write without an approved plan never falls back to the reader's identity;
- an environment with no cluster or database configured reads and writes nothing - and never crashes the worker;
- the terminate login signs in with a plan's IAM token only: a DSN carrying a password is refused.
"""

from __future__ import annotations

import pathlib
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
    assert minted == [], "a read used the actor"
    assert p.healthy("orders"), "a read used the actor"
    assert minted == [], "a read used the actor"
    assert "scaled deployment/orders" in p.apply("k8s_scale", SCALE, snapshot=snap, who=WHO)
    assert minted == [WHO]
    assert reader.patches == []
    assert [n for n, _ in actor.patches] == ["orders"]
    p.rollback("k8s_scale", SCALE, snap, who=WHO)
    assert reader.patches == []
    assert len(actor.patches) == 2
    assert minted == [WHO, WHO]


def test_a_write_without_an_approved_plan_is_refused_never_sent_as_the_reader():
    for who in (None, {**WHO, "approvers": []}):
        p, reader, actor, minted = _two_identities()
        with pytest.raises(k8sp.KubernetesPlatformRefused) as e:
            p.apply("k8s_restart", {"namespace": NS, "deployment": "orders"}, who=who)
        assert e.value.nothing_changed
        assert minted == []
        assert reader.patches == actor.patches == []


def test_the_actor_cannot_act_outside_the_plans_target():
    p, reader, actor, _ = _two_identities()
    bound = p._for_write(WHO, "orders")
    for name, ns in (("payments", NS), ("orders", "kube-system")):
        with pytest.raises(k8sp.KubernetesPlatformRefused, match="not this plan's target"):
            bound.patch_namespaced_deployment(name, ns, {"spec": {}})
    with pytest.raises(k8sp.KubernetesPlatformRefused, match="namespace"):
        p.apply("k8s_restart", {"namespace": "kube-system", "deployment": "orders"}, who=WHO)
    assert actor.patches == []
    assert reader.patches == []
    # Without a writer (in a cluster, a kubeconfig) the one client is held to the target as well.
    legacy = k8sp.KubernetesPlatform(apps=reader, namespace=NS, autoscaling=_Hpas())
    bound = legacy._for_write(None, "orders")
    with pytest.raises(k8sp.KubernetesPlatformRefused):
        bound.patch_namespaced_deployment("payments", NS, {})


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
    assert live["deployment"] == {"orders"}
    assert "warden-dev-eks" in live["state"]["server"]
    assert {s for _, s in cloud.log} == {"reader-sts:" + TEMPLATE.format(env="dev", role="platform-reader")}
    assert cloud.sessions == [], "a read minted an actor session"
    routed.apply("k8s_scale", SCALE, snapshot=live["state"], who=WHO, environment="dev")
    [session] = cloud.sessions
    assert session["role_arn"] == TEMPLATE.format(env="dev", role="actor")
    assert session["incident"] == "inc-7"
    assert session["approvers"] == ["owner"]
    assert session["plan_hash"] == WHO["plan_hash"]
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
    assert cloud.log == []
    assert cloud.sessions == []


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
    approved = routed.live("db_terminate_idle_in_tx", {}, environment="dev")["state"]  # what the plan shows
    out = routed.apply("db_terminate_idle_in_tx", IDLE, snapshot=approved, who=WHO, environment="dev")
    assert "closed 2 session(s)" in out
    [session] = db_cloud.sessions
    assert session["role_arn"] == TEMPLATE.format(env="dev", role="actor")
    assert session["incident"] == "inc-7"
    assert session["actions"] == ["rds-db:connect"]
    assert session["resources"] == ["arn:aws:rds-db:here:111122223333:dbuser:cluster-RID/warden_dev_terminate"]
    [_, (write, writer_conn)] = db_cloud.conns
    assert (write["user"], write["password"]) == ("warden_dev_terminate", "actor-1-token-warden_dev_terminate")
    # The close's server is verified against Amazon RDS's certificate authorities, not only encrypted.
    assert write["sslmode"] == "verify-full"
    assert pathlib.Path(write["sslrootcert"]).read_text(encoding="ascii").count("BEGIN CERTIFICATE") > 1
    assert read["sslmode"] == "verify-full"  # reads verified too
    assert read["sslrootcert"] == write["sslrootcert"]
    assert writer_conn.killed == [101, 102], "a close went through the reader's login"
    assert reader_conn.killed == [], "a close went through the reader's login"
    assert not any("pg_terminate_backend" in sql for sql, _ in reader_conn.sql)
    assert writer_conn.closed, "the plan's connection outlived its close"


def test_the_terminate_login_never_signs_in_with_a_standing_password(db_cloud, monkeypatch):
    monkeypatch.setenv("WARDEN_DB_TERMINATE_DSN", DSN_TERMINATE.replace("_terminate@", f"_terminate:{HUNTER2}@"))
    p = dbp.db_from_environment().for_environment("dev")
    assert isinstance(p, Unconfigured)
    assert "password" in p.why
    with pytest.raises(NotConfigured):
        p.apply("db_terminate_idle_in_tx", IDLE, who=WHO)
    assert db_cloud.conns == []
    assert db_cloud.sessions == []


@pytest.mark.parametrize("dsn, why", [
    (DSN_RO.replace("_ro@", f"_ro:{HUNTER2}@"), "password"),
    (DSN_RO + f"?password={HUNTER2}&sslmode=disable", "password"),
    ("postgresql:///shop?user=warden_dev_ro", "no host"),
    ("postgresql://warden-dev-aurora.cluster-abc123.here.rds.example/shop", "no user"),
])
def test_the_read_login_is_signed_and_verified_or_refused(db_cloud, monkeypatch, dsn, why):
    """A read DSN iam_dsn would pass through as it is - a standing password, or no host or user to sign for - is
    refused before any read: it would sign in unsigned and without verify-full."""
    monkeypatch.setenv("WARDEN_STACK_DB_PRIMARY_RO_DSN", dsn)
    monkeypatch.delenv("WARDEN_DB_TERMINATE_DSN", raising=False)
    p = dbp.db_from_environment().for_environment("dev")
    assert isinstance(p, Unconfigured)
    assert why in p.why
    assert "WARDEN_STACK_DB_PRIMARY_RO_DSN" in p.why
    assert HUNTER2 not in p.why
    assert db_cloud.conns == []


def test_a_zone_without_a_login_or_an_environment_without_a_database_closes_nothing(db_cloud, monkeypatch):
    monkeypatch.setenv("WARDEN_STACK_DB_PRIMARY_RO_DSN", DSN_RO)  # the read zone: no terminate login
    monkeypatch.delenv("WARDEN_DB_TERMINATE_DSN", raising=False)
    read_zone = dbp.db_from_environment()
    dev = read_zone.for_environment("dev")
    with pytest.raises(dbp.DatabasePlatformRefused) as e:
        dev.apply("db_terminate_idle_in_tx", IDLE, who=WHO)
    assert e.value.nothing_changed
    assert db_cloud.sessions == []
    assert isinstance(read_zone.for_environment("prod"), Unconfigured)
    monkeypatch.delenv("WARDEN_STACK_DB_PRIMARY_RO_DSN")
    assert isinstance(dbp.db_from_environment().for_environment("dev"), Unconfigured)
    monkeypatch.setenv("WARDEN_DB_TERMINATE_DSN", DSN_TERMINATE)  # the act zone: no read login, reads nothing
    assert dbp.db_from_environment().for_environment("dev").live("db_terminate_idle_in_tx", {}) == {}
    assert db_cloud.conns == []


def test_a_close_on_another_cluster_than_the_plan_was_read_from_is_refused(db_cloud, monkeypatch):
    """The read zone reads the plan through one DSN, the act zone closes through another. A close goes
    ahead only when the terminate login reaches the same Aurora cluster's writer endpoint the approved plan names -
    endpoints compared, not raw hosts; a reader or instance endpoint proves nothing."""
    monkeypatch.setenv("WARDEN_DB_TERMINATE_DSN", DSN_TERMINATE)
    act = dbp.db_from_environment().for_environment("dev")
    for server in ("warden-dev-other.cluster-abc123.here.rds.example:5432",  # another cluster
                   "warden-dev-aurora.cluster-ro-abc123.here.rds.example:5432",  # its reader endpoint
                   "warden-dev-aurora-1.abc123.here.rds.example:5432",  # an instance endpoint
                   ""):
        with pytest.raises(dbp.DatabasePlatformRefused, match="Aurora cluster the approved plan") as e:
            act.apply("db_terminate_idle_in_tx", IDLE, snapshot={"server": server}, who=WHO)
        assert e.value.nothing_changed
    assert db_cloud.sessions == [], "an actor session was minted for a close that could not go ahead"
    assert db_cloud.conns == []
    assert dbp.aurora_cluster("host=WARDEN-DEV-AURORA.cluster-abc123.here.rds.example port=5432") == \
        dbp.aurora_cluster(DSN_TERMINATE)


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
    assert cli._platform_choice("aws,k8s") == {"aws", "k8s"}
    assert cli._platform("none") is None
    for bad in ("", "aws,ssh", "everything"):
        with pytest.raises(Exception, match="none, all, or a list"):
            cli._platform_choice(bad)


def test_an_eks_client_is_made_again_before_the_credentials_that_signed_it_can_expire(monkeypatch):
    """The reader session is handed out with at least 300 s left (900 s, renewed after 600 s), and a
    client's token is signed once, when it is made - so a client is never kept 300 s."""
    now = [1000.0]
    monkeypatch.setattr(k8sp.time, "monotonic", lambda: now[0])
    made = []
    fresh = k8sp._Fresh(lambda: made.append(len(made)) or types.SimpleNamespace(n=len(made)))
    assert fresh.n == 1
    now[0] += 239
    assert fresh.n == 1
    now[0] += 2  # 241 s after it was made
    assert fresh.n == 2
    assert k8sp._Fresh.__init__.__defaults__[0] < 300


def test_the_shipped_remediation_binding_names_the_service_account_only_and_ci_binds_the_group_apart():
    """Applying k8s/remediation-rbac.yaml must not grant the EKS actor's group anything in `default`.
    The group is bound in shop alone on EKS, and in CI's test namespace by a CI-only file the workflow applies."""
    import yaml

    root = pathlib.Path(__file__).resolve().parents[1]
    docs = [d for d in yaml.safe_load_all((root / "k8s" / "remediation-rbac.yaml").read_text(encoding="utf-8")) if d]
    [shipped] = [d for d in docs if d["kind"] == "RoleBinding"]
    assert shipped["subjects"] == [{"kind": "ServiceAccount", "name": "warden-remediator", "namespace": "warden"}]
    [ci] = yaml.safe_load_all((root / "k8s" / "ci" / "remediation-group-binding.yaml").read_text(encoding="utf-8"))
    assert ci["subjects"] == [{"kind": "Group", "name": "warden-remediators", "apiGroup": "rbac.authorization.k8s.io"}]
    assert ci["roleRef"]["name"] == "warden-remediator"
    # (the CI applies it: tests/test_ci_lanes.py, which runs where the workflows change)
    assert "ci/" not in (root / "k8s" / "kustomization.yaml").read_text(encoding="utf-8")  # never in a real deploy


def test_a_close_without_an_approved_plan_is_refused_and_mints_nothing(db_cloud, monkeypatch):
    monkeypatch.setenv("WARDEN_DB_TERMINATE_DSN", DSN_TERMINATE)
    act = dbp.db_from_environment().for_environment("dev")
    server = {"server": "warden-dev-aurora.cluster-abc123.here.rds.example:5432"}
    for who in (None, {**WHO, "approvers": []}):
        with pytest.raises(dbp.DatabasePlatformRefused, match="approved plan's actor session") as e:
            act.apply("db_terminate_idle_in_tx", IDLE, snapshot=server, who=who)
        assert e.value.nothing_changed
    assert db_cloud.sessions == []
    assert db_cloud.conns == []


@pytest.mark.parametrize("endpoint", ["warden-dev-aurora.cluster-ro-abc123.here.rds.example",
                                      "warden-dev-aurora-1.abc123.here.rds.example", "10.0.0.5",
                                      "a.cluster-x.here.rds.example b.cluster-y.here.rds.example"])
def test_only_one_cluster_writer_endpoint_names_a_cluster(endpoint):
    """A reader (`cluster-ro-`), an instance, an address or two clusters prove nothing about the writer."""
    assert dbp.aurora_cluster(endpoint) is None


def test_a_role_comes_only_from_an_iam_template_and_a_configured_environment(monkeypatch):
    from warden.platforms import role_arn

    monkeypatch.setenv("WARDEN_AWS_ROLE_ARN_TEMPLATE", TEMPLATE)
    assert role_arn("dev", "actor") == TEMPLATE.format(env="dev", role="actor")
    with pytest.raises(NotConfigured, match="not a configured environment"):
        role_arn("staging-x", "actor")
    for bad in ("", "warden-{env}-{role}", "arn:aws:iam::111122223333:role/warden-actor",
                "arn:aws:s3:::bucket/{env}/{role}"):
        monkeypatch.setenv("WARDEN_AWS_ROLE_ARN_TEMPLATE", bad)
        with pytest.raises(NotConfigured, match="WARDEN_AWS_ROLE_ARN_TEMPLATE"):
            role_arn("dev", "actor")


def test_a_platform_that_fails_to_build_changes_nothing_and_is_not_built_again(monkeypatch):
    """An unexpected failure building an environment's platform is that environment's Unconfigured -
    nothing read or written, the worker runs on - and is remembered, not retried on every plan."""
    calls = []

    def build(env):
        calls.append(env)
        raise KeyError("boom")

    per = warden.platforms.PerEnvironment(build, "database")
    first = per.for_environment("dev")
    assert isinstance(first, Unconfigured)
    assert "KeyError" in first.why
    assert per.for_environment("dev") is first
    assert calls == ["dev"]
    with pytest.raises(NotConfigured):
        first.apply("db_terminate_idle_in_tx", IDLE, who=WHO)
