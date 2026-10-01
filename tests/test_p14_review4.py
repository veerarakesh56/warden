"""P14: a target is one named resource (fourth review, 2026-09-30, C-6; the reviewer's table). A flag after
any punctuation, a dash look-alike, a list, a pattern, a whole namespace or a command is refused; a
namespace that only qualifies a resource is not."""

from __future__ import annotations

import pytest

from warden.grounding import target_problem
from warden.models import ActionKind as A
from warden.models import RemediationProposal

INV = {"orders", "checkout", "shop", "payments", "warden-pg"}
SCOPES = {"warden-pg"}


def _problem(target):
    p = RemediationProposal(action=A.restart_pods, target=target, reasoning="r", expected_effect="e",
                            blast_radius="single_service", reversible=True)
    return target_problem(p, INV | {"checkout-7d9f"}, SCOPES)


BAD = [
    # flags after other punctuation
    "deployment=-A orders", "deployment=--all orders", "orders deployment=--all", "orders/--all", "orders:-A",
    "orders.--all", "orders+--all", "orders>--all", "orders!--all", "orders|--all", "orders@-A",
    # dash lookalikes outside Pd
    "orders ⁃⁃all", "orders ──all", "orders ーーall", "orders 一一all",
    "orders ⁻⁻all", "orders ₋₋all", "orders ⼀A", "orders ㇐A", "orders ⎯A",
    "orders ᐨA", "orders ˉA", "orders ｰA",
    # whitespace variants
    "orders\u00a0--all", "orders\u3000-A", "orders\u1680-A", "orders\u205f-A",
    # lists and patterns without '='
    "orders,payments", "orders payments", "orders and payments", "{orders,payments}", "orders-[0-9]",
    "orders-.+", "orders-%", "pod=orders-.+", "pod=orders-[a-z]", "deployment=orders payments",
    "deployment=orders/payments", "deployment=(orders,payments)",
    # whole namespace / cluster other spellings
    "namespace:warden-pg", "namespace/warden-pg", "ns/warden-pg", "namespace warden-pg", "(namespace=warden-pg)",
    '"namespace=warden-pg"', "all pods in warden-pg", "all deployments in namespace warden-pg",
    "warden-pg", "cluster:warden-pg", " Namespace = warden-pg", "\u200bnamespace=warden-pg",
    "NAMESPACE=warden-pg", "deployment=orders namespace=warden-pg --all",
    # shell-ish not in _SHELL
    "orders > /tmp/x", "orders < /etc/hosts", "orders\nkubectl delete ns warden-pg", "orders ( ) { :; }",
    "orders\"; rm -rf /", "$(id)", "orders %0a--all",
]
GOOD = ["orders", "deployment=checkout (namespace=warden-pg)", "deployment=checkout", "lambda:checkout (version 7 -> 6)",
        "\u200b-orders"]
GOOD += ["deployment=checkout, namespace=shop", "namespace=shop, deployment=checkout",
         "namespace=shop deployment=checkout", "deployment=checkout,namespace=shop", "checkout (namespace=shop)",
         "pod=checkout-7d9f (namespace=shop)", "checkout (-1 replica)", "deployment/checkout (namespace warden-pg)"]
GOOD.remove("\u200b-orders")   # models.inert()'s prefix: still a flag, refused on purpose


@pytest.mark.parametrize("target", BAD)
def test_not_one_named_resource_is_refused(target):
    assert _problem(target) is not None


@pytest.mark.parametrize("target", GOOD)
def test_one_named_resource_passes(target):
    assert _problem(target) is None

# Fifth review (2026-10-01): ordinary prose a model writes - refused once targets had to be ASCII.
PROSE = [
    'checkout \u2014 revert to revision 6',
    'checkout \u2013 revision 7 to 6',
    'checkout\u2019s deployment',
    'checkout (namespace \u201cshop\u201d)',
    'checkout (\xd72 replicas)',
    'checkout (\u2265 3 replicas)',
]


@pytest.mark.parametrize("target", PROSE)
def test_ordinary_prose_in_a_target_passes(target):
    assert _problem(target) is None


def test_a_prose_dash_before_a_word_is_still_a_flag():
    assert _problem("orders \u2014all") is not None


@pytest.mark.parametrize("target", ["orders (kubectl/delete/ns/warden-pg)", "orders(kubectl,delete)", "orders (rm)",
                                    "orders (drop table)"])
def test_a_command_after_punctuation_is_refused(target):
    """Fifth review (2026-10-01): a command word not preceded by a space passed."""
    assert _problem(target) is not None


def test_an_image_name_holding_a_command_word_still_passes():
    assert _problem("checkout (image public.ecr.aws/docker/library/python)") is None


def test_every_cluster_label_scopes_the_target():
    """Fifth review (2026-10-01): only `namespace` and `cluster` labels were scopes; `ecs_cluster` let the
    cluster itself through as a target."""
    from warden.cli import DEMO_ALERTS
    from warden.models import Alert, Citation, ContextBundle, RootCause
    from warden.verifier import verify

    alert = Alert(**{**DEMO_ALERTS["inc-002"], "labels": {"ecs_cluster": "warden-dev-cluster,other-cluster"}})
    ctx = ContextBundle(logs=["CONFIG deploy revision 7", "x ERROR a", "x ERROR b"], metrics={"error_rate": 0.1},
                        recent_deploys=[{"kind": "ecs", "service": "warden-dev-cluster"}])
    rc = RootCause(hypothesis="h", confidence=0.9, citations=[Citation(id="C1", quote="deploy revision 7")])
    prop = RemediationProposal(action=A.rollback_deploy, target="warden-dev-cluster", reasoning="r",
                               expected_effect="e", blast_radius="single_service", reversible=True)
    assert "P14-TARGET-NOT-IN-EVIDENCE" in verify(alert, ctx, rc, prop).policy_ids


@pytest.mark.parametrize("target", ["app in (orders,payments)", "orders (and payments)", "orders (payments)",
                                    "orders (+ payments)", "orders -> payments", "orders (then payments)",
                                    "orders " + chr(0x2192) + " payments", "orders everything", "entire orders",
                                    "each pod of orders"])
def test_a_second_resource_in_parentheses_or_after_an_arrow_is_refused(target):
    """Fifth review (2026-10-01): parentheses and arrows were read as describing the one target, so a second
    resource written there passed."""
    assert _problem(target) is not None


@pytest.mark.parametrize("target", ["cluster=warden-dev-aurora", "aurora cluster warden-dev-aurora",
                                    "warden-dev-aurora (cluster)"])
def test_a_failover_names_its_cluster(target):
    """Fifth review (2026-10-01): a failover's target is a cluster; `cluster=<name>` was refused as a scope."""
    p = RemediationProposal(action=A.failover_replica, target=target, reasoning="r", expected_effect="e",
                            blast_radius="single_service", reversible=True)
    assert target_problem(p, INV | {"warden-dev-aurora"}, SCOPES) is None


@pytest.mark.parametrize("target", ["checkout (revision 10 -> previous image python:3.12-alpine)",
                                    "deployment/checkout (revision 8 -> 7, image public.ecr.aws/library/python:3.12)"])
def test_an_image_to_return_to_is_not_a_second_resource(target):
    """Recorded model targets (wave 1/2): the image a rollback returns to names inventory words."""
    p = RemediationProposal(action=A.rollback_deploy, target=target, reasoning="r", expected_effect="e",
                            blast_radius="single_service", reversible=True)
    assert target_problem(p, INV | {"python", "3.12-alpine", "3.12"}, SCOPES) is None


def test_a_word_after_a_colon_is_not_an_image_tag():
    assert _problem("orders (x:payments)") is not None


@pytest.mark.parametrize("target", ["orders (rm.)", "orders (DELETE.)", "orders (and delete.)", "orders (kubectl.exe)",
                                    "orders (kill)", "orders then terraform destroy", "orders (shutdown)",
                                    "orders (pkill -f app)"])
def test_more_commands_and_a_command_before_a_period_are_refused(target):
    """Sixth review (2026-10-01): a trailing period read as part of a name, and unlisted commands passed."""
    assert _problem(target) is not None


@pytest.mark.parametrize("key", ["aurora_cluster", "elasticache", "NAMESPACE", "k8s_namespace", "db_cluster",
                                 "Cluster", "kubernetes_namespace"])
def test_every_spelling_of_a_scope_label_scopes_the_target(key):
    """Sixth review (2026-10-01): only five exact keys were scopes."""
    from warden.cli import DEMO_ALERTS
    from warden.models import Alert, Citation, ContextBundle, RootCause
    from warden.verifier import verify

    alert = Alert(**{**DEMO_ALERTS["inc-002"], "labels": {key: "warden-dev-group"}})
    ctx = ContextBundle(logs=["CONFIG deploy revision 7", "x ERROR a", "x ERROR b"], metrics={"error_rate": 0.1},
                        recent_deploys=[{"kind": "ecs", "service": "warden-dev-group"}])
    rc = RootCause(hypothesis="h", confidence=0.9, citations=[Citation(id="C1", quote="deploy revision 7")])
    prop = RemediationProposal(action=A.rollback_deploy, target="warden-dev-group", reasoning="r",
                               expected_effect="e", blast_radius="single_service", reversible=True)
    assert "P14-TARGET-NOT-IN-EVIDENCE" in verify(alert, ctx, rc, prop).policy_ids


@pytest.mark.parametrize("target", ["warden-dev-aurora", "cluster=warden-dev-aurora"])
def test_a_failover_may_name_the_cluster_its_alert_labels(target):
    """Sixth review: with `cluster=warden-dev-aurora` on the alert, the failover of that cluster was refused."""
    p = RemediationProposal(action=A.failover_replica, target=target, reasoning="r", expected_effect="e",
                            blast_radius="single_service", reversible=True)
    assert target_problem(p, INV | {"warden-dev-aurora"}, {"warden-dev-aurora"}) is None


@pytest.mark.parametrize("target", ["namespace=payments", "ns payments"])
def test_a_failover_never_targets_a_namespace(target):
    p = RemediationProposal(action=A.failover_replica, target=target, reasoning="r", expected_effect="e",
                            blast_radius="single_service", reversible=True)
    assert target_problem(p, INV, SCOPES) is not None


def _verdict_policies(action, target, labels):
    from warden.cli import DEMO_ALERTS
    from warden.models import Alert, Citation, ContextBundle, RootCause
    from warden.verifier import verify

    alert = Alert(**{**DEMO_ALERTS["inc-002"], "labels": labels})
    ctx = ContextBundle(logs=["CONFIG deploy revision 7", "x ERROR a", "x ERROR b"], metrics={"error_rate": 0.1},
                        recent_deploys=[{"kind": "ecs", "service": "orders"}])
    rc = RootCause(hypothesis="h", confidence=0.9, citations=[Citation(id="C1", quote="deploy revision 7")])
    prop = RemediationProposal(action=action, target=target, reasoning="r", expected_effect="e",
                               blast_radius="single_service", reversible=True)
    return verify(alert, ctx, rc, prop).policy_ids


FS01 = {"elasticache": "warden-pg-fs-redis", "aurora_cluster": "warden-pg-fs-aurora", "namespace": "payments",
        "ecs_cluster": "warden-pg-fs-ecs"}


@pytest.mark.parametrize("action, target", [(A.clear_cache, "warden-pg-fs-redis"), (A.scale_up, "warden-pg-fs-redis"),
                                            (A.terminate_connections, "warden-pg-fs-aurora")])
def test_a_data_action_may_target_the_database_or_cache_its_alert_labels(action, target):
    """Seventh review (2026-10-01): on the recorded fs-01 labels these natural targets were rejected as scopes
    (a regression from ac1e2ab); 9d01dfd escalated them without P14."""
    assert "P14-TARGET-NOT-IN-EVIDENCE" not in _verdict_policies(action, target, FS01)


@pytest.mark.parametrize("target", ["warden-pg-fs-redis", "warden-pg-fs-aurora", "warden-pg-fs-ecs"])
def test_a_pod_action_on_a_labelled_cluster_still_names_a_whole_cluster(target):
    assert "P14-TARGET-NOT-IN-EVIDENCE" in _verdict_policies(A.rollback_deploy, target, FS01)


@pytest.mark.parametrize("target", ["payments", "namespaces/payments", "namespaces payments", "warden-pg-fs-ecs"])
def test_a_failover_never_targets_a_labelled_namespace_or_compute_cluster(target):
    """Seventh review: only the word "namespace" was refused - the namespace's own name and the ECS cluster
    passed."""
    assert "P14-TARGET-NOT-IN-EVIDENCE" in _verdict_policies(A.failover_replica, target, FS01)


@pytest.mark.parametrize("target", ["orders-ns-db", "aurora-namespace-db"])
def test_a_database_cluster_may_have_ns_inside_its_name(target):
    p = RemediationProposal(action=A.failover_replica, target=target, reasoning="r", expected_effect="e",
                            blast_radius="single_service", reversible=True)
    assert target_problem(p, INV | {target}, SCOPES) is None


@pytest.mark.parametrize("action, target", [
    (A.failover_replica, "warden-pg-fs-aurora -> warden-pg-fs-ecs"), (A.failover_replica, "warden-pg-fs-aurora (and payments)"),
    (A.clear_cache, "warden-pg-fs-redis -> warden-pg-fs-ecs"), (A.clear_cache, "warden-pg-fs-redis (then warden-pg-fs-ecs)"),
    (A.terminate_connections, "warden-pg-fs-aurora (and payments)"),
])
def test_a_data_target_with_a_whole_scope_beside_it_is_refused(action, target):
    """Eighth review (2026-10-01, a regression from 8ce403d): once a labelled database was no longer a scope, a
    namespace or compute cluster written beside it was not counted as a second target."""
    assert "P14-TARGET-NOT-IN-EVIDENCE" in _verdict_policies(action, target, FS01)


@pytest.mark.parametrize("key", ["k8s.namespace.name", "gke_cluster", "aks_cluster", "ecsClusterName"])
def test_a_failover_never_targets_a_compute_scope_in_any_spelling(key):
    """Eighth review: only keys holding ecs/eks/k8s/kube as a substring were compute clusters, and `ClusterName` or
    `k8s.namespace.name` were not read as scopes at all."""
    assert "P14-TARGET-NOT-IN-EVIDENCE" in _verdict_policies(A.failover_replica, "warden-pg-fs-group",
                                                              {**FS01, key: "warden-pg-fs-group"})


def test_a_failover_never_targets_a_namespace_named_like_the_service():
    """Eighth review: the recorded fs-01 alert's namespace is `shop`, its service `shop` - subtracted, so a failover of
    `shop` passed."""
    assert "P14-TARGET-NOT-IN-EVIDENCE" in _verdict_policies(A.failover_replica, "shop", {**FS01, "namespace": "shop"})


@pytest.mark.parametrize("key", ["sandbox_namespace", "feedback_namespace", "records_namespace", "cache_namespace",
                                 "db_namespace"])
def test_a_namespace_is_never_a_data_resource(key):
    """Eighth review: `is_data` was a substring test - "sandbox" holds "db", "records" holds "rds" - so clearing a cache
    or scaling across that whole namespace passed."""
    assert "P14-TARGET-NOT-IN-EVIDENCE" in _verdict_policies(A.clear_cache, "team-x", {key: "team-x"})


@pytest.mark.parametrize("key", ["ClusterName", "k8s.namespace.name", "namespaceName", "cluster-name"])
def test_a_scope_label_in_any_spelling_scopes_a_pod_action(key):
    """Eighth review: camel case and dotted keys were not read as scopes. (A generic `ClusterName`, like `cluster`,
    may name a database cluster, so a failover may still target it - sixth review.)"""
    assert "P14-TARGET-NOT-IN-EVIDENCE" in _verdict_policies(A.rollback_deploy, "warden-pg-fs-group",
                                                              {key: "warden-pg-fs-group"})


def test_a_failover_may_target_its_labelled_database_and_never_its_eks_cluster():
    """Eighth review (test strength): removing failover from the data actions, or EKS from the compute words, passed."""
    assert "P14-TARGET-NOT-IN-EVIDENCE" not in _verdict_policies(A.failover_replica, "warden-pg-fs-aurora", FS01)
    labels = {**FS01, "eks_cluster": "warden-pg-fs-eks"}
    assert "P14-TARGET-NOT-IN-EVIDENCE" in _verdict_policies(A.failover_replica, "warden-pg-fs-eks", labels)


def test_ns_inside_a_labelled_cluster_name_is_not_the_word_namespace():
    """Eighth review: the earlier test never reached the failover branch; with the cluster labelled under a generic
    key, a target named only by that label does - and `\bns\b` refused `orders-ns-db`."""
    assert "P14-TARGET-NOT-IN-EVIDENCE" not in _verdict_policies(A.failover_replica, "orders-ns-db",
                                                                  {"cluster": "orders-ns-db"})
