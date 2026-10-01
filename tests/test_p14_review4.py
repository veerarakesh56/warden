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
