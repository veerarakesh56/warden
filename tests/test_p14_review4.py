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
