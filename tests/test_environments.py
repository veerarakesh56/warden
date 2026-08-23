"""Per-environment policy: it loads, validates loudly, and — critically — fails closed."""

from __future__ import annotations

import pytest

from aegis.environments import (
    EnvironmentPolicies,
    EnvironmentPolicyError,
    default_environment_policies,
)
from aegis.models import ActionKind

# ------------------------------------------------------------------ the shipped policy

def test_bundled_policy_has_the_five_tier_gradient():
    pol = default_environment_policies()
    known = set(pol.known_environments)
    assert {"staging", "qa-staging", "pre-prod", "qa-prod", "prod"} <= known


def test_low_environments_auto_remediate_and_high_ones_do_not():
    pol = default_environment_policies()
    assert pol.for_env("staging").auto_remediate is True
    assert pol.for_env("qa-staging").auto_remediate is True
    # Everything at or above pre-prod must NOT auto-remediate.
    assert pol.for_env("pre-prod").auto_remediate is False
    assert pol.for_env("qa-prod").auto_remediate is False
    assert pol.for_env("prod").auto_remediate is False


def test_prod_never_auto_remediates_and_denies_scale_down():
    prod = default_environment_policies().for_env("prod")
    assert prod.auto_remediate is False
    assert prod.require_human_approval is True
    assert prod.permits(ActionKind.scale_down) is False


def test_no_action_and_escalate_are_always_permitted_everywhere():
    pol = default_environment_policies()
    for env in (*pol.known_environments, "some-unlisted-env"):
        p = pol.for_env(env)
        assert p.permits(ActionKind.no_action)
        assert p.permits(ActionKind.escalate_to_human)


# ------------------------------------------------------------------ fail closed

def test_unknown_environment_resolves_to_restrictive_default():
    pol = default_environment_policies()
    p = pol.for_env("totally-made-up")
    assert p.auto_remediate is False
    assert p.require_human_approval is True
    # Can only do nothing / escalate — no infrastructure action, no authorised principals.
    assert p.permits(ActionKind.restart_pods) is False
    assert p.permits(ActionKind.rollback_deploy) is False
    assert p.authorizes("role:oncall") is False


def test_none_environment_also_fails_closed():
    p = default_environment_policies().for_env(None)
    assert p.permits(ActionKind.restart_pods) is False


# ------------------------------------------------------------------ authorization

def test_authorizes_only_listed_principals():
    staging = default_environment_policies().for_env("staging")
    assert staging.authorizes("role:oncall") is True
    assert staging.authorizes("role:intern") is False
    assert staging.authorizes(None) is False
    assert staging.authorizes("") is False


def test_wildcard_principal_allows_anyone_in_dev_only():
    pol = default_environment_policies()
    assert pol.for_env("dev").authorizes("anybody-at-all") is True
    assert pol.for_env("prod").authorizes("anybody-at-all") is False


# ------------------------------------------------------------------ loud validation

def _policy(env_block: dict) -> EnvironmentPolicies:
    """Build a policy through the real parser/validator from an in-memory environment block."""
    return EnvironmentPolicies(
        EnvironmentPolicies._parse("default", {}),
        {"e": EnvironmentPolicies._parse("e", env_block)},
    )


def test_a_fake_action_in_allowlist_is_rejected():
    with pytest.raises(EnvironmentPolicyError, match="not a valid ActionKind"):
        _policy({"allow_actions": ["restart_pods", "delete_everything"]})


def test_a_fake_action_in_denylist_is_rejected():
    with pytest.raises(EnvironmentPolicyError, match="not a valid ActionKind"):
        _policy({"deny_actions": ["format_disks"]})


def test_deny_wins_over_allow():
    # An action both allowed and denied is denied.
    p = _policy({"allow_actions": ["restart_pods"], "deny_actions": ["restart_pods"]})
    assert p.for_env("e").permits(ActionKind.restart_pods) is False


def test_wildcard_allow_expands_to_every_action():
    p = _policy({"allow_actions": ["*"]})
    e = p.for_env("e")
    assert all(e.permits(a) for a in ActionKind)


def test_empty_policy_defines_no_environments_raises(tmp_path):
    p = tmp_path / "env.yaml"
    p.write_text("version: 1\ndefault: {}\nenvironments: {}\n", encoding="utf-8")
    with pytest.raises(EnvironmentPolicyError, match="no environments"):
        EnvironmentPolicies.load(p)
