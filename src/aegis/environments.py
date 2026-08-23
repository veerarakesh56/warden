"""Per-environment policy: which environment may do what, who may approve it, and whether AEGIS may
resolve an incident automatically or must hand it to a human.

This is the configurable core of the staging -> prod safety gradient. `data/environments.yaml` ships
a sane default; an operator overrides it with `$AEGIS_ENV_POLICY_PATH` or a path argument. Everything
is validated at load (unknown action names raise), and an environment absent from the config resolves
to the `default` policy, which is the most restrictive one possible — the system FAILS CLOSED on an
unrecognised environment rather than inheriting broad permissions.

Two consumers:
  - the verifier reads `permits(action)` for policy P1 (is this action admissible in this env at all);
  - the remediation executor reads `auto_remediate`, `require_human_approval` and `authorizes(principal)`
    to decide whether a given principal may actually APPLY an approved fix here, now.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from .models import ActionKind

# Always permitted, in every environment including the restrictive default: the system must never be
# unable to do nothing or to hand off to a person. These are added to every allow set at load.
_ALWAYS = frozenset({ActionKind.no_action, ActionKind.escalate_to_human})


class EnvironmentPolicyError(RuntimeError):
    """The environment policy is malformed. Fatal at load."""


def _actions(sid: str, kfield: str, values: Any) -> frozenset[ActionKind]:
    if values in (None, []):
        return frozenset()
    if not isinstance(values, list):
        raise EnvironmentPolicyError(f"{sid}: {kfield} must be a list")
    if values == ["*"]:
        return frozenset(ActionKind)
    out: set[ActionKind] = set()
    for v in values:
        if v == "*":
            return frozenset(ActionKind)
        try:
            out.add(ActionKind(v))
        except ValueError as exc:
            raise EnvironmentPolicyError(
                f"{sid}: '{v}' in {kfield} is not a valid ActionKind"
            ) from exc
    return frozenset(out)


@dataclass(frozen=True)
class EnvPolicy:
    name: str
    tier: str
    auto_remediate: bool
    require_human_approval: bool
    allow_actions: frozenset[ActionKind]
    deny_actions: frozenset[ActionKind]
    authorized_principals: frozenset[str]

    def permits(self, action: ActionKind) -> bool:
        """Is `action` admissible in this environment? Deny wins over allow."""
        if action in self.deny_actions:
            return False
        return action in self.allow_actions

    def authorizes(self, principal: str | None) -> bool:
        """May `principal` approve/apply an action here? '*' in the list means anyone."""
        if not principal:
            return False
        return "*" in self.authorized_principals or principal in self.authorized_principals


class EnvironmentPolicies:
    def __init__(self, default: EnvPolicy, environments: dict[str, EnvPolicy]) -> None:
        self._default = default
        self._envs = environments

    def for_env(self, name: str | None) -> EnvPolicy:
        """The policy for `name`, or the restrictive default for an unknown/None environment."""
        if name and name in self._envs:
            return self._envs[name]
        # Fail closed: an unrecognised environment gets the default, re-labelled so a report shows
        # which environment string was asked for.
        return EnvPolicy(
            name=name or "unknown",
            tier=self._default.tier,
            auto_remediate=self._default.auto_remediate,
            require_human_approval=self._default.require_human_approval,
            allow_actions=self._default.allow_actions,
            deny_actions=self._default.deny_actions,
            authorized_principals=self._default.authorized_principals,
        )

    @property
    def known_environments(self) -> tuple[str, ...]:
        return tuple(self._envs)

    # --------------------------------------------------------------- loading

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None = None) -> EnvironmentPolicies:
        text = cls._read_source(path)
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise EnvironmentPolicyError(f"environment policy is not valid YAML: {exc}") from exc
        if not isinstance(doc, dict):
            raise EnvironmentPolicyError("environment policy must be a mapping")

        default = cls._parse("default", doc.get("default", {}))
        envs: dict[str, EnvPolicy] = {}
        for name, raw in (doc.get("environments") or {}).items():
            envs[name] = cls._parse(name, raw)
        if not envs:
            raise EnvironmentPolicyError("environment policy defines no environments")
        return cls(default, envs)

    @staticmethod
    def _read_source(path: str | os.PathLike[str] | None) -> str:
        chosen = path or os.environ.get("AEGIS_ENV_POLICY_PATH")
        if chosen:
            p = Path(chosen)
            if not p.is_file():
                raise EnvironmentPolicyError(f"environment policy not found at {p}")
            return p.read_text(encoding="utf-8")
        res = resources.files("aegis") / "data" / "environments.yaml"
        return res.read_text(encoding="utf-8")

    @staticmethod
    def _parse(name: str, raw: dict[str, Any]) -> EnvPolicy:
        if not isinstance(raw, dict):
            raise EnvironmentPolicyError(f"{name}: policy must be a mapping")
        allow = _actions(name, "allow_actions", raw.get("allow_actions")) | _ALWAYS
        deny = _actions(name, "deny_actions", raw.get("deny_actions"))
        principals = raw.get("authorized_principals") or []
        if not isinstance(principals, list):
            raise EnvironmentPolicyError(f"{name}: authorized_principals must be a list")
        return EnvPolicy(
            name=name,
            tier=str(raw.get("tier", "unknown")),
            auto_remediate=bool(raw.get("auto_remediate", False)),
            require_human_approval=bool(raw.get("require_human_approval", True)),
            allow_actions=allow,
            deny_actions=deny,
            authorized_principals=frozenset(str(p) for p in principals),
        )


_DEFAULT: EnvironmentPolicies | None = None


def default_environment_policies() -> EnvironmentPolicies:
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = EnvironmentPolicies.load()
    return _DEFAULT
