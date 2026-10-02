"""Per-environment policy: which environment may do what, who may approve it, and whether WARDEN may
resolve an incident automatically or must hand it to a human.

This is the configurable core of the staging -> prod safety gradient. `data/environments.yaml` ships
a sane default; an operator overrides it with `$WARDEN_ENV_POLICY_PATH` or a path argument. Everything
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
import re
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
    # A POINTER to where this environment's credentials/account live — a k8s ServiceAccount name, a
    # cloud IAM role, a Secrets-Manager id. NEVER the secret itself; WARDEN never stores a credential.
    # It lets the policy express "which account acts in this environment" and lets a promotion report
    # tell a human which credential to use in the target env. None = inherit the deployment default.
    credentials_ref: str | None = None
    # The injection tripwire in this environment: off, on, or required (register R47). The stricter of this and
    # WARDEN_TRIPWIRE applies.
    tripwire: str = "off"

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
    def __init__(self, default: EnvPolicy, environments: dict[str, EnvPolicy], runtime: str | None = None,
                 aws_region: str | None = None) -> None:
        self.runtime_environment = runtime
        self.aws_region = aws_region
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
            credentials_ref=self._default.credentials_ref,
            tripwire=self._default.tripwire,
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
            # The name becomes AWS names (`warden-<env>-...`, a role, an SSM path): lower-case letters, digits and
            # dashes only (audit A-B-L12).
            if not isinstance(name, str) or not _ENV_NAME.fullmatch(name):
                raise EnvironmentPolicyError(f"environment name {name!r} must match {_ENV_NAME.pattern}")
            envs[name] = cls._parse(name, raw)
        if not envs:
            raise EnvironmentPolicyError("environment policy defines no environments")
        runtime = doc.get("runtime")
        if runtime is not None and (not isinstance(runtime, str) or runtime in envs):
            raise EnvironmentPolicyError("`runtime` must name WARDEN's own environment, not an application one")
        region = doc.get("aws_region")
        if region is not None and not (isinstance(region, str) and _REGION.fullmatch(region)):
            raise EnvironmentPolicyError(f"`aws_region` is not a region name: {region!r}")
        return cls(default, envs, runtime, region)

    @staticmethod
    def _read_source(path: str | os.PathLike[str] | None) -> str:
        chosen = path or os.environ.get("WARDEN_ENV_POLICY_PATH")
        if chosen:
            p = Path(chosen)
            if not p.is_file():
                raise EnvironmentPolicyError(f"environment policy not found at {p}")
            return p.read_text(encoding="utf-8")
        res = resources.files("warden") / "data" / "environments.yaml"
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
            auto_remediate=_flag(name, raw, "auto_remediate", False),
            require_human_approval=_flag(name, raw, "require_human_approval", True),
            allow_actions=allow,
            deny_actions=deny,
            authorized_principals=frozenset(str(p) for p in principals),
            credentials_ref=raw.get("credentials_ref"),
            tripwire=_tripwire(name, raw),
        )


_ENV_NAME = re.compile(r"[a-z][a-z0-9-]{0,30}")


def _tripwire(name: str, raw: dict[str, Any]) -> str:
    value = raw.get("tripwire", "off")
    if value not in ("off", "on", "required"):
        raise EnvironmentPolicyError(f"{name}: tripwire must be off, on or required, not {value!r}")
    return value


def _flag(name: str, raw: dict[str, Any], key: str, default: bool) -> bool:
    """A YAML boolean, nothing else: `bool("false")` is True, and read so a quoted "false" armed auto_remediate
    (audit A-B-L12)."""
    value = raw.get(key, default)
    if not isinstance(value, bool):
        raise EnvironmentPolicyError(f"{name}: {key} must be true or false, not {value!r}")
    return value


_DEFAULT: EnvironmentPolicies | None = None


def default_environment_policies() -> EnvironmentPolicies:
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = EnvironmentPolicies.load()
    return _DEFAULT


@dataclass(frozen=True)
class EnvNames:
    """Every name an environment uses in AWS, derived from the environment name alone (v2 Phase 1.5):
    nothing per environment is stored, so nothing can drift or be hardcoded twice."""

    env: str
    prefix: str        # resource names: warden-<env>-...
    ssm: str           # parameter root: /warden/<env>/
    role: str          # deploy role: warden-<env>-deploy
    boundary: str      # permissions boundary: WardenEnvBoundary-<env>
    tags: dict[str, str]
    region: str        # the AWS region (environments.yaml `aws_region`)


def _all_names() -> tuple[str, ...]:
    """The application environments and WARDEN's own runtime environment."""
    policies = default_environment_policies()
    return policies.known_environments + ((policies.runtime_environment,) if policies.runtime_environment else ())


def env_of_name(name: str) -> str | None:
    """The environment a `warden-<env>-...` name belongs to, longest environment first (as strip_prefix); None
    for any other name."""
    for env in sorted(_all_names(), key=len, reverse=True):
        if name.startswith(f"warden-{env}-"):
            return env
    return None


def strip_prefix(name: str) -> str:
    """`warden-<env>-checkout` -> `checkout` for any configured environment; other names unchanged.
    Longest environment first, so `warden-qa-staging-x` is not read as environment `qa`."""
    for env in sorted(_all_names(), key=len, reverse=True):
        if name.startswith(f"warden-{env}-"):
            return name[len(f"warden-{env}-"):]
    return name


def names(env: str) -> EnvNames:
    """The names for `env`, which must be a configured environment. Unlike for_env(), an unknown name
    RAISES here: the policy side fails closed to `default`, but a typo must never become an AWS name."""
    if env not in _all_names():
        raise EnvironmentPolicyError(f"unknown environment {env!r}; configured: {', '.join(_all_names())}")
    return EnvNames(env=env, prefix=f"warden-{env}", ssm=f"/warden/{env}/", role=f"warden-{env}-deploy",
                    boundary=f"WardenEnvBoundary-{env}", tags={"Project": "warden", "Environment": env},
                    region=region())


_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-\d")


def region() -> str:
    """The AWS region: AWS_REGION when set (as every AWS tool reads it), else environments.yaml `aws_region`.
    Never a literal in code (owner requirements R17, R32)."""
    chosen = os.environ.get("AWS_REGION") or default_environment_policies().aws_region
    if not chosen or not _REGION.fullmatch(chosen):
        raise EnvironmentPolicyError(f"no usable AWS region (AWS_REGION or environments.yaml aws_region): {chosen!r}")
    return chosen
