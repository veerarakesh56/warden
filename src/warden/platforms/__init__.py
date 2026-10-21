"""Live platforms behind the RemediationWorkflow - the only write path (decision D16).

A platform reads what a catalogue entry needs (`live`), applies an approved plan (`apply`), says whether
the target is healthy (`healthy`) and undoes what it applied (`rollback`). The workflow decides whether
to act - approval, tier, bounds, kill switch, a fresh precheck - and a platform only carries out the
entry it was given, re-checking its own bounds against what it reads at that moment.
"""

from __future__ import annotations

import inspect
import os
import threading
from collections.abc import Callable
from typing import Any

from ..catalog import CATALOG


class RoutedPlatform:
    """Sends each catalogue entry to the platform for its kind (`k8s`, `db`); an entry of a kind with no
    platform here reads nothing, so the catalogue refuses it - as runtime.NoPlatform does for all."""

    def __init__(self, **platforms: Any) -> None:
        self._by_kind = {kind: p for kind, p in platforms.items() if p is not None}

    def _for(self, entry: str, environment: str | None = None) -> Any | None:
        """The platform for this entry's kind - and, for one serving several environments (AWS), its instance for the
        plan's environment, so a plan reads and writes through that environment's roles only."""
        spec = CATALOG.get(entry)
        p = self._by_kind.get(spec.platform) if spec else None
        if p is not None and environment and hasattr(p, "for_environment"):
            p = p.for_environment(environment)
        return p

    def live(self, entry: str, params: dict[str, Any], environment: str | None = None) -> dict[str, Any]:
        p = self._for(entry, environment)
        return p.live(entry, params) if p else {}

    def apply(self, entry: str, params: dict[str, Any], snapshot: dict[str, Any] | None = None,
              who: dict[str, Any] | None = None, environment: str | None = None) -> str:
        p = self._for(entry, environment)
        if p is None:
            raise RuntimeError(f"no platform is connected for {entry}")
        return p.apply(entry, params, **_accepted(p.apply, snapshot=snapshot, who=who))

    def healthy(self, service: str) -> bool:
        # Asked only of the platforms that know the service: a database platform knows nothing of a
        # Deployment and would call every Kubernetes fix a failure. None knowing it is not healthy -
        # unknown counts as a failure (review C18).
        answers = [p.healthy(service) for p in self._by_kind.values() if p.knows(service)]
        return bool(answers) and all(answers)

    def alarm_state(self, alarm: str, environment: str | None = None) -> str | None:
        """A CloudWatch alarm's state (OK, ALARM, INSUFFICIENT_DATA) as a platform that reads alarms sees it, in the
        plan's environment; None when no connected platform reads alarms."""
        p = next((p for p in self._by_kind.values() if hasattr(p, "alarm_state")), None)
        if p is None:
            return None
        if environment and hasattr(p, "for_environment"):
            p = p.for_environment(environment)
        return p.alarm_state(alarm)

    def reader(self, environment: str | None = None) -> Any | None:
        """The connected AWS platform's read clients in the plan's environment (name -> boto3 client, its reader
        role): the symptom check (symptom.py, B13) reads the alarm's metric and the error logs through it."""
        p = next((p for p in self._by_kind.values() if hasattr(p, "alarm_state")), None)
        if p is not None and environment and hasattr(p, "for_environment"):
            p = p.for_environment(environment)
        return getattr(p, "_read", None)

    def healthy_for(self, entry: str, service: str, params: dict[str, Any] | None = None,
                    environment: str | None = None) -> bool:
        """Health as the platform that carries out `entry` sees it - only that one (sixth review, 2026-10-01: a
        database with a Deployment's name decided the Deployment's verdict). None connected is not healthy. A
        platform serving several kinds (AWS) is told the entry and its parameters: a table and a function may share
        a name, and a service is named by its cluster too."""
        p = self._for(entry, environment)
        return bool(p and p.healthy(service, **_accepted(p.healthy, entry=entry, params=params)))

    def permitted(self, entry: str, params: dict[str, Any], snapshot: dict[str, Any], incident: str,
                  environment: str) -> dict[str, Any] | None:
        """B12: whether the actor allows this plan's calls, from the platform that carries it out; None when that
        platform has no such check (Kubernetes, a database) or none is connected."""
        p = self._for(entry, environment)
        check = getattr(p, "permitted", None)
        return check(entry, params, snapshot, incident=incident, environment=environment) if check else None

    def rollback(self, entry: str, params: dict[str, Any], snapshot: dict[str, Any],
                 who: dict[str, Any] | None = None, environment: str | None = None) -> str:
        p = self._for(entry, environment)
        if p is None:
            raise RuntimeError(f"no platform is connected for {entry}")
        return p.rollback(entry, params, snapshot, **_accepted(p.rollback, who=who))


class NotConfigured(RuntimeError):
    """This environment has none of this platform kind configured (no cluster, no database): nothing was read or
    changed, and the catalogue refuses - a person is told, the worker runs on."""

    nothing_changed = True


class Unconfigured:
    """A platform kind an environment does not have: reads nothing, writes nothing, never crashes a worker."""

    def __init__(self, why: str) -> None:
        self.why = why

    def live(self, *_: Any) -> dict[str, Any]:
        """Nothing is read: the catalogue refuses on an empty read."""
        return {}

    def knows(self, *_: Any) -> bool:
        return False

    def healthy(self, *_: Any) -> bool:
        return False

    def apply(self, entry: str, params: dict[str, Any], snapshot: dict[str, Any] | None = None,
              who: dict[str, Any] | None = None) -> str:
        raise NotConfigured(f"{self.why}; nothing was changed")

    def rollback(self, entry: str, params: dict[str, Any], snapshot: dict[str, Any],
                 who: dict[str, Any] | None = None) -> str:
        raise NotConfigured(f"{self.why}; nothing was changed")


class PerEnvironment(Unconfigured):
    """One platform per watched environment, built the first time a plan names it (the cloud runtime: each
    environment's own roles, cluster or database). `build` raises NotConfigured for an environment it cannot serve,
    which then reads and writes nothing. With no environment named, nothing is read or written either."""

    def __init__(self, build: Callable[[str], Any], kind: str) -> None:
        super().__init__(f"no environment was named for this {kind} call")
        self._build, self._made, self._lock = build, {}, threading.Lock()

    def for_environment(self, environment: str) -> Any:
        with self._lock:
            if environment not in self._made:
                try:
                    self._made[environment] = self._build(environment)
                except NotConfigured as exc:
                    self._made[environment] = Unconfigured(str(exc))
                except Exception as exc:  # noqa: BLE001  # a build that fails otherwise also changes nothing and says why
                    self._made[environment] = Unconfigured(
                        f"{environment}'s platform could not be built ({type(exc).__name__})")
            return self._made[environment]


def role_arn(environment: str, role: str) -> str:
    """A watched environment's role (`platform-reader`, `actor`) from WARDEN_AWS_ROLE_ARN_TEMPLATE
    (`...:role/warden-{env}-{role}`, set by the runtime module); NotConfigured when there is no such template or the
    environment is not one of environments.yaml's."""
    from ..environments import default_environment_policies

    template = os.environ.get("WARDEN_AWS_ROLE_ARN_TEMPLATE", "").strip()
    if not template.startswith("arn:aws:iam::") or "{env}" not in template or "{role}" not in template:
        raise NotConfigured("WARDEN_AWS_ROLE_ARN_TEMPLATE is not an IAM role ARN with {env} and {role}")
    if environment not in default_environment_policies().known_environments:
        raise NotConfigured(f"{environment!r} is not a configured environment")
    return template.format(env=environment, role=role)


def reader_clients(sts: Any, where: str, reader_arn: str) -> Callable[[str], Any]:
    """Clients in an environment's reader role. The session lasts 15 minutes; it is renewed after 10, so no read runs
    on one about to expire."""
    import time

    from .. import identity

    held: dict[str, Any] = {}
    lock = threading.Lock()

    def reader(service: str) -> Any:
        with lock:
            if held.get("until", 0) < time.monotonic():
                creds = identity.reader_session(sts, role_arn=reader_arn, incident="warden-worker")
                held["clients"], held["until"] = session_clients(creds, where), time.monotonic() + 600
            return held["clients"](service)

    return reader


def session_clients(creds: dict[str, str], where: str) -> Callable[[str], Any]:
    """boto3 clients on one set of session credentials."""
    import boto3

    s = boto3.Session(**creds, region_name=where)
    return lambda service: s.client(service)


def _accepted(method: Any, **extra: Any) -> dict[str, Any]:
    """The keyword arguments `method` takes, of those given: the Kubernetes and database platforms take no `who`."""
    names = inspect.signature(method).parameters
    return {k: v for k, v in extra.items() if k in names}
