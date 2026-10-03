"""Live platforms behind the RemediationWorkflow - the only write path (decision D16).

A platform reads what a catalogue entry needs (`live`), applies an approved plan (`apply`), says whether
the target is healthy (`healthy`) and undoes what it applied (`rollback`). The workflow decides whether
to act - approval, tier, bounds, kill switch, a fresh precheck - and a platform only carries out the
entry it was given, re-checking its own bounds against what it reads at that moment.
"""

from __future__ import annotations

import inspect
from typing import Any

from ..catalog import CATALOG


class RoutedPlatform:
    """Sends each catalogue entry to the platform for its kind (`k8s`, `db`); an entry of a kind with no
    platform here reads nothing, so the catalogue refuses it - as runtime.NoPlatform does for all."""

    def __init__(self, **platforms: Any) -> None:
        self._by_kind = {kind: p for kind, p in platforms.items() if p is not None}

    def _for(self, entry: str) -> Any | None:
        spec = CATALOG.get(entry)
        return self._by_kind.get(spec.platform) if spec else None

    def live(self, entry: str, params: dict[str, Any]) -> dict[str, Any]:
        p = self._for(entry)
        return p.live(entry, params) if p else {}

    def apply(self, entry: str, params: dict[str, Any], snapshot: dict[str, Any] | None = None,
              who: dict[str, Any] | None = None) -> str:
        p = self._for(entry)
        if p is None:
            raise RuntimeError(f"no platform is connected for {entry}")
        return p.apply(entry, params, **_accepted(p.apply, snapshot=snapshot, who=who))

    def healthy(self, service: str) -> bool:
        # Asked only of the platforms that know the service: a database platform knows nothing of a
        # Deployment and would call every Kubernetes fix a failure. None knowing it is not healthy -
        # unknown counts as a failure (review C18).
        answers = [p.healthy(service) for p in self._by_kind.values() if p.knows(service)]
        return bool(answers) and all(answers)

    def healthy_for(self, entry: str, service: str, params: dict[str, Any] | None = None) -> bool:
        """Health as the platform that carries out `entry` sees it - only that one (sixth review, 2026-10-01: a
        database with a Deployment's name decided the Deployment's verdict). None connected is not healthy. A
        platform serving several kinds (AWS) is told the entry and its parameters: a table and a function may share
        a name, and a service is named by its cluster too."""
        p = self._for(entry)
        return bool(p and p.healthy(service, **_accepted(p.healthy, entry=entry, params=params)))

    def rollback(self, entry: str, params: dict[str, Any], snapshot: dict[str, Any],
                 who: dict[str, Any] | None = None) -> str:
        p = self._for(entry)
        if p is None:
            raise RuntimeError(f"no platform is connected for {entry}")
        return p.rollback(entry, params, snapshot, **_accepted(p.rollback, who=who))


def _accepted(method: Any, **extra: Any) -> dict[str, Any]:
    """The keyword arguments `method` takes, of those given: the Kubernetes and database platforms take no `who`."""
    names = inspect.signature(method).parameters
    return {k: v for k, v in extra.items() if k in names}
