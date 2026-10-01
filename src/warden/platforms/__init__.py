"""Live platforms behind the RemediationWorkflow - the only write path (decision D16).

A platform reads what a catalogue entry needs (`live`), applies an approved plan (`apply`), says whether
the target is healthy (`healthy`) and undoes what it applied (`rollback`). The workflow decides whether
to act - approval, tier, bounds, kill switch, a fresh precheck - and a platform only carries out the
entry it was given, re-checking its own bounds against what it reads at that moment.
"""

from __future__ import annotations

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

    def apply(self, entry: str, params: dict[str, Any]) -> str:
        p = self._for(entry)
        if p is None:
            raise RuntimeError(f"no platform is connected for {entry}")
        return p.apply(entry, params)

    def healthy(self, service: str) -> bool:
        # Asked only of the platforms that know the service: a database platform knows nothing of a
        # Deployment and would call every Kubernetes fix a failure. None knowing it is not healthy -
        # unknown counts as a failure (review C18).
        answers = [p.healthy(service) for p in self._by_kind.values() if p.knows(service)]
        return bool(answers) and all(answers)

    def rollback(self, entry: str, params: dict[str, Any], snapshot: dict[str, Any]) -> str:
        p = self._for(entry)
        if p is None:
            raise RuntimeError(f"no platform is connected for {entry}")
        return p.rollback(entry, params, snapshot)
