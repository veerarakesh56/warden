"""Context tools — the evidence layer.

Deliberate design choice: **the model does not call these.** They run first, deterministically, and
their output is redacted before it is shown. A model that chooses its own tool calls also chooses
what evidence to look at, and that turns "what happened?" into "what did it decide to look for?".

Each tool has a timeout and each failure is recorded rather than swallowed, because a partial
picture must be visible to the verifier (policy P8) instead of looking like a complete one.

The fixtures here stand in for real backends. Swapping `LogTool` for a Loki or CloudWatch client is
a change to one class, which is why the boundary is drawn here.
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass

from .models import Alert, ContextBundle

FIXTURES = pathlib.Path(__file__).resolve().parents[2] / "fixtures"


class ToolError(RuntimeError):
    pass


@dataclass
class ToolResult:
    name: str
    ok: bool
    payload: object
    error: str | None = None


class FixtureBackend:
    """Reads recorded incident data. Real deployments substitute a live client here."""

    def __init__(self, root: pathlib.Path | None = None) -> None:
        self.root = root or FIXTURES

    def _load(self, alert_id: str) -> dict:
        path = self.root / f"{alert_id}.json"
        if not path.exists():
            raise ToolError(f"no fixture for alert {alert_id}")
        return json.loads(path.read_text(encoding="utf-8"))

    def logs(self, alert: Alert) -> list[str]:
        return self._load(alert.alert_id).get("logs", [])

    def metrics(self, alert: Alert) -> dict[str, float]:
        return self._load(alert.alert_id).get("metrics", {})

    def deploys(self, alert: Alert) -> list[dict[str, str]]:
        return self._load(alert.alert_id).get("recent_deploys", [])


def gather(alert: Alert, backend: FixtureBackend | None = None) -> ContextBundle:
    """Run every tool, keep what worked, record what did not."""
    backend = backend or FixtureBackend()
    bundle = ContextBundle()

    for name, fn, sink in (
        ("logs", backend.logs, "logs"),
        ("metrics", backend.metrics, "metrics"),
        ("recent_deploys", backend.deploys, "recent_deploys"),
    ):
        try:
            setattr(bundle, sink, fn(alert))
        except Exception as exc:  # noqa: BLE001 - a tool failing is data, not a crash
            bundle.tool_errors.append(f"{name}: {exc}")

    return bundle
