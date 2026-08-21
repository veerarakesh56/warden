"""Context tools — the evidence layer.

Deliberate design choice: **the model does not call these.** They run first, deterministically, and
their output is redacted before it is shown. A model that chooses its own tool calls also chooses
what evidence to look at, and that turns "what happened?" into "what did it decide to look for?".

Every tool runs under a **real wall-clock timeout** and every failure is recorded rather than
swallowed, because a partial picture must be visible to the verifier (policy P8) instead of looking
like a complete one. A hung logging backend during an incident is the normal case, not the edge one.

The fixtures here stand in for real backends. Swapping `FixtureBackend` for a Loki, CloudWatch or
Datadog client is a change to one class, which is why the boundary is drawn here.
"""

from __future__ import annotations

import json
import os
import pathlib
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass

from .models import Alert, ContextBundle
from .observability import span

FIXTURES = pathlib.Path(__file__).resolve().parents[2] / "fixtures"

# Wall-clock ceiling per tool. Threads are used rather than signals because signal-based timeouts
# are POSIX-main-thread only, and this has to behave identically on Windows and in a container.
TOOL_TIMEOUT_S = float(os.environ.get("AEGIS_TOOL_TIMEOUT", "5.0"))


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


def _call_with_timeout(fn, alert: Alert, timeout: float):
    """Run one tool under a wall-clock ceiling.

    ⚠ A timed-out worker thread is abandoned, not killed — Python cannot force-stop a thread. That
    is acceptable here because the caller stops waiting, which is what the deadline is for. A real
    deployment should also set a socket timeout on the backend client so the thread actually ends.

    ⛔ The executor is shut down with `wait=False` deliberately. Using `ThreadPoolExecutor` as a
    context manager calls `shutdown(wait=True)` on exit, which blocks until the hung thread
    finishes — so the deadline fired and the caller waited the full duration anyway. The timeout
    looked implemented and did nothing. Caught by `test_a_hanging_tool_does_not_hang_the_run`.
    """
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        return pool.submit(fn, alert).result(timeout=timeout)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


def gather(
    alert: Alert,
    backend: FixtureBackend | None = None,
    *,
    timeout: float | None = None,
) -> ContextBundle:
    """Run every tool, keep what worked, record what did not."""
    backend = backend or FixtureBackend()
    timeout = TOOL_TIMEOUT_S if timeout is None else timeout
    bundle = ContextBundle()

    for name, fn, sink in (
        ("logs", backend.logs, "logs"),
        ("metrics", backend.metrics, "metrics"),
        ("recent_deploys", backend.deploys, "recent_deploys"),
    ):
        with span(f"tool.{name}", tool=name, timeout_s=timeout) as sp:
            try:
                setattr(bundle, sink, _call_with_timeout(fn, alert, timeout))
                sp.set_attribute("aegis.tool.ok", True)
            except FutureTimeout:
                msg = f"{name}: timed out after {timeout:.1f}s"
                bundle.tool_errors.append(msg)
                sp.set_attribute("aegis.tool.ok", False)
                sp.set_attribute("aegis.tool.error", msg)
            except Exception as exc:  # noqa: BLE001 - a tool failing is data, not a crash
                msg = f"{name}: {exc}"
                bundle.tool_errors.append(msg)
                sp.set_attribute("aegis.tool.ok", False)
                sp.set_attribute("aegis.tool.error", msg)

    return bundle
