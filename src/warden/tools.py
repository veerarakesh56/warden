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
from .redaction import redact

# Fixtures live INSIDE the package and are shipped as package data.
#
# ⛔ They used to sit at the repo root, found via `parents[2] / "fixtures"`. That works from a
# source checkout and silently breaks once the package is pip-installed: the path resolves to
# `<site-packages>/../../fixtures`, which does not exist. In the container every tool therefore
# failed, the context came back empty, and the demo returned AUTO_SAFE for all four incidents —
# wrong answers, exit code 0, and a green CI job that only checked the exit code.
FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"

# Wall-clock ceiling per tool. Threads are used rather than signals because signal-based timeouts
# are POSIX-main-thread only, and this has to behave identically on Windows and in a container.
TOOL_TIMEOUT_S = float(os.environ.get("WARDEN_TOOL_TIMEOUT", "5.0"))


class ToolError(RuntimeError):
    pass


# A backend that reads many things (several pods' logs, say) may succeed on most and fail on one.
# Raising would lose the successes; returning the failure as a plain line lets the verifier count
# it as EVIDENCE. So: a line carrying this prefix is a partial failure. `gather()` moves every such
# line out of the result and into `tool_errors`, where policy P8 reads it.
PARTIAL_PREFIX = "TOOL-PARTIAL "


def resolve_backend(name: str | None = None):
    """Pick the evidence source from `WARDEN_BACKEND`.

        fixture     recorded incidents shipped with the package (default; what CI uses)
        k8s         a live Kubernetes cluster via kubeconfig or in-cluster credentials

    Same shape as `providers.resolve()`: the optional client is imported lazily, so the core
    package installs and runs with no cluster library present.
    """
    name = (name or os.environ.get("WARDEN_BACKEND") or "fixture").lower()
    if name in ("fixture", "fixtures", "mock"):
        return FixtureBackend()
    if name in ("k8s", "kubernetes"):
        try:
            from .k8s_backend import KubernetesBackend
        except ImportError as exc:  # the `kubernetes` client is an optional extra
            raise ToolError(
                "WARDEN_BACKEND=k8s needs the Kubernetes client: pip install -e '.[k8s]'"
            ) from exc
        return KubernetesBackend()
    raise ToolError(f"unknown backend '{name}'. Known: fixture, k8s")


@dataclass
class ToolResult:
    name: str
    ok: bool
    payload: object
    error: str | None = None


class FixtureBackend:
    """Reads recorded incident data. Real deployments substitute a live client here."""

    name = "fixture"

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
                result = _call_with_timeout(fn, alert, timeout)
                if isinstance(result, list):
                    # Partial failures travel in-band; route them to where the verifier looks.
                    partial = [x for x in result if isinstance(x, str) and x.startswith(PARTIAL_PREFIX)]
                    result = [x for x in result if x not in partial]
                    for p in partial:
                        # Error TEXT is scrubbed: a backend exception (a connection error naming a
                        # host/IP, a k8s message with pod content) would otherwise put a raw
                        # identifier into tool_errors (the audit trail) AND the span attribute
                        # (exported to a third-party tracing backend) unredacted. The model never
                        # sees tool_errors, but those two surfaces still must not carry a secret.
                        bundle.tool_errors.append(redact(f"{name}: {p[len(PARTIAL_PREFIX):]}").text)
                    sp.set_attribute("warden.tool.partial_failures", len(partial))
                setattr(bundle, sink, result)
                sp.set_attribute("warden.tool.ok", True)
            except FutureTimeout:
                msg = f"{name}: timed out after {timeout:.1f}s"
                bundle.tool_errors.append(msg)
                sp.set_attribute("warden.tool.ok", False)
                sp.set_attribute("warden.tool.error", msg)
            except Exception as exc:  # noqa: BLE001 - a tool failing is data, not a crash
                msg = redact(f"{name}: {exc}").text  # scrub raw identifiers out of the error text
                bundle.tool_errors.append(msg)
                sp.set_attribute("warden.tool.ok", False)
                sp.set_attribute("warden.tool.error", msg)

    return bundle
