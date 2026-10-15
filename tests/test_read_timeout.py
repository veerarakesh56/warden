"""Inventory review, 2026-10-15: the cloud's stack read - every resource the alert names, a Logs Insights wait of up to
10 s among them, then each outside source - ran under the 5 s per-tool default, which could cut it off and lose the
logs view. A backend now says how long its whole read may take, and gather waits that long."""

from __future__ import annotations

import time

from warden import tools
from warden.aws_stack import StackBackend
from warden.models import Alert

ALERT = Alert(alert_id="a", name="n", severity="high", service="s", environment="dev", summary="s",
              started_at="2026-10-15T12:00:00+00:00")


class _Slow:
    def __init__(self, budget=None):
        if budget is not None:
            self.read_timeout_s = budget

    def logs(self, alert):
        time.sleep(0.4)
        return ["LOG x ERROR boom"]

    def metrics(self, alert):
        return {"m": 1.0}

    def deploys(self, alert):
        return []


def test_a_backend_that_says_its_read_takes_longer_is_waited_for(monkeypatch):
    monkeypatch.setattr(tools, "TOOL_TIMEOUT_S", 0.1)
    cut = tools.gather(ALERT, _Slow())
    assert not cut.logs and any("timed out" in e for e in cut.tool_errors)
    whole = tools.gather(ALERT, _Slow(budget=5))
    assert whole.logs == ["LOG x ERROR boom"] and not whole.tool_errors
    assert tools.gather(ALERT, _Slow(budget=5), timeout=0.1).tool_errors  # the explicit argument still wins


def test_the_stack_reader_allows_its_whole_read():
    assert StackBackend.read_timeout_s >= 60
