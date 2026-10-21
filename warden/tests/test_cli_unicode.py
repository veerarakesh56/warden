"""The CLI must never crash while REPORTING a diagnosis it has already made.

⛔ Found by a live benchmark wave. The model writes `→` into its own hypotheses. On Windows a piped
stdout is cp1252, which has no `→`, so printing the hypothesis raised UnicodeEncodeError - after the
whole diagnosis had succeeded, and before the JSON report was written. Three runs in one wave were
lost this way and recorded as ERROR, and the handoff already warned about exactly this failure:
a program that crashes while reporting its findings dies precisely when it matters.
"""

from __future__ import annotations

import io
import json
import sys

from warden import cli, graph
from warden.models import RootCause


def test_a_hypothesis_the_terminal_cannot_encode_does_not_lose_the_report(tmp_path, monkeypatch):
    real_run = graph.run

    def run_with_an_arrow(alert, **kw):
        report = real_run(alert, **kw)
        return report.model_copy(update={"root_cause": RootCause(
            hypothesis="new revision → OOM → crash loop", confidence=0.9)})

    monkeypatch.setattr(cli, "run", run_with_an_arrow)
    monkeypatch.setenv("WARDEN_MOCK", "1")
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(io.BytesIO(), encoding="cp1252"))
    out = tmp_path / "report.json"

    assert cli.main(["run", "--alert", "scenarios/alert.yaml", "--json", str(out)]) == 0
    assert out.exists(), "the report must be written even if the terminal cannot display it"
    assert "→" in json.loads(out.read_text(encoding="utf-8"))["root_cause"]["hypothesis"]
