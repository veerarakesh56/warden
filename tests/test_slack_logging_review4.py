"""The Slack conversion, the log formatter and the MCP server's last line of defence (fourth review,
2026-09-30, A-2, A-3, A-4, A-8)."""

from __future__ import annotations

import logging

from warden import chatops, mcp_server
from warden.observability import GatedFormatter

LS, PS, NBSP = chr(0x2028), chr(0x2029), chr(0xA0)


def test_a_line_separator_does_not_make_a_heading():
    """Markdown does not break a line at U+2028; splitlines() did, so the Slack text grew a bold line
    that no other view of the report has."""
    for sep in (LS, PS):
        out = chatops.to_slack_mrkdwn(f"ok{sep}# Fix - approved")
        assert "*Fix - approved*" not in out and LS not in out and PS not in out, out


def test_a_no_break_space_does_not_make_a_heading():
    assert chatops.to_slack_mrkdwn(f"#{NBSP}Fix - approved") == f"#{NBSP}Fix - approved"


def test_an_indented_code_block_is_left_alone():
    """The gate keeps fences inside list items; only column 0 was tracked, so the body was converted."""
    md = "- step\n  ```\n  a**b**c\n  ```\n**after**"
    assert chatops.to_slack_mrkdwn(md) == "- step\n  ```\n  a**b**c\n  ```\n*after*"


def test_a_split_inside_an_indented_code_block_reopens_it():
    """Split inside such a body, the rest - with a URL - became Slack prose, which Slack links."""
    body = "\n".join(f"  https://evil.example/{i}" for i in range(400))
    parts = chatops.split_for_slack(f"- step\n  ```\n{body}\n  ```\ndone", limit=2000)
    assert len(parts) > 1
    for part in parts[1:]:
        assert part.split("\n")[1] == "```", part[:80]
    for part in parts[:-1]:
        assert part.rstrip().endswith("```"), part[-80:]


def test_a_line_separator_cannot_forge_a_log_record():
    record = logging.LogRecord("x", logging.INFO, "f", 1, f"note{LS}2026-09-30 INFO warden: approved{PS}more",
                               None, None)
    out = GatedFormatter("%(levelname)s %(name)s: %(message)s").format(record)
    assert LS not in out and PS not in out
    assert out.splitlines()[1].startswith("    2026-09-30"), out


def _run_main(monkeypatch, capsys, exc):
    def boom():
        raise exc
    monkeypatch.setattr(mcp_server, "_serve", boom)
    try:
        code = mcp_server.main()
    finally:
        logging.captureWarnings(False)
    return code, capsys.readouterr()


def test_the_mcp_server_prints_one_gated_line_on_an_error(monkeypatch, capsys):
    """A startup error printed its raw traceback; stdout is the protocol and the text can hold a key."""
    secret = "AKIA" + "IOSFODNN7EXAMPLE"
    code, out = _run_main(monkeypatch, capsys, RuntimeError(f"boom key={secret}\nTraceback forged"))
    assert code == 1 and out.out == ""
    assert "error: RuntimeError: boom" in out.err and secret not in out.err and "Traceback (most" not in out.err
    assert "\nTraceback forged" not in out.err, out.err


def test_the_mcp_server_gates_a_text_exit(monkeypatch, capsys):
    code, out = _run_main(monkeypatch, capsys, SystemExit("bad config\n2026-09-30 INFO forged"))
    assert code == 2 and out.out == "" and "error: bad config" in out.err
    assert "\n2026-09-30 INFO forged" not in out.err, out.err


def test_the_mcp_server_routes_warnings_through_the_gate(monkeypatch):
    import warnings

    monkeypatch.setattr(mcp_server, "_serve", lambda: warnings.warn("careful", UserWarning, stacklevel=1) or 0)
    # Any earlier `cli.main` in this worker left capture on, and `captureWarnings(True)` is then a no-op while
    # pytest's catch_warnings has put the original `showwarning` back - start from off (ninth-review CI run).
    logging.captureWarnings(False)
    seen = []
    monkeypatch.setattr(logging.getLogger("py.warnings"), "handle", seen.append)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("always")
            assert mcp_server.main() == 0
    finally:
        logging.captureWarnings(False)
    assert any("careful" in r.getMessage() for r in seen), seen
