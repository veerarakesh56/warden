"""Research 2026-10-15, item 16: every MCP tool says what it does to the world (MCP tool annotations) - only the tools
that change nothing are marked read-only, and the one that asks for a fix is marked destructive."""

from __future__ import annotations

from warden import mcp_server


def test_what_a_client_is_shown_is_annotated(monkeypatch):
    monkeypatch.setenv("WARDEN_MCP_PROFILE", "remediate")
    shown = mcp_server.listed_tools()
    assert len(shown) == len(mcp_server.ANNOTATIONS)
    assert all(t.annotations is not None for t in shown)


def test_every_tool_served_has_annotations_and_only_reads_are_read_only():
    served = mcp_server._tools() + mcp_server._workflow_tools()
    assert {t.name for t in served} == set(mcp_server.ANNOTATIONS)
    by_name = {t.name: t for t in mcp_server._annotated(served)}
    assert all(t.annotations is not None for t in by_name.values())
    writers = {n for n, t in by_name.items() if not t.annotations.read_only_hint}
    assert writers == {"start_incident_diagnosis", "request_remediation"}
    assert by_name["request_remediation"].annotations.destructive_hint is True
