"""The MCP server's stdout carries JSON-RPC and nothing else (audit A-C-20).

With console tracing on, spans were printed to stdout - into the protocol stream, where a client
reads them as broken messages. This starts the real server, with console tracing on, and makes it
emit spans; every stdout line must still be one JSON-RPC message.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from warden.observability import _build_exporter


def test_the_console_exporter_writes_to_stderr(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    monkeypatch.setenv("WARDEN_TRACE_CONSOLE", "1")
    assert _build_exporter().out is sys.stderr


def test_stdout_is_pure_json_rpc_with_console_tracing_on():
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "t", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "gather_incident_context", "arguments": {"alert_id": "inc-001"}}},  # tool spans
    ]
    env = {**os.environ, "WARDEN_TRACE_CONSOLE": "1", "PYTHONIOENCODING": "utf-8"}
    env.pop("OTEL_EXPORTER_OTLP_ENDPOINT", None)
    proc = subprocess.run([sys.executable, "-m", "warden.mcp_server"],
                          input="".join(json.dumps(r) + "\n" for r in requests),
                          capture_output=True, text=True, encoding="utf-8", env=env, timeout=60, check=False)
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    assert lines, proc.stderr[-2000:]
    for line in lines:
        msg = json.loads(line)  # a span printed here would fail this
        assert msg.get("jsonrpc") == "2.0", line[:200]
    assert any(m.get("id") == 2 for m in map(json.loads, lines)), "the tool call was answered"
