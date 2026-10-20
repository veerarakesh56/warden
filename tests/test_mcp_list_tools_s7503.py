"""The MCP server lists its tools through a plain function that hands the SDK a finished awaitable (Sonar python:S7503,
2026-10-17: an `async def` that awaited nothing). The SDK's contract (mcp 2.2 and 2.3) is a callable returning an
awaitable, which it awaits; these drive the real SDK end to end so the change is held, not assumed."""

from __future__ import annotations

import asyncio
import inspect

from mcp import Client, types

from warden import mcp_server


def test_a_client_lists_the_same_tools_through_the_sdk(monkeypatch):
    monkeypatch.setenv("WARDEN_MCP_PROFILE", "read")

    async def main():
        async with Client(mcp_server.build_server()) as client:
            return await client.list_tools()

    listed = asyncio.run(main())
    assert [t.name for t in listed.tools] == [t.name for t in mcp_server.listed_tools()]
    assert listed.tools
    assert all(t.annotations for t in listed.tools)


def test_the_list_handler_is_not_a_coroutine_and_its_result_awaits_to_the_listing():
    handler = mcp_server.build_server().get_request_handler("tools/list").handler
    assert not inspect.iscoroutinefunction(handler)

    async def awaited():
        return await handler(None, types.PaginatedRequestParams())

    result = asyncio.run(awaited())
    assert isinstance(result, types.ListToolsResult)
    assert [t.name for t in result.tools] == [t.name for t in mcp_server.listed_tools()]


def test_a_ready_value_is_handed_back_without_waiting():
    ready = mcp_server._Ready("x")
    steps = ready.__await__()
    try:
        next(steps)
    except StopIteration as done:
        assert done.value == "x"
    else:
        raise AssertionError("a ready value suspended the caller")
