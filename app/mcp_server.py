from __future__ import annotations

from typing import Any

from mcp.server.lowlevel.server import Server
from mcp.types import CallToolRequestParams, CallToolResult, ListToolsResult, TextContent, Tool

from . import __version__


async def _list_tools(_ctx, _params) -> ListToolsResult:
    from .gateway import get_runtime

    return ListToolsResult(tools=get_runtime().list_tools())


async def _call_tool(ctx, params: CallToolRequestParams) -> CallToolResult:
    from .gateway import get_runtime

    async def report_progress(progress: float, total: float | None, message: str | None) -> None:
        await ctx.session.report_progress(progress, total, message)

    return await get_runtime().dispatch_tool(
        params.name,
        params.arguments or {},
        progress_callback=report_progress,
    )


def _input_schema_for(name: str) -> dict[str, Any] | None:
    from .gateway import get_runtime

    return get_runtime().input_schema_for(name)


def create_mcp_server() -> Server:
    """Create a fresh SDK server and Streamable HTTP manager for one app lifespan."""
    # The low-level SDK Server preserves parsed JSON arguments for policy validation
    # and forwarding. Only tools/list and tools/call are registered in this milestone.
    return Server(
        "MCP Shield",
        version=__version__,
        instructions="Local MCP security gateway. Open an application session with shield_session_open before calling namespaced downstream tools.",
        get_tool_input_schema=_input_schema_for,
        on_list_tools=_list_tools,
        on_call_tool=_call_tool,
    )


mcp = create_mcp_server()
mcp_app = mcp.streamable_http_app(host="127.0.0.1", max_request_body_size=4_194_304)
