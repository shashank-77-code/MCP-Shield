from __future__ import annotations

import os
from contextlib import AsyncExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp import Client
from mcp.client.stdio import StdioServerParameters
from mcp.types import CallToolResult, Tool as MCPTool

from .gateway_config import GatewayManifest


@dataclass(frozen=True)
class DiscoveredTool:
    server_id: str
    tool_name: str
    schema: dict[str, Any]
    namespaced_name: str


class DownstreamConnectionManager:
    """Owns official-SDK clients and stdio child processes for configured servers."""

    # Carry only process essentials to stdio children. Gateway/approver credentials never
    # inherit into downstream processes; additional values must be explicitly configured.
    _safe_environment = {
        "PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
        "COMSPEC", "PATHEXT", "PROGRAMDATA", "APPDATA", "LOCALAPPDATA",
    }

    def __init__(self) -> None:
        self.clients: dict[str, Client] = {}
        self.tools: dict[str, DiscoveredTool] = {}
        self._stack: AsyncExitStack | None = None

    @classmethod
    def _child_environment(cls, configured: dict[str, str]) -> dict[str, str]:
        values = {name: value for name, value in os.environ.items() if name.upper() in cls._safe_environment}
        values.update(configured)
        values.pop("SHIELD_CLIENT_TOKEN", None)
        values.pop("SHIELD_APPROVER_TOKENS", None)
        return values

    async def start(self, manifest: GatewayManifest) -> None:
        if self._stack is not None:
            raise RuntimeError("downstream manager is already started")
        stack = AsyncExitStack()
        await stack.__aenter__()
        self._stack = stack
        try:
            for server_id, server in manifest.servers.items():
                parameters = StdioServerParameters(
                    command=server.command[0],
                    args=[*server.command[1:]],
                    cwd=server.cwd,
                    env=self._child_environment(server.env),
                )
                client = Client(parameters, read_timeout_seconds=20)
                # Keep each SDK transport's async context in one task for both enter
                # and exit; AnyIO's stdio task groups are task-affine.
                connected = await stack.enter_async_context(client)
                self.clients[server_id] = connected
                discovered = await connected.list_tools()
                downstream_by_name = {tool.name: tool for tool in discovered.tools}
                for tool_name, policy in server.tools.items():
                    downstream = downstream_by_name.get(tool_name)
                    if downstream is None:
                        raise ValueError("manifest maps a tool that the downstream server does not expose")
                    schema = downstream.input_schema
                    if not isinstance(schema, dict) or schema.get("type") != "object":
                        raise ValueError("downstream tool has an invalid input schema")
                    properties = schema.get("properties", {})
                    if not isinstance(properties, dict) or "shield_session_id" in properties:
                        raise ValueError("downstream schema collides with Shield's application session field")
                    exposed_name = f"{server_id}__{tool_name}"
                    self.tools[exposed_name] = DiscoveredTool(server_id, tool_name, schema, exposed_name)
        except BaseException:
            await self.stop()
            raise

    async def call(self, server_id: str, tool_name: str, arguments: dict[str, Any]) -> CallToolResult:
        client = self.clients.get(server_id)
        if client is None:
            raise ConnectionError("downstream server is unavailable")
        return await client.call_tool(tool_name, arguments)

    async def stop(self) -> None:
        stack, self._stack = self._stack, None
        self.clients.clear()
        self.tools.clear()
        if stack is not None:
            await stack.aclose()


def merge_session_field(schema: dict[str, Any]) -> dict[str, Any]:
    """Preserve the downstream JSON schema and add a required, server-minted session handle."""
    merged = {**schema}
    properties = dict(schema.get("properties", {}))
    properties["shield_session_id"] = {"type": "string", "minLength": 16, "description": "Shield application session returned by shield_session_open."}
    merged["properties"] = properties
    required = list(schema.get("required", []))
    if "shield_session_id" not in required:
        required.append("shield_session_id")
    merged["required"] = required
    return merged
