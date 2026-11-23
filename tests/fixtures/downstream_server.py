from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from mcp.server.mcpserver import MCPServer


parser = argparse.ArgumentParser()
parser.add_argument("--server", choices=("fs", "git"), required=True)
parser.add_argument("--counter", type=Path, required=True)
options = parser.parse_args()


def record(tool: str) -> None:
    try:
        state = json.loads(options.counter.read_text(encoding="utf-8"))
    except FileNotFoundError:
        state = {}
    state[tool] = int(state.get(tool, 0)) + 1
    options.counter.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")


server = MCPServer(f"MCP Shield downstream {options.server}", version="test")

if options.server == "fs":

    @server.tool()
    async def crash_tool() -> str:
        """Terminate this fixture process after recording the attempted execution."""
        record("crash_tool")
        os._exit(17)

    @server.tool()
    async def read_file(path: str) -> str:
        """Read a fixture file and record actual execution out of band."""
        record("read_file")
        return Path(path).read_text(encoding="utf-8")

    @server.tool()
    async def delete_path(path: str) -> str:
        """Test-only destructive fixture; records if execution occurs."""
        record("delete_path")
        return f"would delete {Path(path).name}"

else:

    @server.tool()
    async def get_issue(issue: int) -> dict[str, object]:
        """Return a deterministic fixture issue and record actual execution."""
        record("get_issue")
        return {"issue": issue, "title": "Fixture issue", "state": "open"}


server.run(transport="stdio")
