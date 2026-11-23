from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import httpx2
import pytest
import uvicorn
from mcp import Client
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

from app.main import app, gateway


CLIENT_TOKEN = "test-client-token-with-enough-entropy-123456"
FIXTURE_SERVER = Path(__file__).parent / "fixtures" / "downstream_server.py"
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _manifest(tmp_path: Path) -> Path:
    safe_file = tmp_path / "safe.txt"
    safe_file.write_text("real downstream fixture result", encoding="utf-8")
    counters = {"fs": tmp_path / "fs-counts.json", "git": tmp_path / "git-counts.json"}
    servers = {}
    for server_id in ("fs", "git"):
        tool_definitions = (
            {
                "read_file": {
                    "operation_type": "READ",
                    "impact_scope": "PROJECT",
                    "resource_args": [{"pointer": "/path", "kind": "PATH"}],
                    "auto_allow": True,
                    "description": "Read a path through the configured filesystem server.",
                },
                "delete_path": {
                    "operation_type": "DELETE",
                    "impact_scope": "LOCAL",
                    "resource_args": [{"pointer": "/path", "kind": "PATH"}],
                    "auto_allow": False,
                    "description": "Test-only deletion operation requiring enforcement.",
                },
                "crash_tool": {
                    "operation_type": "READ",
                    "impact_scope": "PROJECT",
                    "auto_allow": True,
                    "description": "Test-only downstream process crash operation.",
                },
            }
            if server_id == "fs"
            else {
                "get_issue": {
                    "operation_type": "READ",
                    "impact_scope": "PROJECT",
                    "auto_allow": True,
                    "description": "Read a fixture issue from the configured Git server.",
                }
            }
        )
        servers[server_id] = {
            "transport": "stdio",
            "command": [sys.executable, str(FIXTURE_SERVER), "--server", server_id, "--counter", str(counters[server_id])],
            "cwd": str(PROJECT_ROOT),
            "tools": tool_definitions,
        }
    manifest = {
        "policy_version": "A2-test",
        "allowed_roots": [str(tmp_path)],
        "servers": servers,
        "authorization": [
            {"match": {"server": "fs", "tool": "read_file"}, "result": "AUTHORIZED"},
            {"match": {"server": "fs", "tool": "delete_path"}, "result": "DENIED"},
            {"match": {"server": "fs", "tool": "crash_tool"}, "result": "AUTHORIZED"},
            {"match": {"server": "git", "tool": "get_issue"}, "result": "AUTHORIZED"},
        ],
    }
    path = tmp_path / "manifest.yaml"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return path


def _counts(path: Path) -> dict[str, int]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}


async def _exercise_asgi_gateway(tmp_path: Path) -> None:
    _manifest(tmp_path)
    from app import main as main_module
    from app.gateway_audit import gateway_audit

    await gateway_audit.clear()
    port = _reserve_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="info", access_log=True, lifespan="on")
    server = uvicorn.Server(config)
    server_task = asyncio.create_task(server.serve())
    try:
        await _wait_for_server(server, server_task)
        root = f"http://127.0.0.1:{port}"
        async with httpx2.AsyncClient(base_url=root, timeout=10) as unauthenticated:
            health = await unauthenticated.get("/api/health")
            assert health.status_code == 200

        async with httpx2.AsyncClient(
            base_url=root,
            timeout=10,
            headers={"Authorization": f"Bearer {CLIENT_TOKEN}"},
        ) as malformed_http:
            oversized_request = malformed_http.build_request("POST", "/mcp", content=b"x" * (1_048_576 + 1))
            oversized = await malformed_http.send(oversized_request, stream=True)
            assert oversized.status_code == 413
            await oversized.aclose()
            malformed_request = malformed_http.build_request(
                "POST",
                "/mcp",
                content=b'{"jsonrpc":"2.0","method":',
                headers={"Content-Type": "application/json"},
            )
            malformed = await malformed_http.send(malformed_request, stream=True)
            assert malformed.status_code >= 400
            await malformed.aclose()

        async with create_mcp_http_client(
            headers={"Authorization": f"Bearer {CLIENT_TOKEN}"},
            timeout=httpx2.Timeout(20),
        ) as http_client:
            async with Client(streamable_http_client(f"{root}/mcp", http_client=http_client), mode="legacy", read_timeout_seconds=10) as client:
                assert client.session.initialize_result is not None
                names = [tool.name for tool in (await client.list_tools()).tools]
                assert {"shield_status", "shield_session_open", "shield_session_close", "fs__read_file", "fs__delete_path", "fs__crash_tool", "git__get_issue"} == set(names)

                opened = await client.call_tool("shield_session_open", {})
                assert opened.is_error is False
                session_id = opened.structured_content["session_id"]

                result = await client.call_tool("fs__read_file", {"path": str(tmp_path / "safe.txt"), "shield_session_id": session_id})
                assert result.is_error is False
                assert any(getattr(block, "text", "") == "real downstream fixture result" for block in result.content)
                assert _counts(tmp_path / "fs-counts.json") == {"read_file": 1}

                blocked = await client.call_tool("fs__delete_path", {"path": str(tmp_path / "safe.txt"), "shield_session_id": session_id})
                assert blocked.is_error is True
                assert _counts(tmp_path / "fs-counts.json") == {"read_file": 1}

                routed = await client.call_tool("git__get_issue", {"issue": 81, "shield_session_id": session_id})
                assert routed.is_error is False
                assert routed.structured_content == {"issue": 81, "title": "Fixture issue", "state": "open"}
                assert _counts(tmp_path / "git-counts.json") == {"get_issue": 1}

                unavailable_client = main_module.gateway.downstream.clients.pop("git")
                unavailable = await client.call_tool("git__get_issue", {"issue": 82, "shield_session_id": session_id})
                assert unavailable.is_error is True
                assert "unavailable" in unavailable.content[0].text.lower()
                assert _counts(tmp_path / "git-counts.json") == {"get_issue": 1}
                main_module.gateway.downstream.clients["git"] = unavailable_client

                outside = await client.call_tool(
                    "fs__read_file",
                    {"path": str(tmp_path.parent / "outside-root.txt"), "shield_session_id": session_id},
                )
                traversed = await client.call_tool(
                    "fs__read_file",
                    {"path": str(tmp_path / ".." / "outside-traversal.txt"), "shield_session_id": session_id},
                )
                assert outside.is_error is True
                assert traversed.is_error is True
                assert _counts(tmp_path / "fs-counts.json") == {"read_file": 1}

                external_target = tmp_path.parent / "symlink-target.txt"
                external_target.mkdir(exist_ok=True)
                symlink_escape = tmp_path / "escape-link"
                try:
                    symlink_escape.symlink_to(external_target, target_is_directory=True)
                except OSError as symlink_error:
                    if os.name != "nt":
                        raise AssertionError(f"could not create a directory symlink: {symlink_error}")
                    link_literal = str(symlink_escape).replace("'", "''")
                    target_literal = str(external_target).replace("'", "''")
                    junction = subprocess.run(
                        [
                            "powershell.exe",
                            "-NoProfile",
                            "-Command",
                            f"New-Item -ItemType Junction -Path '{link_literal}' -Target '{target_literal}' | Out-Null",
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    if junction.returncode != 0:
                        raise AssertionError(f"could not create a Windows junction: {junction.stderr or junction.stdout}")
                escaped_link = await client.call_tool(
                    "fs__read_file",
                    {"path": str(symlink_escape / "secret.txt"), "shield_session_id": session_id},
                )
                assert escaped_link.is_error is True
                assert _counts(tmp_path / "fs-counts.json") == {"read_file": 1}

                malformed_args = await client.call_tool(
                    "fs__read_file",
                    {"path": 123, "shield_session_id": session_id},
                )
                assert malformed_args.is_error is True
                assert _counts(tmp_path / "fs-counts.json") == {"read_file": 1}

                crash = await asyncio.wait_for(
                    client.call_tool("fs__crash_tool", {"shield_session_id": session_id}),
                    timeout=10,
                )
                assert crash.is_error is True
                assert _counts(tmp_path / "fs-counts.json") == {"read_file": 1, "crash_tool": 1}

                unknown = await client.call_tool("not_configured", {"secret": "canary"})
                assert unknown.is_error is True
                assert _counts(tmp_path / "fs-counts.json") == {"read_file": 1, "crash_tool": 1}
                assert _counts(tmp_path / "git-counts.json") == {"get_issue": 1}

                closed = await client.call_tool("shield_session_close", {"shield_session_id": session_id})
                assert closed.is_error is False
                assert closed.structured_content == {"closed": True}
    finally:
        server.should_exit = True
        await asyncio.wait_for(server_task, timeout=10)
    events = await gateway_audit_snapshot()
    assert not any("canary" in json.dumps(event) for event in events)
    decisions = {event["request_id"]: event["decision"] for event in events if event["event_type"] == "POLICY_DECISION"}
    forwarded = {event["request_id"] for event in events if event["event_type"] == "FORWARDED"}
    assert not any(decisions.get(request_id) == "BLOCK" for request_id in forwarded)
    unavailable = next(event for event in events if event["event_type"] == "DOWNSTREAM_ERROR" and event["downstream_status"] == "UNAVAILABLE")
    assert unavailable["decision"] != "BLOCK"
    assert unavailable["request_id"] not in forwarded
    assert any(event["event_type"] == "DOWNSTREAM_ERROR" and event["downstream_status"] == "ERROR" for event in events)


async def gateway_audit_snapshot() -> list[dict[str, object]]:
    from app.gateway_audit import gateway_audit

    return [event.model_dump(mode="json") for event in await gateway_audit.snapshot()]


async def _wait_for_server(server: uvicorn.Server, server_task: asyncio.Task) -> int:
    for _ in range(1_000):
        if server_task.done():
            error = server_task.exception()
            if error is not None:
                raise error
            raise RuntimeError(f"local test server stopped before binding (started={server.started}, should_exit={server.should_exit})")
        if server.started:
            return 0
        await asyncio.sleep(0.01)
    raise TimeoutError("local MCP Shield did not bind its ephemeral test port")


def _reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def test_sdk_client_forwards_to_two_real_stdio_servers_and_blocks_without_execution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHIELD_MANIFEST", str(_manifest(tmp_path)))
    monkeypatch.setenv("SHIELD_CLIENT_TOKEN", CLIENT_TOKEN)
    monkeypatch.delenv("SHIELD_APPROVER_TOKENS", raising=False)
    asyncio.run(_exercise_asgi_gateway(tmp_path))


def test_boundary_rejects_missing_bearer_and_bad_origin_without_echoing_body() -> None:
    from app.main import ShieldBoundaryMiddleware

    async def exercise() -> None:
        async def unused_app(_scope, _receive, _send):
            raise AssertionError("rejected requests must not reach the MCP app")

        middleware = ShieldBoundaryMiddleware(unused_app)
        incoming = {"type": "http.request", "body": b'{"payload":"CANARY-DO-NOT-RETURN"}', "more_body": False}
        messages = []

        async def receive():
            return incoming

        async def send(message):
            messages.append(message)

        scope = {
            "type": "http",
            "scheme": "http",
            "method": "POST",
            "path": "/mcp",
            "headers": [(b"host", b"127.0.0.1:8765")],
        }
        await middleware(scope, receive, send)
        assert messages[0]["status"] == 401
        body = messages[-1]["body"]
        assert b"Unauthorized" in body
        assert b"CANARY-DO-NOT-RETURN" not in body

        messages.clear()
        scope["headers"].append((b"origin", b"https://attacker.invalid"))
        await middleware(scope, receive, send)
        assert messages[0]["status"] == 403
        assert b"CANARY-DO-NOT-RETURN" not in messages[-1]["body"]

    coroutine = exercise()
    try:
        coroutine.send(None)
    except StopIteration:
        return
    raise AssertionError("the in-memory boundary response unexpectedly performed I/O")
