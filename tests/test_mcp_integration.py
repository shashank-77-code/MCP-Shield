from __future__ import annotations

import asyncio
import json
import os
from urllib.request import Request, urlopen

import httpx2
import uvicorn
import websockets
from mcp import Client
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

from app import __version__
from app.main import app, store


def _http_request(url: str, method: str = "GET") -> tuple[int, str, bytes]:
    request = Request(url, data=b"" if method == "POST" else None, method=method)
    with urlopen(request, timeout=5) as response:
        return response.status, response.headers.get_content_type(), response.read()


async def _wait_for_server(server: uvicorn.Server, task: asyncio.Task[None]) -> int:
    deadline = asyncio.get_running_loop().time() + 8
    while not server.started and not task.done():
        if asyncio.get_running_loop().time() >= deadline:
            server.should_exit = True
            raise AssertionError("Uvicorn did not start within 8 seconds")
        await asyncio.sleep(0.02)
    if task.done():
        await task
        raise AssertionError("Uvicorn exited before accepting requests")
    sockets = [sock for listener in (server.servers or []) for sock in (listener.sockets or [])]
    assert sockets, "Uvicorn started without a listening socket"
    return int(sockets[0].getsockname()[1])


async def _exercise_application() -> None:
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=0,
        log_level="warning",
        access_log=False,
        lifespan="on",
    )
    server = uvicorn.Server(config)
    server_task = asyncio.create_task(server.serve())
    try:
        port = await _wait_for_server(server, server_task)
        root = f"http://127.0.0.1:{port}"

        health_status, health_type, health_body = await asyncio.to_thread(
            _http_request, f"{root}/api/health"
        )
        assert health_status == 200
        assert health_type == "application/json"
        health = json.loads(health_body)
        assert health["status"] == "ready"
        assert health["mcp_endpoint"] == "/mcp"

        page_status, page_type, page_body = await asyncio.to_thread(_http_request, root)
        assert page_status == 200
        assert page_type == "text/html"
        assert b"MCP Shield" in page_body

        subscriber_count = len(store.subscribers)
        async with websockets.connect(f"ws://127.0.0.1:{port}/ws/live") as websocket:
            first_message = json.loads(await asyncio.wait_for(websocket.recv(), timeout=5))
            assert first_message["type"] == "snapshot"

            simulation_status, simulation_type, simulation_body = await asyncio.to_thread(
                _http_request, f"{root}/api/demo/run", "POST"
            )
            assert simulation_status == 200
            assert simulation_type == "application/json"
            simulation = json.loads(simulation_body)
            assert len(simulation["events"]) == 3
            assert simulation["decision"]["verdict"] == "block"
            live_event = json.loads(await asyncio.wait_for(websocket.recv(), timeout=5))
            assert live_event["type"] == "event"
            assert live_event["payload"]["event_type"] == "tool_call"
        for _ in range(100):
            if len(store.subscribers) == subscriber_count:
                break
            await asyncio.sleep(0.01)
        assert len(store.subscribers) == subscriber_count

        async with create_mcp_http_client(headers={"Authorization": f"Bearer {os.environ['SHIELD_CLIENT_TOKEN']}"}) as http_client:
            async with Client(
                streamable_http_client(f"{root}/mcp", http_client=http_client),
                mode="legacy",
                read_timeout_seconds=10,
            ) as client:
                # Force the classic initialize handshake used by pre-2026 clients.
                assert client.session.initialize_result is not None
                assert client.protocol_version == "2025-11-25"

                tools = await client.list_tools()
                assert {"shield_status", "shield_session_open", "shield_session_close"} == {tool.name for tool in tools.tools}

                result = await client.call_tool("shield_status", {})
                assert result.is_error is False
                assert result.structured_content == {
                    "status": "ok",
                    "server_name": "MCP Shield",
                    "version": __version__,
                    "transport": "streamable-http",
                    "downstream_proxy_enabled": False,
                    "downstream_server_count": 0,
                }

                session_result = await client.call_tool("shield_session_open", {})
                assert session_result.is_error is False
                assert session_result.structured_content["status"] == "created"

                invalid_result = await client.call_tool("not_a_real_tool", {})
                assert invalid_result.is_error is True

    finally:
        server.should_exit = True
        await asyncio.wait_for(server_task, timeout=10)


def test_real_streamable_http_mcp_client_and_existing_app_routes(monkeypatch) -> None:
    monkeypatch.setenv("SHIELD_MANIFEST", str(__import__("pathlib").Path(__file__).resolve().parents[1] / "config" / "manifest.example.json"))
    monkeypatch.setenv("SHIELD_CLIENT_TOKEN", "integration-test-client-token-entropy-123456")
    monkeypatch.delenv("SHIELD_APPROVER_TOKENS", raising=False)
    asyncio.run(_exercise_application())
