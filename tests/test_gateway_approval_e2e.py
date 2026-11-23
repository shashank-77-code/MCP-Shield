from __future__ import annotations

import asyncio
import json
import socket
import sys
from pathlib import Path

import httpx2
import pytest
import uvicorn
from mcp import Client
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

from app.gateway_audit import gateway_audit
from app.gateway_config import Authorization


CLIENT_TOKEN = "approval-e2e-client-token-with-entropy-123456"
APPROVER_TOKEN = "approval-e2e-approver-token-with-entropy-123456"
FIXTURE_SERVER = Path(__file__).parent / "fixtures" / "downstream_server.py"
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _manifest(tmp_path: Path) -> Path:
    data = {
        "policy_version": "A4-e2e",
        "allowed_roots": [str(tmp_path.resolve())],
        "approval": {"timeout_s": 10, "grant_ttl_s": 5},
        "servers": {
            "fs": {
                "transport": "stdio",
                "command": [
                    sys.executable,
                    str(FIXTURE_SERVER),
                    "--server",
                    "fs",
                    "--counter",
                    str(tmp_path / "counts.json"),
                ],
                "cwd": str(PROJECT_ROOT),
                "tools": {
                    "delete_path": {
                        "operation_type": "DELETE",
                        "impact_scope": "LOCAL",
                        "resource_args": [{"pointer": "/path", "kind": "PATH"}],
                        "auto_allow": False,
                        "description": "Fixture deletion operation requiring review.",
                    }
                },
            }
        },
        "authorization": [
            {"match": {"server": "fs", "tool": "delete_path"}, "result": "AUTHORIZED"}
        ],
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _counts(path: Path) -> dict[str, int]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}


def _reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


async def _wait_for_server(server: uvicorn.Server, task: asyncio.Task) -> None:
    for _ in range(1_500):
        if task.done():
            error = task.exception()
            if error is not None:
                raise error
            raise RuntimeError("Shield exited before binding its local test port")
        if server.started:
            return
        await asyncio.sleep(0.01)
    raise TimeoutError("Shield did not bind its local test port")


async def _wait_for_pending(runtime, timeout_s: float = 3.0):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_s
    while loop.time() < deadline:
        records = await runtime.approval_store.list_pending()
        if records:
            return records[0]
        await asyncio.sleep(0.01)
    raise TimeoutError("reviewable MCP request did not enter the approval store")


async def _open_session(client: Client) -> str:
    result = await client.call_tool("shield_session_open", {})
    assert not result.is_error
    return result.structured_content["session_id"]


async def _exercise(tmp_path: Path) -> None:
    import app.main as main_module

    await gateway_audit.clear()
    port = _reserve_port()
    server = uvicorn.Server(uvicorn.Config(app=main_module.app, host="127.0.0.1", port=port, log_level="warning", access_log=False, lifespan="on"))
    server_task = asyncio.create_task(server.serve())
    root = f"http://127.0.0.1:{port}"
    origin = root
    try:
        await _wait_for_server(server, server_task)
        async with create_mcp_http_client(headers={"Authorization": f"Bearer {CLIENT_TOKEN}"}) as http_client:
            async with Client(
                streamable_http_client(f"{root}/mcp", http_client=http_client),
                mode="legacy",
                read_timeout_seconds=12,
            ) as client:
                assert client.session.initialize_result is not None
                names = {tool.name for tool in (await client.list_tools()).tools}
                assert "fs__delete_path" in names
                runtime = main_module.gateway

                async with httpx2.AsyncClient(base_url=root, timeout=5) as api:
                    health = await api.get("/api/health")
                    assert health.status_code == 200
                    assert health.json()["status"] == "ready"
                    assert health.json()["downstream_server_count"] == 1
                    assert health.json()["approvals_enabled"] is True
                    no_auth = await api.get("/api/gateway/approvals", headers={"Origin": origin})
                    client_as_approver = await api.get(
                        "/api/gateway/approvals",
                        headers={"Origin": origin, "Authorization": f"Bearer {CLIENT_TOKEN}"},
                    )
                    invalid = await api.get(
                        "/api/gateway/approvals",
                        headers={"Origin": origin, "Authorization": "Bearer invalid-token"},
                    )
                    cross_origin = await api.get(
                        "/api/gateway/approvals",
                        headers={"Origin": "https://attacker.invalid", "Authorization": f"Bearer {APPROVER_TOKEN}"},
                    )
                    assert no_auth.status_code == 401
                    assert client_as_approver.status_code == 403
                    assert invalid.status_code == 401
                    assert cross_origin.status_code == 403

                    session_id = await _open_session(client)
                    marker_path = tmp_path / "CANARY-APPROVAL-ARG.txt"
                    progress_updates = []

                    async def record_progress(progress: float, total: float | None, message: str | None) -> None:
                        progress_updates.append((progress, total, message))

                    held_call = asyncio.create_task(client.call_tool(
                        "fs__delete_path",
                        {"path": str(marker_path), "shield_session_id": session_id},
                        progress_callback=record_progress,
                    ))
                    pending = await _wait_for_pending(runtime)
                    for _ in range(100):
                        if progress_updates:
                            break
                        await asyncio.sleep(0.01)
                    assert progress_updates == [(0, 1, "Waiting for authenticated approval.")]
                    assert pending.status.value == "PENDING"
                    assert _counts(tmp_path / "counts.json") == {}
                    initial_session = runtime.sessions[session_id]
                    before = (initial_session.integrity, initial_session.confidentiality)

                    pending_list = await api.get(
                        "/api/gateway/approvals",
                        headers={"Origin": origin, "Authorization": f"Bearer {APPROVER_TOKEN}"},
                    )
                    assert pending_list.status_code == 200
                    pending_json = pending_list.json()
                    assert len(pending_json["approvals"]) == 1
                    assert "CANARY-APPROVAL-ARG" not in pending_list.text
                    assert "grant_id" not in pending_list.text
                    events_while_pending = await api.get("/api/gateway/events", headers={"Origin": origin})
                    assert "CANARY-APPROVAL-ARG" not in events_while_pending.text
                    public_dashboard_data = events_while_pending.json()
                    assert "pending_approvals" not in public_dashboard_data
                    assert public_dashboard_data["metrics"]["review_count"] == 1
                    assert any(event["event_type"] == "APPROVAL_REQUESTED" for event in public_dashboard_data["events"])

                    approve_body = {"action": "approve", "reason": "Reviewed CANARY-APPROVAL-REASON by operator."}
                    approved = await api.post(
                        f"/api/gateway/approvals/{pending.request_id}",
                        json=approve_body,
                        headers={"Origin": origin, "Authorization": f"Bearer {APPROVER_TOKEN}"},
                    )
                    assert approved.status_code == 200
                    assert approved.json()["grant_issued"] is True
                    assert "grant_id" not in approved.text
                    result = await asyncio.wait_for(held_call, timeout=8)
                    assert result.is_error is False
                    assert progress_updates == [
                        (0, 1, "Waiting for authenticated approval."),
                        (1, 1, "Approval received; revalidating the request."),
                    ]
                    assert any("would delete CANARY-APPROVAL-ARG.txt" in getattr(block, "text", "") for block in result.content)
                    assert _counts(tmp_path / "counts.json") == {"delete_path": 1}
                    assert (initial_session.integrity, initial_session.confidentiality) == before
                    duplicate_approve = await api.post(
                        f"/api/gateway/approvals/{pending.request_id}",
                        json=approve_body,
                        headers={"Origin": origin, "Authorization": f"Bearer {APPROVER_TOKEN}"},
                    )
                    assert duplicate_approve.status_code == 409

                    second_session = await _open_session(client)
                    rejected_call = asyncio.create_task(client.call_tool(
                        "fs__delete_path",
                        {"path": str(tmp_path / "reject.txt"), "shield_session_id": second_session},
                    ))
                    rejected_pending = await _wait_for_pending(runtime)
                    rejected = await api.post(
                        f"/api/gateway/approvals/{rejected_pending.request_id}",
                        json={"action": "reject", "reason": "Rejected by reviewer."},
                        headers={"Origin": origin, "Authorization": f"Bearer {APPROVER_TOKEN}"},
                    )
                    assert rejected.status_code == 200
                    assert (await asyncio.wait_for(rejected_call, timeout=5)).is_error
                    assert _counts(tmp_path / "counts.json") == {"delete_path": 1}
                    duplicate_reject = await api.post(
                        f"/api/gateway/approvals/{rejected_pending.request_id}",
                        json={"action": "reject", "reason": "Second rejection."},
                        headers={"Origin": origin, "Authorization": f"Bearer {APPROVER_TOKEN}"},
                    )
                    assert duplicate_reject.status_code == 409

                    third_session = await _open_session(client)
                    changed_policy_call = asyncio.create_task(client.call_tool(
                        "fs__delete_path",
                        {"path": str(tmp_path / "policy-changed.txt"), "shield_session_id": third_session},
                    ))
                    changed_policy_pending = await _wait_for_pending(runtime)
                    runtime.manifest.authorization[0].result = Authorization.DENIED
                    approved_but_blocked = await api.post(
                        f"/api/gateway/approvals/{changed_policy_pending.request_id}",
                        json=approve_body,
                        headers={"Origin": origin, "Authorization": f"Bearer {APPROVER_TOKEN}"},
                    )
                    assert approved_but_blocked.status_code == 200
                    assert (await asyncio.wait_for(changed_policy_call, timeout=5)).is_error
                    runtime.manifest.authorization[0].result = Authorization.AUTHORIZED
                    assert _counts(tmp_path / "counts.json") == {"delete_path": 1}
                    assert any(
                        event.request_id == changed_policy_pending.request_id
                        and event.event_type.value == "REVALIDATION"
                        and event.decision == "BLOCK"
                        for event in await gateway_audit.snapshot()
                    )

                    runtime.manifest.approval.timeout_s = 1
                    fourth_session = await _open_session(client)
                    timed_call = asyncio.create_task(client.call_tool(
                        "fs__delete_path",
                        {"path": str(tmp_path / "timeout.txt"), "shield_session_id": fourth_session},
                    ))
                    timed_pending = await _wait_for_pending(runtime)
                    assert (await asyncio.wait_for(timed_call, timeout=5)).is_error
                    assert (await runtime.approval_store.get_pending(timed_pending.request_id)).status.value == "EXPIRED"
                    late_approve = await api.post(
                        f"/api/gateway/approvals/{timed_pending.request_id}",
                        json=approve_body,
                        headers={"Origin": origin, "Authorization": f"Bearer {APPROVER_TOKEN}"},
                    )
                    assert late_approve.status_code == 409
                    assert _counts(tmp_path / "counts.json") == {"delete_path": 1}

                    fifth_session = await _open_session(client)
                    cancelled_call = asyncio.create_task(client.call_tool(
                        "fs__delete_path",
                        {"path": str(tmp_path / "cancelled.txt"), "shield_session_id": fifth_session},
                    ))
                    cancelled_pending = await _wait_for_pending(runtime)
                    cancelled_call.cancel()
                    await asyncio.gather(cancelled_call, return_exceptions=True)
                    for _ in range(100):
                        status = (await runtime.approval_store.get_pending(cancelled_pending.request_id)).status.value
                        if status in {"CANCELLED", "APPROVED"}:
                            break
                        await asyncio.sleep(0.01)
                    assert status == "CANCELLED"
                    after_cancel_approve = await api.post(
                        f"/api/gateway/approvals/{cancelled_pending.request_id}",
                        json=approve_body,
                        headers={"Origin": origin, "Authorization": f"Bearer {APPROVER_TOKEN}"},
                    )
                    assert after_cancel_approve.status_code == 409
                    assert _counts(tmp_path / "counts.json") == {"delete_path": 1}

                    metrics = (await api.get("/api/gateway/metrics")).json()
                    assert metrics["review_count"] == 5
                    assert metrics["executed_count"] == 1
                    assert metrics["timed_out_count"] == 1
                    assert metrics["cancelled_count"] == 1
                    audited = await gateway_audit.snapshot()
                    serialized = json.dumps([event.model_dump(mode="json") for event in audited])
                    assert "CANARY-APPROVAL-ARG" not in serialized
                    assert "CANARY-APPROVAL-REASON" not in serialized
                    dashboard_data = (await api.get("/api/gateway/events")).json()
                    assert dashboard_data["metrics"] == metrics
                    assert len(dashboard_data["events"]) == metrics["audit_event_count"]
                    assert "CANARY-APPROVAL-ARG" not in json.dumps(dashboard_data)
                    assert "CANARY-APPROVAL-REASON" not in json.dumps(dashboard_data)
                    assert any(event.event_type.value == "REVALIDATION" for event in audited)
                    assert any(event.event_type.value == "APPROVAL_EXPIRED" for event in audited)
                    assert any(event.actor_id == "ops-1" for event in audited)
    finally:
        server.should_exit = True
        await asyncio.wait_for(server_task, timeout=10)


async def _exercise_approval_disabled(tmp_path: Path) -> None:
    import app.main as main_module

    await gateway_audit.clear()
    port = _reserve_port()
    server = uvicorn.Server(uvicorn.Config(app=main_module.app, host="127.0.0.1", port=port, log_level="warning", access_log=False, lifespan="on"))
    server_task = asyncio.create_task(server.serve())
    root = f"http://127.0.0.1:{port}"
    try:
        await _wait_for_server(server, server_task)
        async with create_mcp_http_client(headers={"Authorization": f"Bearer {CLIENT_TOKEN}"}) as http_client:
            async with Client(streamable_http_client(f"{root}/mcp", http_client=http_client), mode="legacy", read_timeout_seconds=8) as client:
                session_id = await _open_session(client)
                result = await client.call_tool(
                    "fs__delete_path",
                    {"path": str(tmp_path / "approval-disabled.txt"), "shield_session_id": session_id},
                )
                assert result.is_error
                assert main_module.gateway.approver_tokens == {}
                assert await main_module.gateway.approval_store.list_pending() == []
                assert _counts(tmp_path / "counts.json") == {}
                events = await gateway_audit.snapshot()
                assert any(event.forwarding_status == "REVIEW_DISABLED" for event in events)
                metrics = await gateway_audit.metrics()
                assert metrics["review_count"] == 1
                assert metrics["executed_count"] == 0
    finally:
        server.should_exit = True
        await asyncio.wait_for(server_task, timeout=10)


def test_approval_hold_revalidate_reject_timeout_cancel_and_authentication(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHIELD_MANIFEST", str(_manifest(tmp_path)))
    monkeypatch.setenv("SHIELD_CLIENT_TOKEN", CLIENT_TOKEN)
    monkeypatch.setenv("SHIELD_APPROVER_TOKENS", json.dumps({"ops-1": APPROVER_TOKEN}))
    asyncio.run(_exercise(tmp_path))


def test_review_terminates_without_forwarding_when_approvals_are_unconfigured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHIELD_MANIFEST", str(_manifest(tmp_path)))
    monkeypatch.setenv("SHIELD_CLIENT_TOKEN", CLIENT_TOKEN)
    monkeypatch.delenv("SHIELD_APPROVER_TOKENS", raising=False)
    asyncio.run(_exercise_approval_disabled(tmp_path))
