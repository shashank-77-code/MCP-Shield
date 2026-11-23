from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from time import perf_counter
from uuid import uuid4
from urllib.parse import urlsplit
from typing import Literal

from fastapi import FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from .approvals import ApprovalConflict, ApprovalNotFound, ApprovalUnavailable
from .models import Decision, Event, ToolCall, Verdict
from . import __version__
from .mcp_server import create_mcp_server, mcp, mcp_app
from .policy_engine import evaluate
from .store import store
from .taint_engine import OUTBOUND, SENSITIVE, UNTRUSTED, inspect_arguments
from .gateway import configure_runtime, bind_client_principal, reset_client_principal
from .gateway_audit import gateway_audit

gateway = configure_runtime(mcp)

ROOT = Path(__file__).resolve().parent.parent


async def inspect_call(call: ToolCall, source_taints: set[str] | None = None) -> Decision:
    started = perf_counter()
    effective_session_id = call.session_id or store.session_id
    inherited = store.session_taints.get(effective_session_id, set())
    taint = inspect_arguments(call.arguments, inherited | (source_taints or set()))
    policy = evaluate(call.tool, taint.labels)
    event = Event(tool_name=call.tool, source=call.source, decision=policy.verdict, message=policy.explanation,
                  session_id=effective_session_id, run_id=call.run_id,
                  taints=sorted(taint.labels), rule=policy.rule,
                  arguments={}, latency_ms=round((perf_counter() - started) * 1000, 2))
    store.session_taints[event.session_id] = taint.labels
    await store.add_event(event)
    approval_id = await store.queue_approval(event) if policy.verdict == Verdict.review else None
    return Decision(event=event, explanation=policy.explanation, approval_required=approval_id is not None, approval_id=approval_id)


def session_graph(session_id: str | None = None, run_id: str | None = None) -> dict[str, object]:
    """Build a graph from tool-call records, scoped to the latest run by default."""
    events = list(store.events)
    if session_id is None:
        session_id = store.session_id
    if run_id is None:
        latest_run = next((event for event in events if event.session_id == session_id and event.run_id), None)
        if latest_run:
            run_id = latest_run.run_id
    scope = "latest_run" if run_id else "current_session"
    session_events = [
        event for event in reversed(events)
        if event.event_type == "tool_call"
        and event.session_id == session_id
        and (run_id is None or event.run_id == run_id)
    ]
    nodes: list[dict[str, object]] = []
    edges: list[list[str]] = []
    if session_events:
        nodes.append({"id": "demo-client", "label": "LOCAL CLIENT", "kind": "client", "x": 7, "y": 50})
        previous = "demo-client"
        total = len(session_events)
        for index, event in enumerate(session_events):
            node_id = event.event_id
            x = round(26 + (64 * index / max(total - 1, 1)), 1)
            y = 50 if total < 3 or index == 1 else (23 if index % 2 == 0 else 77)
            kind = "danger" if event.decision == Verdict.block else "review" if event.decision == Verdict.review else "tool"
            nodes.append({"id": node_id, "label": event.tool_name, "kind": kind, "x": x, "y": y,
                          "decision": event.decision.value, "taints": event.taints})
            edges.append([previous, node_id])
            previous = node_id
    dangerous_paths = sum(
        1 for event in session_events
        if event.decision == Verdict.block and {UNTRUSTED, SENSITIVE, OUTBOUND}.issubset(set(event.taints))
    )
    risk_state = "contained" if dangerous_paths else "review" if any(e.decision == Verdict.review for e in session_events) else "clear"
    return {
        "scope": scope,
        "session_id": session_id,
        "run_id": run_id,
        "run_number": store.run_numbers.get(run_id) if run_id else None,
        "simulation_run_count": store.simulation_run_count,
        "nodes": nodes,
        "edges": edges,
        "metrics": {
            "tool_call_count": len(session_events),
            "unique_tool_count": len({event.tool_name for event in session_events}),
            "blocked_tool_call_count": sum(event.decision == Verdict.block for event in session_events),
            "graph_node_count": len(nodes),
            "graph_edge_count": len(edges),
            "blocked_path_count": dangerous_paths,
            "risk": risk_state,
        },
    }


def session_stats() -> dict[str, object]:
    events = list(store.events)
    tool_calls = [event for event in events if event.event_type == "tool_call"]
    blocked = sum(event.decision == Verdict.block for event in tool_calls)
    reviews = sum(event.decision == Verdict.review for event in tool_calls)
    risk_state = "CONTAINED" if blocked else "WATCH" if reviews else "CLEAR"
    average_latency = round(sum(event.latency_ms for event in tool_calls) / len(tool_calls), 2) if tool_calls else 0
    return {
        "scope": "current_in_memory_store",
        "session_id": store.session_id,
        "audit_record_count": len(events),
        "tool_call_count": len(tool_calls),
        "blocked_tool_call_count": blocked,
        "simulation_run_count": store.simulation_run_count,
        "audit_record_limit": store.events.maxlen,
        "pending_approvals": len(store.approvals),
        "risk": risk_state,
        "average_latency_ms": average_latency,
    }


async def call_mock_destination(destination: str, message: str) -> dict[str, object]:
    """Record delivery locally. This function never contacts an external service."""
    delivery = {"destination": destination, "message": message}
    store.mock_deliveries.append(delivery)
    return {"delivered": True, "destination": destination}


@asynccontextmanager
async def lifespan(_: FastAPI):
    global gateway, mcp
    # The SDK's Streamable HTTP manager is single-use. Create a fresh SDK server
    # for every application lifespan so test and development restarts are safe.
    mcp = create_mcp_server()
    gateway = configure_runtime(mcp)
    await gateway.start()
    mcp_app = mcp.streamable_http_app(host="127.0.0.1", max_request_body_size=4_194_304)
    mcp_route = next(route for route in app.router.routes if getattr(route, "name", None) == "mcp")
    mcp_route.app = mcp_app
    try:
        async with mcp.session_manager.run():
            yield
    finally:
        await gateway.stop()


app = FastAPI(title="MCP Shield", version=__version__, lifespan=lifespan)


class ShieldBoundaryMiddleware:
    """Enforce local HTTP boundaries, bearer authentication, origin checks and body size."""

    def __init__(self, inner):
        self.inner = inner

    @staticmethod
    async def _reply(scope, receive, send, status: int, message: str, headers: list[tuple[bytes, bytes]] | None = None) -> None:
        response = JSONResponse(
            {"error": message},
            status_code=status,
            headers={name.decode("latin-1"): value.decode("latin-1") for name, value in (headers or [])},
        )
        await response(scope, receive, send)

    @staticmethod
    async def _drain_request(receive, limit: int) -> bool:
        """Consume a rejected body without retaining it; cap how much is drained."""
        received = 0
        drain_cap = limit + 1_048_576
        while True:
            message = await receive()
            if message.get("type") == "http.disconnect":
                return True
            if message.get("type") != "http.request":
                continue
            received += len(message.get("body", b""))
            if received > drain_cap:
                return False
            if not message.get("more_body", False):
                return True

    @staticmethod
    def _headers(scope) -> dict[str, list[str]]:
        values: dict[str, list[str]] = {}
        for name, value in scope.get("headers", []):
            values.setdefault(name.decode("latin-1").lower(), []).append(value.decode("latin-1"))
        return values

    @staticmethod
    def _is_loopback_host(host_header: str) -> bool:
        try:
            host = urlsplit("//" + host_header).hostname
        except ValueError:
            return False
        return host is not None and host.lower() in {"127.0.0.1", "localhost", "::1"}

    @staticmethod
    def _same_origin(origin: str, host_header: str, scheme: str) -> bool:
        try:
            parts = urlsplit(origin)
            return (
                parts.scheme.lower() == scheme.lower()
                and parts.netloc.lower() == host_header.lower()
                and parts.username is None
                and parts.password is None
                and parts.path in ("", "/")
                and not parts.query
                and not parts.fragment
            )
        except ValueError:
            return False

    async def __call__(self, scope, receive, send):
        if scope["type"] not in {"http", "websocket"}:
            await self.inner(scope, receive, send)
            return

        headers = self._headers(scope)
        runtime = gateway
        limit = runtime.manifest.request_size_limit_bytes if runtime.manifest else 1_048_576

        async def reject(status: int, message: str, extra_headers: list[tuple[bytes, bytes]] | None = None):
            close_connection = False
            if scope.get("method") in {"POST", "PUT", "PATCH", "DELETE"}:
                close_connection = not await self._drain_request(receive, limit)
                if close_connection:
                    status, message = 413, "Request body too large"
            response_headers = list(extra_headers or [])
            if close_connection:
                response_headers.append((b"connection", b"close"))
            await self._reply(scope, receive, send, status, message, response_headers)

        origin_values = headers.get("origin", [])
        origin = origin_values[0] if len(origin_values) == 1 else None
        path = scope.get("path", "")
        host_values = headers.get("host", [])
        host = host_values[0] if len(host_values) == 1 else ""
        configured_origins = set(runtime.manifest.allowed_origins) if runtime.manifest else set()
        same_origin = bool(origin and self._same_origin(origin, host, scope.get("scheme", "http")))
        origin_allowed = same_origin or (origin is not None and origin in configured_origins)

        if scope["type"] == "websocket":
            if origin and (not self._is_loopback_host(host) or not origin_allowed):
                await send({"type": "websocket.close", "code": 1008})
                return
            await self.inner(scope, receive, send)
            return

        is_mcp = path == "/mcp" or path.startswith("/mcp/")
        is_approval_api = path == "/api/gateway/approvals" or path.startswith("/api/gateway/approvals/")
        if (is_mcp or is_approval_api) and not self._is_loopback_host(host):
            await reject(403, "Forbidden")
            return
        if len(origin_values) > 1 or (origin and (is_mcp or is_approval_api) and not origin_allowed):
            await reject(403, "Forbidden")
            return
        if is_approval_api and scope["method"] in {"POST", "PUT", "PATCH", "DELETE"} and not origin_allowed:
            await reject(403, "Forbidden")
            return

        if scope["method"] == "OPTIONS":
            if not origin or origin not in configured_origins:
                await self._reply(scope, receive, send, 403, "Forbidden")
                return
            cors_headers = [
                (b"access-control-allow-origin", origin.encode("latin-1")),
                (b"access-control-allow-methods", b"GET, POST, DELETE, OPTIONS"),
                (b"access-control-allow-headers", b"Authorization, Content-Type, Accept, MCP-Protocol-Version, MCP-Session-Id, Last-Event-ID"),
                (b"access-control-max-age", b"600"),
                (b"vary", b"Origin"),
            ]
            await send({"type": "http.response.start", "status": 204, "headers": cors_headers})
            await send({"type": "http.response.body", "body": b""})
            return

        client_token = None
        context_token = None
        if is_mcp:
            authorization = headers.get("authorization", [])
            if len(authorization) == 1 and authorization[0][:7].lower() == "bearer ":
                client_token = authorization[0][7:]
            if not runtime.check_client_token(client_token):
                await reject(401, "Unauthorized", [(b"www-authenticate", b"Bearer")])
                return
            context_token = bind_client_principal(client_token)

        length_values = headers.get("content-length", [])
        if length_values:
            try:
                if len(length_values) != 1 or int(length_values[0]) > limit:
                    if context_token is not None:
                        reset_client_principal(context_token)
                    await reject(413, "Request body too large", [(b"connection", b"close")])
                    return
            except ValueError:
                if context_token is not None:
                    reset_client_principal(context_token)
                await reject(400, "Malformed request")
                return

        received = 0
        overflow_body_complete = False

        async def limited_receive():
            nonlocal received, overflow_body_complete
            message = await receive()
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    overflow_body_complete = not message.get("more_body", False)
                    raise OverflowError("request too large")
            return message

        async def cors_send(message):
            if message.get("type") == "http.response.start" and origin in configured_origins:
                response_headers = list(message.get("headers", []))
                response_headers.extend([
                    (b"access-control-allow-origin", origin.encode("latin-1")),
                    (b"vary", b"Origin"),
                ])
                message = {**message, "headers": response_headers}
            await send(message)

        try:
            await self.inner(scope, limited_receive, cors_send)
        except OverflowError:
            fully_drained = overflow_body_complete or await self._drain_request(receive, limit)
            headers_out = [] if fully_drained else [(b"connection", b"close")]
            await self._reply(scope, receive, send, 413, "Request body too large", headers_out)
        finally:
            if context_token is not None:
                reset_client_principal(context_token)


app.add_middleware(ShieldBoundaryMiddleware)
app.mount("/assets", StaticFiles(directory=ROOT / "web"), name="assets")


@app.get("/")
async def dashboard() -> FileResponse:
    return FileResponse(ROOT / "web" / "index.html")


@app.get("/api/health")
async def health() -> dict[str, object]:
    return {
        "status": "ready" if gateway.configured else "not_configured",
        "engine": "MCP Shield Gateway",
        "version": __version__,
        "mcp_endpoint": "/mcp",
        "downstream_server_count": len(gateway.downstream.clients),
        "approvals_enabled": bool(gateway.approver_tokens),
        "audit_event_limit": gateway.manifest.audit_limit if gateway.manifest is not None else 0,
    }


@app.get("/api/events")
async def events() -> dict[str, object]:
    return {"events": list(store.events), "approvals": [{"id": k, "event": v} for k, v in store.approvals.items()],
            "stats": session_stats(), "graph": session_graph()}


@app.get("/api/graph")
async def graph(session_id: str | None = None, run_id: str | None = None) -> dict[str, object]:
    return session_graph(session_id, run_id)


@app.get("/api/gateway/events")
async def gateway_events() -> dict[str, object]:
    events = await gateway_audit.snapshot()
    return {
        "events": [event.model_dump(mode="json") for event in events],
        "metrics": await gateway_audit.metrics(),
    }


@app.get("/api/gateway/metrics")
async def gateway_metrics() -> dict[str, int]:
    return await gateway_audit.metrics()


@app.post("/api/inspect", response_model=Decision)
async def inspect(call: ToolCall) -> Decision:
    return await inspect_call(call)


@app.post("/api/approvals/{approval_id}")
async def approval(approval_id: str, approved: bool) -> dict[str, object]:
    event = await store.resolve_approval(approval_id, approved)
    if not event:
        raise HTTPException(status_code=404, detail="Approval not found")
    return {"ok": True, "event": event}


class GatewayApprovalCommand(BaseModel):
    action: Literal["approve", "reject"]
    reason: str = Field(min_length=1, max_length=500)

    @field_validator("reason")
    @classmethod
    def reason_must_not_be_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("a non-empty reason is required")
        return value


def _approver_id_from_request(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    scheme, separator, token = authorization.partition(" ")
    token = token.strip() if separator and scheme.lower() == "bearer" else None
    approver_id, result = gateway.approver_identity(token)
    if result == "CLIENT_CREDENTIAL":
        raise HTTPException(status_code=403, detail="Client credentials cannot approve requests.")
    if result != "APPROVER" or approver_id is None:
        raise HTTPException(status_code=401, detail="Approver authentication is required.", headers={"WWW-Authenticate": "Bearer"})
    return approver_id


@app.get("/api/gateway/approvals")
async def gateway_pending_approvals(request: Request) -> dict[str, object]:
    _approver_id_from_request(request)
    try:
        return {"approvals": await gateway.pending_approvals()}
    except ApprovalUnavailable:
        raise HTTPException(status_code=503, detail="Approval service is unavailable.") from None


@app.post("/api/gateway/approvals/{request_id}")
async def resolve_gateway_approval(request_id: str, command: GatewayApprovalCommand, request: Request) -> dict[str, object]:
    approver_id = _approver_id_from_request(request)
    try:
        return await gateway.decide_approval(
            request_id,
            approved=command.action == "approve",
            approver_id=approver_id,
            reason=command.reason,
        )
    except ApprovalNotFound:
        raise HTTPException(status_code=404, detail="Approval request was not found.") from None
    except ApprovalConflict:
        raise HTTPException(status_code=409, detail="Approval request is no longer pending.") from None
    except ApprovalUnavailable:
        raise HTTPException(status_code=503, detail="Approval service is unavailable.") from None


@app.post("/api/session/reset")
async def reset() -> dict[str, bool]:
    await store.reset()
    return {"ok": True}


@app.post("/api/demo/run")
async def run_demo() -> dict[str, object]:
    run_id, run_number = store.begin_simulation()
    session_id = store.session_id
    destination_called = False
    scenario = [
        (ToolCall(tool="github.read_issue", arguments={"issue": 184, "visibility": "public"}, session_id=session_id, run_id=run_id), {UNTRUSTED}),
        (ToolCall(tool="filesystem.read_sensitive", arguments={"path": "fixtures/demo_secret.txt"}, session_id=session_id, run_id=run_id), {SENSITIVE}),
        (ToolCall(tool="slack.send_message", arguments={"destination": "https://mock-destination.invalid/security", "message": "Synthetic demo content"}, session_id=session_id, run_id=run_id), {OUTBOUND}),
    ]
    decisions = []
    for call, result_taints in scenario:
        decision = await inspect_call(call, source_taints=result_taints)
        decisions.append(decision)
        if call.tool == "slack.send_message" and decision.event.decision == Verdict.allow:
            await call_mock_destination(call.arguments["destination"], call.arguments["message"])
            destination_called = True
    final = decisions[-1]
    return {"status": "completed", "session_id": session_id, "run_id": run_id, "run_number": run_number,
            "events": [decision.event for decision in decisions],
            "decision": {"verdict": final.event.decision.value, "rule": final.event.rule,
                         "explanation": final.explanation, "destination_called": destination_called},
            "stats": session_stats(), "graph": session_graph(session_id, run_id)}


@app.websocket("/ws/live")
async def live(websocket: WebSocket) -> None:
    await websocket.accept()
    queue: asyncio.Queue[dict[str, object]] = asyncio.Queue(maxsize=40)
    store.subscribers.add(queue)
    try:
        await websocket.send_json({"type": "snapshot", "payload": {"events": [event.model_dump(mode="json") for event in store.events]}})
        while True:
            receive_task = asyncio.create_task(websocket.receive())
            event_task = asyncio.create_task(queue.get())
            try:
                done, _ = await asyncio.wait(
                    {receive_task, event_task},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if receive_task in done:
                    message = receive_task.result()
                    if message["type"] == "websocket.disconnect":
                        break
                if event_task in done:
                    await websocket.send_json(event_task.result())
            finally:
                for task in (receive_task, event_task):
                    if not task.done():
                        task.cancel()
                await asyncio.gather(receive_task, event_task, return_exceptions=True)
    except WebSocketDisconnect:
        pass
    finally:
        store.subscribers.discard(queue)


# Mount last: the SDK app owns /mcp and its lifespan is managed above because
# mounted ASGI applications do not receive their own lifespan events.
app.mount("/", mcp_app, name="mcp")
