from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class GatewayEventType(str, Enum):
    REQUEST_RECEIVED = "REQUEST_RECEIVED"
    POLICY_DECISION = "POLICY_DECISION"
    APPROVAL_REQUESTED = "APPROVAL_REQUESTED"
    APPROVAL_GRANTED = "APPROVAL_GRANTED"
    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    REVALIDATION = "REVALIDATION"
    FORWARDED = "FORWARDED"
    DOWNSTREAM_RESPONSE = "DOWNSTREAM_RESPONSE"
    DOWNSTREAM_ERROR = "DOWNSTREAM_ERROR"
    REQUEST_TERMINATED = "REQUEST_TERMINATED"


class GatewayAuditEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: uuid4().hex)
    event_type: GatewayEventType
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    request_id: str
    session_id: str | None = None
    server_id: str | None = None
    tool_name: str | None = None
    argument_fingerprint: str | None = None
    policy_version: str | None = None
    decision: str | None = None
    actor_id: str | None = None
    matched_policy_ids: list[str] = Field(default_factory=list)
    redacted_evidence: list[str] = Field(default_factory=list)
    forwarding_status: str = "NOT_FORWARDED"
    downstream_status: str | None = None


class GatewayAuditStore:
    """Single-process in-memory store. Never accepts raw arguments or tool results."""

    def __init__(self) -> None:
        self._events: deque[GatewayAuditEvent] = deque(maxlen=1_000)
        self._lock = asyncio.Lock()

    async def append(self, event: GatewayAuditEvent, limit: int | None = None) -> None:
        async with self._lock:
            if limit is not None and self._events.maxlen != limit:
                previous = list(self._events)
                self._events = deque(previous[-limit:], maxlen=limit)
            self._events.appendleft(event)

    async def snapshot(self) -> list[GatewayAuditEvent]:
        async with self._lock:
            return list(self._events)

    async def metrics(self) -> dict[str, int]:
        events = await self.snapshot()
        first_decisions: dict[str, str] = {}
        for event in reversed(events):
            if event.event_type == GatewayEventType.POLICY_DECISION and event.request_id not in first_decisions:
                first_decisions[event.request_id] = event.decision or "BLOCK"
        return {
            "tool_calls_total": len({e.request_id for e in events if e.event_type == GatewayEventType.REQUEST_RECEIVED}),
            "allow_count": sum(value == "ALLOW" for value in first_decisions.values()),
            "review_count": sum(value == "REVIEW" for value in first_decisions.values()),
            "block_count": sum(value == "BLOCK" for value in first_decisions.values()),
            "executed_count": len({e.request_id for e in events if e.event_type == GatewayEventType.FORWARDED}),
            "rejected_count": len({e.request_id for e in events if e.event_type == GatewayEventType.REQUEST_TERMINATED and e.forwarding_status == "REJECTED"}),
            "timed_out_count": len({e.request_id for e in events if e.event_type == GatewayEventType.REQUEST_TERMINATED and e.forwarding_status == "TIMED_OUT"}),
            "cancelled_count": len({e.request_id for e in events if e.event_type == GatewayEventType.REQUEST_TERMINATED and e.forwarding_status == "CANCELLED"}),
            "downstream_error_count": len({e.request_id for e in events if e.event_type == GatewayEventType.DOWNSTREAM_ERROR}),
            "audit_event_count": len(events),
        }

    async def clear(self) -> None:
        async with self._lock:
            self._events.clear()


gateway_audit = GatewayAuditStore()


def safe_event_payload(event: GatewayAuditEvent) -> dict[str, Any]:
    """Serialize the explicitly redacted audit schema for the dashboard and APIs."""
    return event.model_dump(mode="json")
