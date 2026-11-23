from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from .models import Event, Verdict


class ShieldStore:
    def __init__(self) -> None:
        self.events: deque[Event] = deque(maxlen=60)
        self.session_id = f"session-{uuid4().hex[:8]}"
        self.simulation_run_count = 0
        self.run_numbers: dict[str, int] = {}
        self.approvals: dict[str, Event] = {}
        self.session_taints: dict[str, set[str]] = {}
        self.mock_deliveries: list[dict[str, Any]] = []
        self.subscribers: set[asyncio.Queue[dict[str, Any]]] = set()

    async def publish(self, kind: str, payload: Any) -> None:
        message = {"type": kind, "payload": payload.model_dump(mode="json") if hasattr(payload, "model_dump") else payload}
        for queue in list(self.subscribers):
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                self.subscribers.discard(queue)

    async def add_event(self, event: Event) -> None:
        self.events.appendleft(event)
        await self.publish("event", event)

    async def queue_approval(self, event: Event) -> str:
        approval_id = uuid4().hex[:8]
        self.approvals[approval_id] = event
        await self.publish("approval", {"id": approval_id, "event": event.model_dump(mode="json")})
        return approval_id

    def begin_simulation(self) -> tuple[str, int]:
        self.simulation_run_count += 1
        run_id = uuid4().hex[:10]
        self.run_numbers[run_id] = self.simulation_run_count
        return run_id, self.simulation_run_count

    async def resolve_approval(self, approval_id: str, approved: bool) -> Event | None:
        original = self.approvals.pop(approval_id, None)
        if not original:
            return None
        outcome = original.model_copy(update={
            "event_id": uuid4().hex[:10],
            "event_type": "approval_decision",
            "timestamp": datetime.now(timezone.utc),
            "decision": Verdict.allow if approved else Verdict.block,
            "message": "Human approval granted" if approved else "Human approval denied",
            "rule": "HUMAN-ALLOW" if approved else "HUMAN-DENY",
        })
        await self.add_event(outcome)
        await self.publish("approval-resolved", {"id": approval_id, "approved": approved})
        return outcome

    async def reset(self) -> None:
        self.events.clear()
        self.approvals.clear()
        self.session_taints.clear()
        self.mock_deliveries.clear()
        self.session_id = f"session-{uuid4().hex[:8]}"
        self.simulation_run_count = 0
        self.run_numbers.clear()
        await self.publish("reset", {"ok": True})


store = ShieldStore()
