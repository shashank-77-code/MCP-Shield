from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    allow = "allow"
    review = "review"
    block = "block"


class ToolCall(BaseModel):
    tool: str = Field(min_length=1, max_length=120)
    arguments: dict[str, Any] = Field(default_factory=dict)
    session_id: str | None = None
    run_id: str | None = None
    source: str = "mcp-client"


class Event(BaseModel):
    event_id: str = Field(default_factory=lambda: uuid4().hex)
    event_type: str = "tool_call"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tool_name: str
    source: str
    session_id: str
    run_id: str | None = None
    decision: Verdict
    message: str
    taints: list[str] = Field(default_factory=list)
    rule: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    latency_ms: float = 0


class Decision(BaseModel):
    event: Event
    explanation: str
    approval_required: bool = False
    approval_id: str | None = None
