from __future__ import annotations

import asyncio
import copy
import hashlib
import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


class ApprovalError(Exception):
    """Base class for safe approval-store failures."""


class ApprovalNotFound(ApprovalError):
    pass


class ApprovalConflict(ApprovalError):
    pass


class ApprovalUnavailable(ApprovalError):
    pass


@dataclass(frozen=True)
class GrantBinding:
    session_id: str
    request_id: str
    server_id: str
    tool_name: str
    arguments_fingerprint: str
    policy_version: str
    approvable_policy_ids: frozenset[str]


@dataclass
class ApprovalGrant:
    grant_id: str
    binding: GrantBinding
    expires_at: datetime
    expires_monotonic: float
    approver_id: str
    reason_fingerprint: str
    status: str = "ACTIVE"


@dataclass(frozen=True)
class ApprovalResolution:
    status: ApprovalStatus
    grant_id: str | None = None


@dataclass
class PendingApproval:
    request_id: str
    session_id: str
    server_id: str
    tool_name: str
    arguments_fingerprint: str
    original_arguments: dict[str, Any] = field(repr=False)
    policy_version: str
    matched_policy_ids: tuple[str, ...]
    approvable_policy_ids: frozenset[str]
    redacted_evidence: tuple[str, ...]
    argument_count: int
    created_at: datetime
    expires_at: datetime
    expires_monotonic: float
    resolution: asyncio.Future[ApprovalResolution] = field(repr=False)
    status: ApprovalStatus = ApprovalStatus.PENDING
    approver_id: str | None = None
    reason_fingerprint: str | None = None
    grant_id: str | None = None


class ApprovalStore(ABC):
    """Async approval persistence contract. Implementations must make transitions atomic."""

    @abstractmethod
    async def create_pending(
        self,
        *,
        request_id: str,
        session_id: str,
        server_id: str,
        tool_name: str,
        arguments_fingerprint: str,
        original_arguments: dict[str, Any],
        policy_version: str,
        matched_policy_ids: tuple[str, ...],
        approvable_policy_ids: frozenset[str],
        redacted_evidence: tuple[str, ...],
        timeout_s: int,
    ) -> PendingApproval: ...

    @abstractmethod
    async def list_pending(self) -> list[PendingApproval]: ...

    @abstractmethod
    async def get_pending(self, request_id: str) -> PendingApproval: ...

    @abstractmethod
    async def get_grant(self, grant_id: str) -> ApprovalGrant: ...

    @abstractmethod
    async def decide(
        self,
        request_id: str,
        *,
        approved: bool,
        approver_id: str,
        reason: str,
        grant_ttl_s: int,
    ) -> ApprovalGrant | None: ...

    @abstractmethod
    async def expire(self, request_id: str) -> bool: ...

    @abstractmethod
    async def cancel(self, request_id: str) -> bool: ...

    @abstractmethod
    async def consume(
        self,
        grant_id: str,
        *,
        binding: GrantBinding,
        matched_policy_ids: frozenset[str],
    ) -> bool: ...

    @abstractmethod
    async def revoke(self, grant_id: str) -> None: ...


class InMemoryApprovalStore(ApprovalStore):
    """Single-process prototype store with lock-protected terminal transitions."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._pending: dict[str, PendingApproval] = {}
        self._grants: dict[str, ApprovalGrant] = {}
        self._lock = asyncio.Lock()
        self._clock = clock

    async def create_pending(
        self,
        *,
        request_id: str,
        session_id: str,
        server_id: str,
        tool_name: str,
        arguments_fingerprint: str,
        original_arguments: dict[str, Any],
        policy_version: str,
        matched_policy_ids: tuple[str, ...],
        approvable_policy_ids: frozenset[str],
        redacted_evidence: tuple[str, ...],
        timeout_s: int,
    ) -> PendingApproval:
        if timeout_s <= 0 or not approvable_policy_ids:
            raise ApprovalUnavailable("approval request is not safely reviewable")
        loop = asyncio.get_running_loop()
        now = self._clock()
        created = datetime.now(timezone.utc)
        record = PendingApproval(
            request_id=request_id,
            session_id=session_id,
            server_id=server_id,
            tool_name=tool_name,
            arguments_fingerprint=arguments_fingerprint,
            original_arguments=copy.deepcopy(original_arguments),
            policy_version=policy_version,
            matched_policy_ids=tuple(sorted(matched_policy_ids)),
            approvable_policy_ids=frozenset(approvable_policy_ids),
            redacted_evidence=tuple(redacted_evidence),
            argument_count=len(original_arguments),
            created_at=created,
            expires_at=created + timedelta(seconds=timeout_s),
            expires_monotonic=now + timeout_s,
            resolution=loop.create_future(),
        )
        async with self._lock:
            if request_id in self._pending:
                raise ApprovalConflict("approval request already exists")
            self._pending[request_id] = record
        return record

    async def list_pending(self) -> list[PendingApproval]:
        async with self._lock:
            return [record for record in self._pending.values() if record.status == ApprovalStatus.PENDING]

    async def get_pending(self, request_id: str) -> PendingApproval:
        async with self._lock:
            record = self._pending.get(request_id)
            if record is None:
                raise ApprovalNotFound("approval request was not found")
            return record

    async def get_grant(self, grant_id: str) -> ApprovalGrant:
        async with self._lock:
            grant = self._grants.get(grant_id)
            if grant is None:
                raise ApprovalNotFound("approval grant was not found")
            return grant

    async def decide(
        self,
        request_id: str,
        *,
        approved: bool,
        approver_id: str,
        reason: str,
        grant_ttl_s: int,
    ) -> ApprovalGrant | None:
        normalized_reason = reason.strip()
        if approved and not normalized_reason:
            raise ApprovalConflict("approval reason is required")
        if grant_ttl_s <= 0:
            raise ApprovalUnavailable("grant lifetime is invalid")

        async with self._lock:
            record = self._pending.get(request_id)
            if record is None:
                raise ApprovalNotFound("approval request was not found")
            if record.status != ApprovalStatus.PENDING:
                raise ApprovalConflict("approval request already has a terminal outcome")
            now_mono = self._clock()
            if now_mono >= record.expires_monotonic:
                record.status = ApprovalStatus.EXPIRED
                record.resolution.set_result(ApprovalResolution(ApprovalStatus.EXPIRED))
                raise ApprovalConflict("approval request has expired")

            reason_fingerprint = hashlib.sha256(normalized_reason.encode("utf-8")).hexdigest()
            record.approver_id = approver_id
            record.reason_fingerprint = reason_fingerprint
            if not approved:
                record.status = ApprovalStatus.REJECTED
                record.resolution.set_result(ApprovalResolution(ApprovalStatus.REJECTED))
                return None

            grant_created = datetime.now(timezone.utc)
            binding = GrantBinding(
                session_id=record.session_id,
                request_id=record.request_id,
                server_id=record.server_id,
                tool_name=record.tool_name,
                arguments_fingerprint=record.arguments_fingerprint,
                policy_version=record.policy_version,
                approvable_policy_ids=record.approvable_policy_ids,
            )
            grant = ApprovalGrant(
                grant_id=secrets.token_urlsafe(32),
                binding=binding,
                expires_at=grant_created + timedelta(seconds=grant_ttl_s),
                expires_monotonic=now_mono + grant_ttl_s,
                approver_id=approver_id,
                reason_fingerprint=reason_fingerprint,
            )
            record.status = ApprovalStatus.APPROVED
            record.grant_id = grant.grant_id
            self._grants[grant.grant_id] = grant
            record.resolution.set_result(ApprovalResolution(ApprovalStatus.APPROVED, grant.grant_id))
            return grant

    async def expire(self, request_id: str) -> bool:
        async with self._lock:
            record = self._pending.get(request_id)
            if record is None or record.status != ApprovalStatus.PENDING:
                return False
            if self._clock() < record.expires_monotonic:
                return False
            record.status = ApprovalStatus.EXPIRED
            record.resolution.set_result(ApprovalResolution(ApprovalStatus.EXPIRED))
            return True

    async def cancel(self, request_id: str) -> bool:
        async with self._lock:
            record = self._pending.get(request_id)
            if record is None:
                return False
            if record.status == ApprovalStatus.PENDING:
                record.status = ApprovalStatus.CANCELLED
                record.resolution.set_result(ApprovalResolution(ApprovalStatus.CANCELLED))
                return True
            if record.status == ApprovalStatus.APPROVED and record.grant_id:
                grant = self._grants.get(record.grant_id)
                if grant and grant.status == "ACTIVE":
                    grant.status = "REVOKED"
                return True
            return False

    async def consume(
        self,
        grant_id: str,
        *,
        binding: GrantBinding,
        matched_policy_ids: frozenset[str],
    ) -> bool:
        async with self._lock:
            grant = self._grants.get(grant_id)
            if grant is None or grant.status != "ACTIVE":
                return False
            if self._clock() >= grant.expires_monotonic:
                grant.status = "EXPIRED"
                return False
            if grant.binding != binding:
                grant.status = "REVOKED"
                return False
            if not matched_policy_ids or not matched_policy_ids.issubset(grant.binding.approvable_policy_ids):
                grant.status = "REVOKED"
                return False
            record = self._pending.get(binding.request_id)
            if record is None or record.status != ApprovalStatus.APPROVED or record.grant_id != grant_id:
                grant.status = "REVOKED"
                return False
            grant.status = "CONSUMED"
            return True

    async def revoke(self, grant_id: str) -> None:
        async with self._lock:
            grant = self._grants.get(grant_id)
            if grant is not None and grant.status == "ACTIVE":
                grant.status = "REVOKED"


def public_pending_view(record: PendingApproval) -> dict[str, Any]:
    """Return only redacted fields. Original arguments and approval material stay internal."""
    return {
        "request_id": record.request_id,
        "session_id": record.session_id,
        "server_id": record.server_id,
        "tool_name": record.tool_name,
        "argument_count": record.argument_count,
        "arguments_redacted": True,
        "policy_version": record.policy_version,
        "matched_policy_ids": list(record.matched_policy_ids),
        "approvable_policy_ids": sorted(record.approvable_policy_ids),
        "redacted_evidence": list(record.redacted_evidence),
        "created_at": record.created_at.isoformat(),
        "expires_at": record.expires_at.isoformat(),
        "status": record.status.value,
    }
