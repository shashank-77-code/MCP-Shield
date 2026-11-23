from __future__ import annotations

import asyncio
from dataclasses import replace

import pytest

from app.approvals import (
    ApprovalConflict,
    ApprovalStatus,
    InMemoryApprovalStore,
    public_pending_view,
)


def _create(store: InMemoryApprovalStore, request_id: str = "request-1", timeout_s: int = 20):
    return store.create_pending(
        request_id=request_id,
        session_id="session-1",
        server_id="fs",
        tool_name="delete_path",
        arguments_fingerprint="a" * 64,
        original_arguments={"path": "C:/safe/CANARY-APPROVAL-ARG.txt"},
        policy_version="A-test",
        matched_policy_ids=("P-006",),
        approvable_policy_ids=frozenset({"P-006"}),
        redacted_evidence=("P-006",),
        timeout_s=timeout_s,
    )


async def _approve(store: InMemoryApprovalStore, request_id: str = "request-1"):
    return await store.decide(
        request_id,
        approved=True,
        approver_id="ops-1",
        reason="Reviewed against the change ticket.",
        grant_ttl_s=10,
    )


def test_grant_is_request_specific_single_use_and_does_not_expose_arguments() -> None:
    async def exercise() -> None:
        store = InMemoryApprovalStore()
        raw_arguments = {"path": "C:/safe/CANARY-APPROVAL-ARG.txt"}
        pending = await store.create_pending(
            request_id="request-1",
            session_id="session-1",
            server_id="fs",
            tool_name="delete_path",
            arguments_fingerprint="a" * 64,
            original_arguments=raw_arguments,
            policy_version="A-test",
            matched_policy_ids=("P-006",),
            approvable_policy_ids=frozenset({"P-006"}),
            redacted_evidence=("P-006",),
            timeout_s=20,
        )
        raw_arguments["path"] = "C:/changed-after-request.txt"
        assert pending.original_arguments["path"] == "C:/safe/CANARY-APPROVAL-ARG.txt"
        public_view = str(public_pending_view(pending))
        assert "CANARY-APPROVAL-ARG" not in public_view
        assert "grant_id" not in public_view

        grant = await _approve(store)
        assert grant is not None
        binding = grant.binding
        assert await store.consume(grant.grant_id, binding=binding, matched_policy_ids=frozenset({"P-006"}))
        assert not await store.consume(grant.grant_id, binding=binding, matched_policy_ids=frozenset({"P-006"}))

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "field,value",
    [
        ("session_id", "other-session"),
        ("request_id", "other-request"),
        ("server_id", "other-server"),
        ("tool_name", "other-tool"),
        ("arguments_fingerprint", "b" * 64),
        ("policy_version", "other-version"),
        ("approvable_policy_ids", frozenset({"P-007"})),
    ],
)
def test_every_grant_binding_field_is_checked(field: str, value: object) -> None:
    async def exercise() -> None:
        store = InMemoryApprovalStore()
        await _create(store)
        grant = await _approve(store)
        assert grant is not None
        tampered = replace(grant.binding, **{field: value})
        assert not await store.consume(grant.grant_id, binding=tampered, matched_policy_ids=frozenset({"P-006"}))

    asyncio.run(exercise())


def test_duplicate_approve_and_reject_are_conflicts() -> None:
    async def exercise() -> None:
        store = InMemoryApprovalStore()
        await _create(store)
        await _approve(store)
        with pytest.raises(ApprovalConflict):
            await _approve(store)

        rejected = InMemoryApprovalStore()
        await _create(rejected)
        assert await rejected.decide(
            "request-1", approved=False, approver_id="ops-1", reason="Rejected.", grant_ttl_s=10
        ) is None
        with pytest.raises(ApprovalConflict):
            await rejected.decide(
                "request-1", approved=False, approver_id="ops-1", reason="Duplicate.", grant_ttl_s=10
            )

    asyncio.run(exercise())


def test_approve_versus_reject_race_has_exactly_one_terminal_winner() -> None:
    async def exercise() -> None:
        store = InMemoryApprovalStore()
        pending = await _create(store)

        async def act(approved: bool) -> str:
            try:
                await store.decide(
                    "request-1",
                    approved=approved,
                    approver_id="ops-1",
                    reason="Concurrent reviewer decision.",
                    grant_ttl_s=10,
                )
                return "approved" if approved else "rejected"
            except ApprovalConflict:
                return "conflict"

        results = await asyncio.gather(act(True), act(False))
        assert sorted(results).count("conflict") == 1
        assert pending.status in {ApprovalStatus.APPROVED, ApprovalStatus.REJECTED}

    asyncio.run(exercise())


def test_approval_versus_timeout_race_expires_without_grant() -> None:
    async def exercise() -> None:
        current = [100.0]
        store = InMemoryApprovalStore(clock=lambda: current[0])
        pending = await _create(store, timeout_s=1)
        current[0] = 101.0

        async def approve():
            try:
                return await _approve(store)
            except ApprovalConflict:
                return None

        expired, grant = await asyncio.gather(store.expire("request-1"), approve())
        assert grant is None
        record = await store.get_pending("request-1")
        assert record.status == ApprovalStatus.EXPIRED
        assert record.resolution.result().status == ApprovalStatus.EXPIRED
        assert expired in {True, False}

    asyncio.run(exercise())


def test_cancel_racing_approval_never_leaves_a_usable_grant() -> None:
    async def exercise() -> None:
        store = InMemoryApprovalStore()
        pending = await _create(store)

        async def approve():
            try:
                return await _approve(store)
            except ApprovalConflict:
                return None

        _, grant = await asyncio.gather(store.cancel("request-1"), approve())
        record = await store.get_pending("request-1")
        if record.status == ApprovalStatus.CANCELLED:
            assert grant is None
            assert record.resolution.result().status == ApprovalStatus.CANCELLED
        else:
            assert record.status == ApprovalStatus.APPROVED
            assert record.grant_id is not None
            saved = await store.get_grant(record.grant_id)
            assert saved.status == "REVOKED"
        assert pending.status in {ApprovalStatus.CANCELLED, ApprovalStatus.APPROVED}

    asyncio.run(exercise())


def test_grant_expiry_and_empty_approval_reason_fail_closed() -> None:
    async def exercise() -> None:
        current = [25.0]
        store = InMemoryApprovalStore(clock=lambda: current[0])
        await _create(store)
        with pytest.raises(ApprovalConflict):
            await store.decide(
                "request-1", approved=True, approver_id="ops-1", reason="   ", grant_ttl_s=1
            )
        grant = await store.decide(
            "request-1", approved=True, approver_id="ops-1", reason="Accept.", grant_ttl_s=1
        )
        assert grant is not None
        current[0] = 26.0
        assert not await store.consume(
            grant.grant_id,
            binding=grant.binding,
            matched_policy_ids=frozenset({"P-006"}),
        )

    asyncio.run(exercise())
