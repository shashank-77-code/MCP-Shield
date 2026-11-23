from __future__ import annotations

import asyncio
import contextvars
import hashlib
import hmac
import inspect
import json
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable
from uuid import uuid4

import jsonschema
from mcp.server.lowlevel.server import Server
from mcp.types import CallToolResult, TextContent, Tool, ToolAnnotations

from .approvals import (
    ApprovalConflict,
    ApprovalNotFound,
    ApprovalResolution,
    ApprovalStatus,
    ApprovalStore,
    ApprovalUnavailable,
    GrantBinding,
    InMemoryApprovalStore,
    public_pending_view,
)
from .downstream import DiscoveredTool, DownstreamConnectionManager, merge_session_field
from .gateway_audit import GatewayAuditEvent, GatewayEventType, gateway_audit
from .gateway_config import (
    Authorization,
    GatewayManifest,
    Integrity,
    OperationType,
    Sensitivity,
    load_approver_tokens,
    load_manifest,
)
from .jcs import fingerprint as jcs_fingerprint
from .policy_engine import PolicyConfig, PolicyOutcome, evaluate
from .security_context import SecurityContext, build_security_context, content_hash_from_result

_client_principal: contextvars.ContextVar[str | None] = contextvars.ContextVar("shield_client_principal", default=None)
ProgressCallback = Callable[[float, float | None, str | None], Awaitable[None]]


def token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def current_client_principal() -> str | None:
    return _client_principal.get()


def bind_client_principal(token: str) -> contextvars.Token[str | None]:
    return _client_principal.set(token_fingerprint(token))


def reset_client_principal(token: contextvars.Token[str | None]) -> None:
    _client_principal.reset(token)


@dataclass
class ReadResource:
    resource_id: str
    sensitivity: Sensitivity
    request_id: str
    content_hash: str | None
    event_id: str


@dataclass
class ApplicationSession:
    session_id: str
    owner_fingerprint: str
    created_at: datetime
    expires_at: datetime
    expires_monotonic: float
    integrity: Integrity = Integrity.TRUSTED
    confidentiality: Sensitivity = Sensitivity.PUBLIC
    resources: list[ReadResource] = field(default_factory=list)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class GatewayRuntime:
    def __init__(self, server: Server) -> None:
        self.server = server
        self.manifest: GatewayManifest | None = None
        self.downstream = DownstreamConnectionManager()
        self.sessions: dict[str, ApplicationSession] = {}
        self.client_token: str | None = None
        self.approver_tokens: dict[str, str] = {}
        self.approval_store: ApprovalStore = InMemoryApprovalStore()
        self._session_lock = asyncio.Lock()

    @property
    def configured(self) -> bool:
        return self.manifest is not None

    async def start(self) -> None:
        default_manifest = Path(__file__).resolve().parents[1] / "config" / "manifest.example.json"
        manifest_path = Path(os.environ.get("SHIELD_MANIFEST", str(default_manifest)))
        manifest = load_manifest(manifest_path)
        client_token = os.environ.get("SHIELD_CLIENT_TOKEN", "")
        if len(client_token) < 24:
            raise ValueError("SHIELD_CLIENT_TOKEN must be configured with at least 24 characters")
        approvers = load_approver_tokens(os.environ.get("SHIELD_APPROVER_TOKENS"))
        await self.downstream.start(manifest)
        self.manifest = manifest
        self.client_token = client_token
        self.approver_tokens = approvers

    async def stop(self) -> None:
        self.sessions.clear()
        self.manifest = None
        self.client_token = None
        self.approver_tokens.clear()
        await self.downstream.stop()

    def check_client_token(self, token: str | None) -> bool:
        expected = self.client_token
        if not token or not expected:
            return False
        return hmac.compare_digest(token.encode("utf-8"), expected.encode("utf-8"))

    def approver_identity(self, token: str | None) -> tuple[str | None, str]:
        """Return (approver ID, auth result); credentials are compared but never returned."""
        if not token:
            return None, "UNAUTHENTICATED"
        if self.check_client_token(token):
            return None, "CLIENT_CREDENTIAL"
        token_bytes = token.encode("utf-8")
        identity: str | None = None
        for approver_id, configured in self.approver_tokens.items():
            if hmac.compare_digest(token_bytes, configured.encode("utf-8")):
                identity = approver_id
        return (identity, "APPROVER") if identity is not None else (None, "UNAUTHENTICATED")

    async def pending_approvals(self) -> list[dict[str, Any]]:
        if not self.approver_tokens:
            raise ApprovalUnavailable("approvals are not configured")
        return [public_pending_view(record) for record in await self.approval_store.list_pending()]

    async def decide_approval(
        self,
        request_id: str,
        *,
        approved: bool,
        approver_id: str,
        reason: str,
    ) -> dict[str, Any]:
        manifest = self.manifest
        if not self.approver_tokens or manifest is None:
            raise ApprovalUnavailable("approvals are not configured")
        pending = await self.approval_store.get_pending(request_id)
        grant = await self.approval_store.decide(
            request_id,
            approved=approved,
            approver_id=approver_id,
            reason=reason,
            grant_ttl_s=manifest.approval.grant_ttl_s,
        )
        discovered = self.downstream.tools.get(f"{pending.server_id}__{pending.tool_name}")
        await self._audit(
            GatewayEventType.APPROVAL_GRANTED if approved else GatewayEventType.APPROVAL_REJECTED,
            request_id,
            pending.session_id,
            discovered,
            pending.arguments_fingerprint,
            decision="REVIEW_APPROVED" if approved else "REVIEW_REJECTED",
            matched=list(pending.matched_policy_ids),
            evidence=["approver reason fingerprint recorded"],
            forwarding_status="NOT_FORWARDED",
            actor_id=approver_id,
        )
        updated = await self.approval_store.get_pending(request_id)
        return {
            "ok": True,
            "request": public_pending_view(updated),
            "grant_issued": grant is not None,
        }

    async def create_session(self) -> dict[str, Any]:
        owner = current_client_principal()
        if owner is None or self.manifest is None:
            raise PermissionError("authenticated client context is required")
        now = datetime.now(timezone.utc)
        ttl = self.manifest.session_ttl_s
        session_id = "shs_" + secrets.token_urlsafe(32)
        record = ApplicationSession(
            session_id=session_id,
            owner_fingerprint=owner,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl),
            expires_monotonic=time.monotonic() + ttl,
            integrity=self.manifest.initial_session_integrity,
        )
        async with self._session_lock:
            self.sessions[session_id] = record
        return {"session_id": session_id, "expires_at": record.expires_at.isoformat(), "status": "created"}

    async def close_session(self, session_id: str) -> bool:
        owner = current_client_principal()
        async with self._session_lock:
            record = self.sessions.get(session_id)
            if record is None or owner is None or not hmac.compare_digest(record.owner_fingerprint, owner):
                return False
            del self.sessions[session_id]
            return True

    async def _get_session(self, session_id: str) -> ApplicationSession | None:
        owner = current_client_principal()
        if owner is None:
            return None
        async with self._session_lock:
            record = self.sessions.get(session_id)
            if record is None:
                return None
            if record.expires_monotonic <= time.monotonic():
                self.sessions.pop(session_id, None)
                return None
            if not hmac.compare_digest(record.owner_fingerprint, owner):
                return None
            return record

    def _authorization_for(self, server_id: str, tool_name: str) -> Authorization:
        assert self.manifest is not None
        results = [
            rule.result for rule in self.manifest.authorization
            if rule.match.server == server_id and rule.match.tool == tool_name
        ]
        if Authorization.DENIED in results:
            return Authorization.DENIED
        return results[0] if results else Authorization.NOT_CONFIGURED

    @staticmethod
    def _status_schema() -> dict[str, Any]:
        return {"type": "object", "properties": {}, "additionalProperties": False}

    @staticmethod
    def _open_session_schema() -> dict[str, Any]:
        return {"type": "object", "properties": {}, "additionalProperties": False}

    @staticmethod
    def _close_session_schema() -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {"shield_session_id": {"type": "string", "minLength": 16}},
            "required": ["shield_session_id"],
            "additionalProperties": False,
        }

    def _tool_policy(self, discovered: DiscoveredTool) -> Any:
        assert self.manifest is not None
        return self.manifest.servers[discovered.server_id].tools[discovered.tool_name]

    def input_schema_for(self, name: str) -> dict[str, Any] | None:
        if name == "shield_status":
            return self._status_schema()
        if name == "shield_session_open":
            return self._open_session_schema()
        if name == "shield_session_close":
            return self._close_session_schema()
        discovered = self.downstream.tools.get(name)
        return merge_session_field(discovered.schema) if discovered is not None else None

    def list_tools(self) -> list[Tool]:
        tools = [
            Tool(name="shield_status", description="Return Shield gateway readiness without request contents.", input_schema=self._status_schema(), annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False)),
            Tool(name="shield_session_open", description="Create an application session bound to the authenticated MCP client.", input_schema=self._open_session_schema(), annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False)),
            Tool(name="shield_session_close", description="Expire an application session owned by the authenticated MCP client.", input_schema=self._close_session_schema(), annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=False)),
        ]
        for name in sorted(self.downstream.tools):
            discovered = self.downstream.tools[name]
            policy = self._tool_policy(discovered)
            tools.append(Tool(
                name=name,
                description=policy.description,
                input_schema=merge_session_field(discovered.schema),
                annotations=ToolAnnotations(
                    read_only_hint=policy.operation_type == OperationType.READ,
                    destructive_hint=policy.operation_type in {OperationType.DELETE, OperationType.EXECUTE, OperationType.PERMISSION_MODIFY},
                    idempotent_hint=policy.operation_type == OperationType.READ,
                    open_world_hint=policy.impact_scope.value == "EXTERNAL",
                ),
            ))
        return tools

    async def dispatch_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        progress_callback: ProgressCallback | None = None,
    ) -> CallToolResult:
        if name == "shield_status":
            try:
                jsonschema.validate(arguments, self._status_schema())
            except Exception:
                return self._error_result("Request arguments are invalid.")
            count = len(self.downstream.clients)
            payload = {
                "status": "ok" if self.configured else "not_configured",
                "server_name": "MCP Shield",
                "version": "0.1.0",
                "transport": "streamable-http",
                "downstream_proxy_enabled": self.configured and count > 0,
                "downstream_server_count": count,
            }
            return self._structured_result(payload)

        if name == "shield_session_open":
            try:
                jsonschema.validate(arguments, self._open_session_schema())
                return self._structured_result(await self.create_session())
            except Exception:
                return self._error_result("Unable to create the Shield application session.")

        if name == "shield_session_close":
            try:
                jsonschema.validate(arguments, self._close_session_schema())
            except Exception:
                return self._error_result("Request arguments are invalid.")
            closed = await self.close_session(arguments["shield_session_id"])
            return self._structured_result({"closed": closed})

        discovered = self.downstream.tools.get(name)
        if discovered is None:
            request_id = uuid4().hex
            try:
                argument_fingerprint = jcs_fingerprint(arguments)
            except (TypeError, ValueError, OverflowError):
                argument_fingerprint = None
            await self._audit(GatewayEventType.REQUEST_RECEIVED, request_id, None, None, argument_fingerprint)
            await self._audit(GatewayEventType.POLICY_DECISION, request_id, None, None, argument_fingerprint,
                              decision="BLOCK", matched=["P-011"], evidence=["tool is not present in the validated manifest"])
            await self._audit(GatewayEventType.REQUEST_TERMINATED, request_id, None, None, argument_fingerprint,
                              decision="REJECTED", forwarding_status="REJECTED")
            return self._error_result("Request blocked by MCP Shield.")

        schema = merge_session_field(discovered.schema)
        try:
            jsonschema.validate(arguments, schema)
        except Exception:
            request_id = uuid4().hex
            try:
                argument_fingerprint = jcs_fingerprint(arguments)
            except (TypeError, ValueError, OverflowError):
                argument_fingerprint = None
            await self._audit(GatewayEventType.REQUEST_RECEIVED, request_id, None, discovered, argument_fingerprint)
            await self._decision(request_id, None, discovered, argument_fingerprint or "", "BLOCK", ["P-008"], ["arguments do not match the exposed tool schema"])
            await self._terminate(request_id, None, discovered, argument_fingerprint or "", "REJECTED")
            return self._error_result("Request blocked by MCP Shield.")
        call_arguments = dict(arguments)
        session_id = call_arguments.pop("shield_session_id")
        if not isinstance(session_id, str):
            return self._error_result("Request blocked by MCP Shield.")
        return await self.call_tool(
            discovered,
            self._tool_policy(discovered),
            session_id,
            call_arguments,
            progress_callback=progress_callback,
        )

    @staticmethod
    def _structured_result(value: dict[str, Any]) -> CallToolResult:
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(value, separators=(",", ":")))],
            structured_content=value,
        )

    @staticmethod
    def _error_result(message: str) -> CallToolResult:
        return CallToolResult(content=[TextContent(type="text", text=message)], is_error=True)

    async def call_tool(
        self,
        discovered: DiscoveredTool,
        tool_policy: Any,
        session_id: str,
        arguments: dict[str, Any],
        *,
        progress_callback: ProgressCallback | None = None,
    ) -> CallToolResult:
        manifest = self.manifest
        request_id = uuid4().hex
        try:
            argument_fingerprint = jcs_fingerprint(arguments)
        except (TypeError, ValueError, OverflowError):
            argument_fingerprint = ""
        if manifest is None:
            return self._error_result("MCP Shield is not configured.")

        session = await self._get_session(session_id)
        await self._audit(GatewayEventType.REQUEST_RECEIVED, request_id, session_id, discovered, argument_fingerprint or None)

        if session is None:
            await self._decision(request_id, session_id, discovered, argument_fingerprint, "BLOCK", ["P-008"], ["application session is missing, expired, or not owned by this client"])
            await self._terminate(request_id, session_id, discovered, argument_fingerprint, "REJECTED")
            return self._error_result("Request blocked by MCP Shield.")

        async with session.lock:
            try:
                jsonschema.validate(arguments, discovered.schema)
            except Exception:
                await self._decision(request_id, session_id, discovered, argument_fingerprint, "BLOCK", ["P-008"], ["arguments do not match the downstream tool schema"])
                await self._terminate(request_id, session_id, discovered, argument_fingerprint, "REJECTED")
                return self._error_result("Request blocked by MCP Shield.")

            authorization = self._authorization_for(discovered.server_id, discovered.tool_name)
            try:
                context: SecurityContext = build_security_context(
                    request_id=request_id,
                    session_id=session_id,
                    session=session,
                    discovered=discovered,
                    tool_policy=tool_policy,
                    arguments=arguments,
                    authorization=authorization,
                    manifest=manifest,
                )
                decision = evaluate(context, PolicyConfig(
                    block_external_send_when_session_secret=manifest.block_external_send_when_session_secret,
                ))
            except Exception:
                await self._decision(request_id, session_id, discovered, argument_fingerprint, "BLOCK", ["POLICY_ERROR"], ["security context construction failed closed"])
                await self._terminate(request_id, session_id, discovered, argument_fingerprint, "REJECTED")
                return self._error_result("Request blocked by MCP Shield.")

            reason_codes = [reason.code for reason in decision.reasons]
            await self._decision(
                request_id,
                session_id,
                discovered,
                argument_fingerprint,
                decision.verdict,
                list(decision.matched_policy_ids),
                reason_codes,
            )
            if decision.verdict == PolicyOutcome.BLOCK:
                await self._terminate(request_id, session_id, discovered, argument_fingerprint, "REJECTED")
                return self._error_result("Request blocked by MCP Shield.")
            forwarded_arguments = arguments
            forwarding_decision = PolicyOutcome.ALLOW
            forwarding_policy_ids = list(decision.matched_policy_ids)
            if decision.verdict == PolicyOutcome.REVIEW:
                reviewed = await self._hold_and_revalidate(
                    session=session,
                    original_context=context,
                    original_decision=decision,
                    discovered=discovered,
                    arguments=arguments,
                    request_id=request_id,
                    argument_fingerprint=argument_fingerprint,
                    progress_callback=progress_callback,
                )
                if reviewed is None:
                    return self._error_result("Request was not approved for forwarding by MCP Shield.")
                context, forwarded_arguments, decision = reviewed
                forwarding_decision = "REVIEW_APPROVED"
                forwarding_policy_ids = list(decision.matched_policy_ids)

            if discovered.server_id not in self.downstream.clients:
                await self._audit(
                    GatewayEventType.DOWNSTREAM_ERROR,
                    request_id,
                    session_id,
                    discovered,
                    argument_fingerprint,
                    decision=forwarding_decision,
                    matched=forwarding_policy_ids,
                    forwarding_status="NOT_FORWARDED",
                    downstream_status="UNAVAILABLE",
                )
                await self._terminate(request_id, session_id, discovered, argument_fingerprint, "DOWNSTREAM_ERROR")
                return self._error_result("Downstream MCP server is unavailable.")

            await self._audit(GatewayEventType.FORWARDED, request_id, session_id, discovered, argument_fingerprint, decision=forwarding_decision, matched=forwarding_policy_ids, forwarding_status="FORWARDED")
            try:
                result = await self.downstream.call(discovered.server_id, discovered.tool_name, forwarded_arguments)
            except asyncio.CancelledError:
                await self._terminate(request_id, session_id, discovered, argument_fingerprint, "CANCELLED", forwarding_status="FORWARDED")
                raise
            except Exception:
                await self._audit(GatewayEventType.DOWNSTREAM_ERROR, request_id, session_id, discovered, argument_fingerprint, decision=forwarding_decision, forwarding_status="FORWARDED", downstream_status="ERROR")
                await self._terminate(request_id, session_id, discovered, argument_fingerprint, "DOWNSTREAM_ERROR", forwarding_status="FORWARDED")
                return self._error_result("Downstream MCP server failed to complete the request.")

            if result.is_error:
                await self._audit(GatewayEventType.DOWNSTREAM_ERROR, request_id, session_id, discovered, argument_fingerprint, decision=forwarding_decision, forwarding_status="FORWARDED", downstream_status="ERROR")
                await self._terminate(request_id, session_id, discovered, argument_fingerprint, "DOWNSTREAM_ERROR", forwarding_status="FORWARDED")
                return self._error_result("Downstream MCP server returned an error.")

            self._update_session_ledger(session, context, tool_policy, request_id, result)
            await self._audit(GatewayEventType.DOWNSTREAM_RESPONSE, request_id, session_id, discovered, argument_fingerprint, decision=forwarding_decision, matched=forwarding_policy_ids, forwarding_status="FORWARDED", downstream_status="SUCCESS")
            return result

    async def _hold_and_revalidate(
        self,
        *,
        session: ApplicationSession,
        original_context: SecurityContext,
        original_decision: Any,
        discovered: DiscoveredTool,
        arguments: dict[str, Any],
        request_id: str,
        argument_fingerprint: str,
        progress_callback: ProgressCallback | None,
    ) -> tuple[SecurityContext, dict[str, Any], Any] | None:
        manifest_at_request = self.manifest
        if manifest_at_request is None or not self.approver_tokens:
            await self._terminate(request_id, session.session_id, discovered, argument_fingerprint, "REVIEW_DISABLED")
            return None

        try:
            pending = await self.approval_store.create_pending(
                request_id=request_id,
                session_id=session.session_id,
                server_id=discovered.server_id,
                tool_name=discovered.tool_name,
                arguments_fingerprint=argument_fingerprint,
                original_arguments=arguments,
                policy_version=manifest_at_request.policy_version,
                matched_policy_ids=tuple(original_decision.matched_policy_ids),
                approvable_policy_ids=frozenset(original_decision.approvable_policy_ids),
                redacted_evidence=tuple(reason.code for reason in original_decision.reasons),
                timeout_s=manifest_at_request.approval.timeout_s,
            )
        except asyncio.CancelledError:
            await self._terminate(request_id, session.session_id, discovered, argument_fingerprint, "CANCELLED")
            raise
        except Exception:
            await self._terminate(request_id, session.session_id, discovered, argument_fingerprint, "APPROVAL_STORE_ERROR")
            return None

        try:
            await self._audit(
                GatewayEventType.APPROVAL_REQUESTED,
                request_id,
                session.session_id,
                discovered,
                argument_fingerprint,
                decision="REVIEW",
                matched=list(original_decision.matched_policy_ids),
                evidence=[reason.code for reason in original_decision.reasons],
                forwarding_status="HELD",
            )
        except asyncio.CancelledError:
            try:
                await self.approval_store.cancel(request_id)
            finally:
                await self._terminate(request_id, session.session_id, discovered, argument_fingerprint, "CANCELLED")
            raise
        except Exception:
            try:
                await self.approval_store.cancel(request_id)
            except Exception:
                pass
            await self._terminate(request_id, session.session_id, discovered, argument_fingerprint, "AUDIT_ERROR")
            return None
        try:
            if progress_callback is not None:
                await progress_callback(0, 1, "Waiting for authenticated approval.")
            resolution: ApprovalResolution = await asyncio.wait_for(
                asyncio.shield(pending.resolution),
                timeout=manifest_at_request.approval.timeout_s,
            )
        except TimeoutError:
            try:
                expired = await self.approval_store.expire(request_id)
            except Exception:
                expired = False
            if expired:
                await self._audit(
                    GatewayEventType.APPROVAL_EXPIRED,
                    request_id,
                    session.session_id,
                    discovered,
                    argument_fingerprint,
                    decision="REVIEW_EXPIRED",
                    matched=list(original_decision.matched_policy_ids),
                    forwarding_status="NOT_FORWARDED",
                )
                await self._terminate(request_id, session.session_id, discovered, argument_fingerprint, "TIMED_OUT")
                return None
            if pending.resolution.done():
                resolution = pending.resolution.result()
            else:
                try:
                    await self.approval_store.cancel(request_id)
                except Exception:
                    pass
                await self._terminate(request_id, session.session_id, discovered, argument_fingerprint, "TIMED_OUT")
                return None
        except asyncio.CancelledError:
            try:
                await self.approval_store.cancel(request_id)
            finally:
                await self._terminate(request_id, session.session_id, discovered, argument_fingerprint, "CANCELLED")
            raise
        except Exception:
            try:
                await self.approval_store.cancel(request_id)
            except Exception:
                pass
            await self._terminate(request_id, session.session_id, discovered, argument_fingerprint, "APPROVAL_STORE_ERROR")
            return None

        if resolution.status != ApprovalStatus.APPROVED or resolution.grant_id is None:
            if resolution.status == ApprovalStatus.EXPIRED:
                await self._audit(
                    GatewayEventType.APPROVAL_EXPIRED,
                    request_id,
                    session.session_id,
                    discovered,
                    argument_fingerprint,
                    decision="REVIEW_EXPIRED",
                    matched=list(original_decision.matched_policy_ids),
                    forwarding_status="NOT_FORWARDED",
                )
                terminal_status = "TIMED_OUT"
            elif resolution.status == ApprovalStatus.CANCELLED:
                terminal_status = "CANCELLED"
            else:
                terminal_status = "REJECTED"
            await self._terminate(request_id, session.session_id, discovered, argument_fingerprint, terminal_status)
            return None

        try:
            if progress_callback is not None:
                await progress_callback(1, 1, "Approval received; revalidating the request.")
            grant = await self.approval_store.get_grant(resolution.grant_id)
            # Re-validate the current in-memory security configuration and route.
            manifest = GatewayManifest.model_validate(self.manifest.model_dump()) if self.manifest is not None else None
            current_session = await self._get_session(session.session_id)
            current_discovered = self.downstream.tools.get(discovered.namespaced_name)
            if (
                manifest is None
                or manifest.policy_version != pending.policy_version
                or current_session is not session
                or current_discovered is None
            ):
                raise ValueError("security configuration or session changed")
            current_tool_policy = manifest.servers[current_discovered.server_id].tools[current_discovered.tool_name]
            current_fingerprint = jcs_fingerprint(pending.original_arguments)
            if not hmac.compare_digest(current_fingerprint, pending.arguments_fingerprint):
                raise ValueError("held arguments changed")
            jsonschema.validate(pending.original_arguments, current_discovered.schema)
            authorization = self._authorization_for(current_discovered.server_id, current_discovered.tool_name)
            context = build_security_context(
                request_id=request_id,
                session_id=session.session_id,
                session=current_session,
                discovered=current_discovered,
                tool_policy=current_tool_policy,
                arguments=pending.original_arguments,
                authorization=authorization,
                manifest=manifest,
            )
            decision = evaluate(context, PolicyConfig(
                block_external_send_when_session_secret=manifest.block_external_send_when_session_secret,
            ))
            await self._audit(
                GatewayEventType.REVALIDATION,
                request_id,
                session.session_id,
                current_discovered,
                current_fingerprint,
                decision=decision.verdict,
                matched=list(decision.matched_policy_ids),
                evidence=[reason.code for reason in decision.reasons],
                forwarding_status="NOT_FORWARDED",
            )
            new_policy_ids = frozenset(decision.matched_policy_ids)
            if (
                decision.verdict != PolicyOutcome.REVIEW
                or not new_policy_ids
                or not new_policy_ids.issubset(grant.binding.approvable_policy_ids)
            ):
                await self.approval_store.revoke(grant.grant_id)
                await self._terminate(request_id, session.session_id, current_discovered, current_fingerprint, "REVALIDATION_BLOCK")
                return None

            binding = GrantBinding(
                session_id=session.session_id,
                request_id=request_id,
                server_id=current_discovered.server_id,
                tool_name=current_discovered.tool_name,
                arguments_fingerprint=current_fingerprint,
                policy_version=manifest.policy_version,
                approvable_policy_ids=grant.binding.approvable_policy_ids,
            )
            consumed = await self.approval_store.consume(
                grant.grant_id,
                binding=binding,
                matched_policy_ids=new_policy_ids,
            )
            if not consumed:
                await self.approval_store.revoke(grant.grant_id)
                await self._terminate(request_id, session.session_id, current_discovered, current_fingerprint, "INVALID_GRANT")
                return None
            return context, pending.original_arguments, decision
        except asyncio.CancelledError:
            try:
                await self.approval_store.cancel(request_id)
                await self.approval_store.revoke(resolution.grant_id)
            finally:
                await self._terminate(request_id, session.session_id, discovered, argument_fingerprint, "CANCELLED")
            raise
        except Exception:
            try:
                await self.approval_store.revoke(resolution.grant_id)
            except Exception:
                pass
            await self._terminate(request_id, session.session_id, discovered, argument_fingerprint, "REVALIDATION_ERROR")
            return None

    @staticmethod
    def _update_session_ledger(
        session: ApplicationSession,
        context: SecurityContext,
        tool_policy: Any,
        request_id: str,
        result: CallToolResult,
    ) -> None:
        if tool_policy.operation_type == OperationType.READ:
            content_hash = content_hash_from_result(result)
            for target in context.resource_targets:
                session.resources.append(ReadResource(
                    resource_id=target.value,
                    sensitivity=target.sensitivity,
                    request_id=request_id,
                    content_hash=content_hash,
                    event_id=request_id,
                ))
                levels = {
                    Sensitivity.PUBLIC: 0,
                    Sensitivity.INTERNAL: 1,
                    Sensitivity.CONFIDENTIAL: 2,
                    Sensitivity.SECRET: 3,
                }
                if levels[target.sensitivity] > levels[session.confidentiality]:
                    session.confidentiality = target.sensitivity
        if tool_policy.returns_untrusted_content:
            session.integrity = Integrity.UNTRUSTED

    @staticmethod
    def _check_path_boundaries(tool_policy: Any, arguments: dict[str, Any], manifest: GatewayManifest) -> str | None:
        for mapping in tool_policy.resource_args:
            if mapping.kind != ResourceKind.PATH:
                continue
            value: Any = arguments
            for part in mapping.pointer[1:].split("/"):
                key = part.replace("~1", "/").replace("~0", "~")
                if not isinstance(value, dict) or key not in value:
                    return "required path resource is missing"
                value = value[key]
            if not isinstance(value, str) or not value:
                return "path resource is malformed"
            try:
                resolved = Path(value).expanduser().resolve(strict=False)
                if not any(resolved.is_relative_to(root.expanduser().resolve(strict=False)) for root in manifest.allowed_roots):
                    return "path resource is outside configured allowed roots"
            except (OSError, RuntimeError, ValueError):
                return "path resource cannot be safely resolved"
        return None

    async def _audit(
        self,
        event_type: GatewayEventType,
        request_id: str,
        session_id: str | None,
        discovered: DiscoveredTool | None,
        fingerprint: str | None,
        *,
        decision: str | None = None,
        actor_id: str | None = None,
        matched: list[str] | None = None,
        evidence: list[str] | None = None,
        forwarding_status: str = "NOT_FORWARDED",
        downstream_status: str | None = None,
    ) -> None:
        manifest = self.manifest
        await gateway_audit.append(GatewayAuditEvent(
            event_type=event_type,
            request_id=request_id,
            session_id=session_id,
            server_id=discovered.server_id if discovered else None,
            tool_name=discovered.tool_name if discovered else None,
            argument_fingerprint=fingerprint,
            policy_version=manifest.policy_version if manifest else None,
            decision=decision,
            actor_id=actor_id,
            matched_policy_ids=matched or [],
            redacted_evidence=evidence or [],
            forwarding_status=forwarding_status,
            downstream_status=downstream_status,
        ), limit=manifest.audit_limit if manifest else 1_000)

    async def _decision(
        self,
        request_id: str,
        session_id: str | None,
        discovered: DiscoveredTool,
        fingerprint: str,
        decision: str,
        policy_ids: list[str],
        evidence: list[str],
    ) -> None:
        await self._audit(GatewayEventType.POLICY_DECISION, request_id, session_id, discovered, fingerprint,
                          decision=decision, matched=policy_ids, evidence=evidence,
                          forwarding_status="NOT_FORWARDED")

    async def _terminate(
        self,
        request_id: str,
        session_id: str | None,
        discovered: DiscoveredTool,
        fingerprint: str,
        status: str,
        *,
        forwarding_status: str = "NOT_FORWARDED",
    ) -> None:
        await self._audit(GatewayEventType.REQUEST_TERMINATED, request_id, session_id, discovered, fingerprint,
                          decision=status, forwarding_status=status if forwarding_status == "NOT_FORWARDED" else forwarding_status)


runtime: GatewayRuntime | None = None


def configure_runtime(server: Server) -> GatewayRuntime:
    global runtime
    runtime = GatewayRuntime(server)
    return runtime


def get_runtime() -> GatewayRuntime:
    if runtime is None:
        raise RuntimeError("MCP Shield runtime is not initialized")
    return runtime
