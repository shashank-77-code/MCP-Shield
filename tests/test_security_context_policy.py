from __future__ import annotations

import asyncio
import itertools
import subprocess
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from mcp.types import CallToolResult, TextContent

from app.gateway import (
    ApplicationSession,
    GatewayRuntime,
    ReadResource,
    bind_client_principal,
    reset_client_principal,
)
from app.gateway_config import (
    Authorization,
    Destinations,
    DestinationTrust,
    GatewayManifest,
    ImpactScope,
    Integrity,
    OperationType,
    PayloadEvidence,
    ResourceArgument,
    ResourceKind,
    SecretDetector,
    Sensitivity,
    ToolManifest,
    canonicalize_destination,
)
from app.jcs import canonicalize, fingerprint
from app.policy_engine import PolicyConfig, PolicyOutcome, evaluate
from app.security_context import ResourceTarget, SecurityContext, build_security_context


def _context(**updates: object) -> SecurityContext:
    values: dict[str, object] = {
        "request_id": "request-1",
        "session_id": "session-1",
        "trace_id": "trace-1",
        "server_id": "fs",
        "tool_name": "read_file",
        "arguments_fingerprint": "a" * 64,
        "operation_type": OperationType.READ,
        "impact_scope": ImpactScope.PROJECT,
        "authorization": Authorization.AUTHORIZED,
        "resource_targets": (),
        "effective_sensitivity": Sensitivity.PUBLIC,
        "session_integrity": Integrity.TRUSTED,
        "session_confidentiality": Sensitivity.PUBLIC,
        "payload_evidence": PayloadEvidence.CLEAN,
        "destination_trust": DestinationTrust.NOT_APPLICABLE,
        "missing_fields": (),
        "policy_version": "test-v1",
        "manifest_tool_exists": True,
        "auto_allow": True,
        "resource_boundaries_satisfied": True,
        "required_metadata_complete": True,
        "destination_redirect_safe": True,
        "session_secret_present": False,
        "secret_detector_match": False,
    }
    values.update(updates)
    return SecurityContext(**values)


def _manifest(root: Path | None = None, **updates: object) -> GatewayManifest:
    values: dict[str, object] = {"policy_version": "test-v1"}
    if root is not None:
        values["allowed_roots"] = [root]
    values.update(updates)
    return GatewayManifest(**values)


def _session() -> ApplicationSession:
    now = datetime.now(timezone.utc)
    return ApplicationSession(
        session_id="session-1",
        owner_fingerprint="owner-hash",
        created_at=now,
        expires_at=now + timedelta(minutes=5),
        expires_monotonic=10_000_000_000.0,
    )


def _decision(context: SecurityContext, *, block_secret_session: bool = False):
    return evaluate(context, PolicyConfig(block_external_send_when_session_secret=block_secret_session))


def test_policy_rows_p001_through_p006() -> None:
    outside = _context(
        resource_targets=(ResourceTarget(kind=ResourceKind.PATH, value="/outside", boundary_satisfied=False, sensitivity=Sensitivity.INTERNAL),),
        resource_boundaries_satisfied=False,
    )
    assert _decision(outside).verdict == PolicyOutcome.BLOCK
    assert "P-001" in _decision(outside).matched_policy_ids

    credential_access = _context(operation_type=OperationType.CREDENTIAL_ACCESS, authorization=Authorization.APPROVAL_REQUIRED)
    assert "P-001" in _decision(credential_access).matched_policy_ids
    assert _decision(credential_access).verdict == PolicyOutcome.BLOCK

    secret_egress = _context(
        operation_type=OperationType.EXTERNAL_SEND,
        impact_scope=ImpactScope.EXTERNAL,
        destination_trust=DestinationTrust.APPROVED,
        secret_detector_match=True,
        payload_evidence=PayloadEvidence.SECRET_DETECTED,
    )
    assert "P-002" in _decision(secret_egress).matched_policy_ids
    assert _decision(secret_egress).verdict == PolicyOutcome.BLOCK

    referenced_secret = _context(
        operation_type=OperationType.EXTERNAL_SEND,
        impact_scope=ImpactScope.EXTERNAL,
        destination_trust=DestinationTrust.RESTRICTED,
        payload_evidence=PayloadEvidence.RESOURCE_REFERENCED,
        effective_sensitivity=Sensitivity.SECRET,
    )
    assert "P-003" in _decision(referenced_secret).matched_policy_ids
    assert _decision(referenced_secret).verdict == PolicyOutcome.BLOCK

    untrusted_delete = _context(operation_type=OperationType.DELETE, session_integrity=Integrity.UNTRUSTED)
    assert "P-004" in _decision(untrusted_delete).matched_policy_ids
    assert _decision(untrusted_delete).verdict == PolicyOutcome.BLOCK

    denied_org_delete = _context(
        operation_type=OperationType.DELETE,
        impact_scope=ImpactScope.ORGANISATION,
        authorization=Authorization.DENIED,
    )
    assert "P-005" in _decision(denied_org_delete).matched_policy_ids
    assert _decision(denied_org_delete).verdict == PolicyOutcome.BLOCK

    authorized_delete = _context(operation_type=OperationType.DELETE, impact_scope=ImpactScope.LOCAL)
    result = _decision(authorized_delete)
    assert result.verdict == PolicyOutcome.REVIEW
    assert "P-006" in result.matched_policy_ids
    assert "P-006" in result.approvable_policy_ids


def test_policy_rows_p007_through_p012_and_precedence() -> None:
    uncertain_send = _context(
        operation_type=OperationType.EXTERNAL_SEND,
        impact_scope=ImpactScope.EXTERNAL,
        destination_trust=DestinationTrust.UNKNOWN,
        payload_evidence=PayloadEvidence.INDETERMINATE,
        effective_sensitivity=Sensitivity.CONFIDENTIAL,
    )
    result = _decision(uncertain_send)
    assert result.verdict == PolicyOutcome.REVIEW
    assert "P-007" in result.matched_policy_ids
    assert "P-007" in result.approvable_policy_ids

    public_reference = _context(
        operation_type=OperationType.EXTERNAL_SEND,
        impact_scope=ImpactScope.EXTERNAL,
        destination_trust=DestinationTrust.UNKNOWN,
        payload_evidence=PayloadEvidence.RESOURCE_REFERENCED,
        effective_sensitivity=Sensitivity.PUBLIC,
    )
    assert "P-007" not in _decision(public_reference).matched_policy_ids
    assert _decision(public_reference).verdict == PolicyOutcome.BLOCK

    missing = _context(missing_fields=("/path",), required_metadata_complete=False)
    assert "P-008" in _decision(missing).matched_policy_ids
    assert _decision(missing).verdict == PolicyOutcome.BLOCK

    for auth in (Authorization.DENIED, Authorization.NOT_CONFIGURED):
        result = _decision(_context(authorization=auth))
        assert "P-009" in result.matched_policy_ids
        assert result.verdict == PolicyOutcome.BLOCK

    approval_without_review_policy = _context(authorization=Authorization.APPROVAL_REQUIRED)
    assert "P-009" in _decision(approval_without_review_policy).matched_policy_ids
    assert _decision(approval_without_review_policy).verdict == PolicyOutcome.BLOCK

    approval_for_reviewable_send = _context(
        operation_type=OperationType.EXTERNAL_SEND,
        impact_scope=ImpactScope.EXTERNAL,
        authorization=Authorization.APPROVAL_REQUIRED,
        destination_trust=DestinationTrust.UNKNOWN,
        payload_evidence=PayloadEvidence.INDETERMINATE,
        effective_sensitivity=Sensitivity.CONFIDENTIAL,
    )
    assert _decision(approval_for_reviewable_send).verdict == PolicyOutcome.REVIEW
    assert "P-009" in _decision(approval_for_reviewable_send).matched_policy_ids

    valid_read = _context()
    assert _decision(valid_read).verdict == PolicyOutcome.ALLOW
    assert "P-010" in _decision(valid_read).matched_policy_ids

    no_auto_allow = _context(auto_allow=False)
    assert _decision(no_auto_allow).verdict == PolicyOutcome.BLOCK
    assert "P-010" not in _decision(no_auto_allow).matched_policy_ids

    unmapped = _context(manifest_tool_exists=False)
    assert "P-011" in _decision(unmapped).matched_policy_ids
    assert _decision(unmapped).verdict == PolicyOutcome.BLOCK

    untrusted_write = _context(operation_type=OperationType.WRITE, session_integrity=Integrity.UNTRUSTED)
    assert "P-012" in _decision(untrusted_write).matched_policy_ids
    assert _decision(untrusted_write).verdict == PolicyOutcome.REVIEW

    blocked_review_overlap = _context(
        operation_type=OperationType.EXTERNAL_SEND,
        impact_scope=ImpactScope.EXTERNAL,
        destination_trust=DestinationTrust.UNKNOWN,
        payload_evidence=PayloadEvidence.SECRET_DETECTED,
        effective_sensitivity=Sensitivity.CONFIDENTIAL,
        secret_detector_match=True,
    )
    result = _decision(blocked_review_overlap)
    assert result.verdict == PolicyOutcome.BLOCK
    assert "P-002" in result.matched_policy_ids
    assert "P-007" not in result.matched_policy_ids


def test_strict_external_send_allow_requires_approved_clean_trusted_and_redirect_safe() -> None:
    safe = _context(
        operation_type=OperationType.EXTERNAL_SEND,
        impact_scope=ImpactScope.EXTERNAL,
        destination_trust=DestinationTrust.APPROVED,
        payload_evidence=PayloadEvidence.CLEAN,
        effective_sensitivity=Sensitivity.INTERNAL,
        session_integrity=Integrity.TRUSTED,
        destination_redirect_safe=True,
    )
    assert _decision(safe).verdict == PolicyOutcome.ALLOW

    for changes in (
        {"destination_trust": DestinationTrust.UNKNOWN},
        {"payload_evidence": PayloadEvidence.INDETERMINATE},
        {"session_integrity": Integrity.UNTRUSTED},
        {"effective_sensitivity": Sensitivity.CONFIDENTIAL},
        {"destination_redirect_safe": False},
    ):
        result = _decision(safe.model_copy(update=changes))
        assert result.verdict != PolicyOutcome.ALLOW


def test_policy_error_fails_closed() -> None:
    result = evaluate(_context(), None)
    assert result.verdict == PolicyOutcome.BLOCK
    assert result.matched_policy_ids == ("POLICY_ERROR",)


def _assert_allow_is_strict(context: SecurityContext, result: object) -> None:
    if result.verdict != PolicyOutcome.ALLOW:
        return
    assert context.authorization == Authorization.AUTHORIZED
    assert context.manifest_tool_exists
    assert context.auto_allow
    assert context.required_metadata_complete and not context.missing_fields
    assert context.operation_type is not None and context.impact_scope is not None
    assert context.session_integrity != Integrity.UNKNOWN
    assert context.session_confidentiality is not None
    assert context.effective_sensitivity is not None
    assert context.resource_boundaries_satisfied
    assert context.destination_redirect_safe
    if context.operation_type == OperationType.EXTERNAL_SEND:
        assert not context.secret_detector_match
        assert context.destination_trust == DestinationTrust.APPROVED
        assert context.payload_evidence == PayloadEvidence.CLEAN
        assert context.session_integrity == Integrity.TRUSTED
        assert context.effective_sensitivity in {Sensitivity.PUBLIC, Sensitivity.INTERNAL}


def test_no_context_combination_can_allow_without_all_p010_conditions() -> None:
    """Exhaustively enumerate the finite decision-relevant enum/flag domains."""
    config = PolicyConfig(block_external_send_when_session_secret=False)
    sensitivities: list[Sensitivity | None] = [None, *Sensitivity]
    non_send_operations = [operation for operation in OperationType if operation != OperationType.EXTERNAL_SEND]

    common_values = itertools.product(
        non_send_operations,
        ImpactScope,
        Authorization,
        Integrity,
        sensitivities,
        (False, True),  # mapped tool
        (False, True),  # auto_allow
        (False, True),  # metadata complete
        (False, True),  # resource boundaries
        (False, True),  # redirect handling safe
    )
    for operation, scope, auth, integrity, sensitivity, mapped, auto, complete, boundary_ok, redirect_safe in common_values:
        missing = () if complete else ("required-field",)
        context = _context(
            operation_type=operation,
            impact_scope=scope,
            authorization=auth,
            session_integrity=integrity,
            effective_sensitivity=sensitivity,
            session_confidentiality=sensitivity,
            manifest_tool_exists=mapped,
            auto_allow=auto,
            required_metadata_complete=complete,
            missing_fields=missing,
            resource_boundaries_satisfied=boundary_ok,
            destination_redirect_safe=redirect_safe,
        )
        _assert_allow_is_strict(context, evaluate(context, config))

    external_values = itertools.product(
        Authorization,
        Integrity,
        sensitivities,
        DestinationTrust,
        PayloadEvidence,
        (False, True),  # mapped tool
        (False, True),  # auto_allow
        (False, True),  # metadata complete
        (False, True),  # resource boundaries
        (False, True),  # redirect handling safe
        (False, True),  # configured detector match
    )
    for auth, integrity, sensitivity, destination, evidence, mapped, auto, complete, boundary_ok, redirect_safe, secret_match in external_values:
        missing = () if complete else ("required-field",)
        context = _context(
            operation_type=OperationType.EXTERNAL_SEND,
            impact_scope=ImpactScope.EXTERNAL,
            authorization=auth,
            session_integrity=integrity,
            effective_sensitivity=sensitivity,
            session_confidentiality=sensitivity,
            destination_trust=destination,
            payload_evidence=evidence,
            manifest_tool_exists=mapped,
            auto_allow=auto,
            required_metadata_complete=complete,
            missing_fields=missing,
            resource_boundaries_satisfied=boundary_ok,
            destination_redirect_safe=redirect_safe,
            secret_detector_match=secret_match,
        )
        _assert_allow_is_strict(context, evaluate(context, config))


def test_path_traversal_and_symlink_escape_are_resolved_at_check_time(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    manifest = _manifest(allowed)
    tool = ToolManifest(
        operation_type=OperationType.READ,
        impact_scope=ImpactScope.PROJECT,
        resource_args=[ResourceArgument(pointer="/path", kind=ResourceKind.PATH)],
        auto_allow=True,
    )
    discovered = SimpleNamespace(server_id="fs", tool_name="read_file")
    session = _session()

    traversal = build_security_context(
        request_id="path-traversal",
        session_id=session.session_id,
        session=session,
        discovered=discovered,
        tool_policy=tool,
        arguments={"path": str(allowed / ".." / "outside" / "secret.txt")},
        authorization=Authorization.AUTHORIZED,
        manifest=manifest,
    )
    assert not traversal.resource_boundaries_satisfied
    assert "P-001" in _decision(traversal).matched_policy_ids

    link = allowed / "escape"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as symlink_error:
        if os.name != "nt":
            pytest.fail(f"symlink escape test could not create its link: {symlink_error}")
        link_literal = str(link).replace("'", "''")
        outside_literal = str(outside).replace("'", "''")
        junction = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                f"New-Item -ItemType Junction -Path '{link_literal}' -Target '{outside_literal}' | Out-Null",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if junction.returncode != 0:
            pytest.fail(f"could not create a Windows junction for symlink coverage: {junction.stderr or junction.stdout}")
    symlink_escape = build_security_context(
        request_id="symlink-escape",
        session_id=session.session_id,
        session=session,
        discovered=discovered,
        tool_policy=tool,
        arguments={"path": str(link / "secret.txt")},
        authorization=Authorization.AUTHORIZED,
        manifest=manifest,
    )
    assert not symlink_escape.resource_boundaries_satisfied
    assert "P-001" in _decision(symlink_escape).matched_policy_ids


def test_repository_normalization_and_url_canonicalization() -> None:
    manifest = _manifest(allowed_repos=["Org/Safe-Repo"])
    tool = ToolManifest(
        operation_type=OperationType.READ,
        impact_scope=ImpactScope.PROJECT,
        resource_args=[ResourceArgument(pointer="/repo", kind=ResourceKind.REPO)],
        auto_allow=True,
    )
    session = _session()
    context = build_security_context(
        request_id="repo-normalized",
        session_id=session.session_id,
        session=session,
        discovered=SimpleNamespace(server_id="git", tool_name="get_issue"),
        tool_policy=tool,
        arguments={"repo": "org/safe-repo"},
        authorization=Authorization.AUTHORIZED,
        manifest=manifest,
    )
    assert context.resource_boundaries_satisfied
    assert context.resource_targets[0].value == "org/safe-repo"

    assert canonicalize_destination("HTTPS://BÜCHER.example.:443") == "https://xn--bcher-kva.example/"
    assert canonicalize_destination("https://[2001:0db8::1]:443/path") == "https://[2001:db8::1]/path"
    with pytest.raises(ValueError):
        canonicalize_destination("https://user:password@example.test/hook")
    with pytest.raises(ValueError):
        canonicalize_destination("https://example.test/hook#fragment")


def test_secret_detector_and_external_payload_provenance() -> None:
    manifest = _manifest(
        destinations=Destinations(approved=["https://hooks.example/"], restricted=["https://paste.example/"]),
        secret_detectors=[SecretDetector(name="test_canary", pattern=r"CANARY-[A-Z0-9]{8}")],
    )
    send_tool = ToolManifest(
        operation_type=OperationType.EXTERNAL_SEND,
        impact_scope=ImpactScope.EXTERNAL,
        destination_arg="/url",
        payload_args=["/body"],
        auto_allow=True,
        redirects_blocked=True,
    )
    session = _session()
    canary = "CANARY-AB12CD34"
    context = build_security_context(
        request_id="outgoing-secret",
        session_id=session.session_id,
        session=session,
        discovered=SimpleNamespace(server_id="fs", tool_name="send_message"),
        tool_policy=send_tool,
        arguments={"url": "https://hooks.example/", "body": canary},
        authorization=Authorization.AUTHORIZED,
        manifest=manifest,
    )
    assert context.secret_detector_match
    assert context.payload_evidence == PayloadEvidence.SECRET_DETECTED
    result = _decision(context)
    assert result.verdict == PolicyOutcome.BLOCK
    assert "P-002" in result.matched_policy_ids

    confidential_session = _session()
    confidential_session.resources.append(ReadResource(
        resource_id="C:/repo/internal/design.txt",
        sensitivity=Sensitivity.CONFIDENTIAL,
        request_id="read-1",
        content_hash=None,
        event_id="read-1",
    ))
    referenced = build_security_context(
        request_id="outgoing-reference",
        session_id=confidential_session.session_id,
        session=confidential_session,
        discovered=SimpleNamespace(server_id="fs", tool_name="send_message"),
        tool_policy=send_tool,
        arguments={"url": "https://paste.example/", "body": "C:/repo/internal/design.txt"},
        authorization=Authorization.AUTHORIZED,
        manifest=manifest,
    )
    assert referenced.payload_evidence == PayloadEvidence.RESOURCE_REFERENCED
    assert referenced.effective_sensitivity == Sensitivity.CONFIDENTIAL
    assert "P-003" in _decision(referenced).matched_policy_ids


def test_successful_reads_update_confidentiality_and_integrity_independently(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    secret_dir = root / "secrets"
    secret_dir.mkdir(parents=True)
    secret_file = secret_dir / "local.txt"
    secret_file.write_text("sensitive local contents", encoding="utf-8")
    manifest = _manifest(
        root,
        sensitivity_rules=[{"glob": f"{root.as_posix()}/secrets/**", "level": Sensitivity.SECRET}],
    )
    session = _session()
    read_tool = ToolManifest(
        operation_type=OperationType.READ,
        impact_scope=ImpactScope.PROJECT,
        resource_args=[ResourceArgument(pointer="/path", kind=ResourceKind.PATH)],
        auto_allow=True,
    )
    context = build_security_context(
        request_id="read-secret",
        session_id=session.session_id,
        session=session,
        discovered=SimpleNamespace(server_id="fs", tool_name="read_file"),
        tool_policy=read_tool,
        arguments={"path": str(secret_file)},
        authorization=Authorization.AUTHORIZED,
        manifest=manifest,
    )
    assert context.effective_sensitivity == Sensitivity.SECRET
    assert _decision(context).verdict == PolicyOutcome.ALLOW
    GatewayRuntime._update_session_ledger(
        session,
        context,
        read_tool,
        "read-secret",
        CallToolResult(content=[TextContent(type="text", text="sensitive local contents")]),
    )
    assert session.confidentiality == Sensitivity.SECRET
    assert session.integrity == Integrity.TRUSTED
    assert session.resources[0].content_hash is not None

    untrusted_read = ToolManifest(
        operation_type=OperationType.READ,
        impact_scope=ImpactScope.EXTERNAL,
        auto_allow=True,
        returns_untrusted_content=True,
    )
    untrusted_context = build_security_context(
        request_id="fetch-untrusted",
        session_id=session.session_id,
        session=session,
        discovered=SimpleNamespace(server_id="web", tool_name="fetch_url"),
        tool_policy=untrusted_read,
        arguments={},
        authorization=Authorization.AUTHORIZED,
        manifest=manifest,
    )
    GatewayRuntime._update_session_ledger(
        session,
        untrusted_context,
        untrusted_read,
        "fetch-untrusted",
        CallToolResult(content=[TextContent(type="text", text="untrusted remote response")]),
    )
    assert session.integrity == Integrity.UNTRUSTED
    assert session.confidentiality == Sensitivity.SECRET


def test_application_sessions_are_isolated_and_bound_to_authenticated_client() -> None:
    async def exercise() -> None:
        from app.mcp_server import create_mcp_server

        runtime = GatewayRuntime(create_mcp_server())
        runtime.manifest = _manifest()
        principal = bind_client_principal("client-token-one-with-enough-entropy")
        try:
            first = await runtime.create_session()
            second = await runtime.create_session()
        finally:
            reset_client_principal(principal)

        first_state = runtime.sessions[first["session_id"]]
        second_state = runtime.sessions[second["session_id"]]
        assert first_state is not second_state
        first_state.integrity = Integrity.UNTRUSTED
        first_state.confidentiality = Sensitivity.SECRET
        first_state.resources.append(ReadResource(
            resource_id="C:/private/item.txt",
            sensitivity=Sensitivity.SECRET,
            request_id="read-first-only",
            content_hash=None,
            event_id="read-first-only",
        ))
        assert second_state.integrity == Integrity.TRUSTED
        assert second_state.confidentiality == Sensitivity.PUBLIC
        assert second_state.resources == []

        other = bind_client_principal("a-different-client-token-with-entropy")
        try:
            assert await runtime._get_session(first["session_id"]) is None
        finally:
            reset_client_principal(other)

    asyncio.run(exercise())


def test_jcs_canonicalization_and_fingerprint_are_stable() -> None:
    assert canonicalize({"b": 1, "a": "x"}) == b'{"a":"x","b":1}'
    assert canonicalize({"n": 1e-6}) == b'{"n":0.000001}'
    assert canonicalize({"n": 1e21}) == b'{"n":1e+21}'
    assert canonicalize({"numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 1e-27]}) == (
        b'{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}'
    )
    assert canonicalize({"n": -0.0}) == b'{"n":0}'
    assert canonicalize({"n": 5e-324}) == b'{"n":5e-324}'
    assert canonicalize({"n": 1.7976931348623157e308}) == b'{"n":1.7976931348623157e+308}'
    assert canonicalize({"n": 9_007_199_254_740_992}) == b'{"n":9007199254740992}'
    assert fingerprint({"a": 1, "b": 2}) == fingerprint({"b": 2, "a": 1})
    unicode_keys = {
        "\u20ac": "Euro Sign",
        "\r": "Carriage Return",
        "\ufb33": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\U0001f600": "Emoji: Grinning Face",
        "\u0080": "Control",
        "\u00f6": "Latin Small Letter O With Diaeresis",
    }
    assert canonicalize(unicode_keys) == (
        b'{"\\r":"Carriage Return","1":"One","\xc2\x80":"Control",'
        b'"\xc3\xb6":"Latin Small Letter O With Diaeresis",'
        b'"\xe2\x82\xac":"Euro Sign","\xf0\x9f\x98\x80":"Emoji: Grinning Face",'
        b'"\xef\xac\xb3":"Hebrew Letter Dalet With Dagesh"}'
    )
    with pytest.raises(ValueError):
        canonicalize({"n": float("nan")})
    with pytest.raises(ValueError):
        canonicalize({"n": 9_007_199_254_740_993})
