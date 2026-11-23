from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field

from .gateway_config import (
    Authorization,
    DestinationTrust,
    ImpactScope,
    Integrity,
    OperationType,
    PayloadEvidence,
    Sensitivity,
)
from .models import Verdict
from .security_context import SecurityContext
from .taint_engine import OUTBOUND, SENSITIVE, UNTRUSTED


@dataclass(frozen=True)
class PolicyResult:
    """Legacy simulation decision. It is not used to authorize MCP forwarding."""

    verdict: Verdict
    rule: str
    explanation: str


class PolicyOutcome(str):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    block_external_send_when_session_secret: bool


class PolicyReason(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    message: str


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    verdict: str
    matched_policy_ids: tuple[str, ...] = ()
    approvable_policy_ids: tuple[str, ...] = ()
    reasons: tuple[PolicyReason, ...] = ()


_egress_tools = {
    "slack.postMessage", "slack.send_message", "email.send", "http.request",
    "webhook.send", "github.createIssue",
}
_write_tools = {"fs.writeFile", "github.createIssue", "github.push"}


def _legacy_evaluate(tool: str, labels: set[str]) -> PolicyResult:
    """Preserve the original demonstration endpoint and its existing tests."""
    if {UNTRUSTED, SENSITIVE, OUTBOUND}.issubset(labels):
        return PolicyResult(Verdict.block, "P-101", "Lethal trifecta: untrusted instructions would move sensitive data to an external destination.")
    if SENSITIVE in labels and (OUTBOUND in labels or tool in _egress_tools):
        return PolicyResult(Verdict.review, "P-072", "Sensitive data is about to cross a trust boundary; explicit human approval is required.")
    if UNTRUSTED in labels and tool in _write_tools:
        return PolicyResult(Verdict.review, "P-043", "Untrusted content is attempting a state-changing tool call; verify intent before execution.")
    if tool in _egress_tools:
        return PolicyResult(Verdict.review, "P-021", "Outbound side effects require a recorded approval in this local policy.")
    return PolicyResult(Verdict.allow, "P-001", "No policy violation detected. The request can continue through the gateway.")


def _severity(level: Sensitivity | None) -> int:
    order = {
        Sensitivity.PUBLIC: 0,
        Sensitivity.INTERNAL: 1,
        Sensitivity.CONFIDENTIAL: 2,
        Sensitivity.SECRET: 3,
    }
    return order.get(level, -1)


def _evaluate_context(context: SecurityContext, config: PolicyConfig) -> PolicyDecision:
    matched: set[str] = set()
    reasons: list[PolicyReason] = []
    approvable: set[str] = set()
    block = False
    review = False

    def add(policy_id: str, message: str, outcome: str) -> None:
        nonlocal block, review
        matched.add(policy_id)
        reasons.append(PolicyReason(code=policy_id, message=message))
        if outcome == PolicyOutcome.BLOCK:
            block = True
        elif outcome == PolicyOutcome.REVIEW:
            review = True

    if not context.manifest_tool_exists:
        add("P-011", "Tool is unknown or is not mapped by the validated manifest.", PolicyOutcome.BLOCK)

    if any(target.boundary_satisfied is False for target in context.resource_targets):
        add("P-001", "A path or repository resource is outside the configured boundary.", PolicyOutcome.BLOCK)
    if context.operation_type == OperationType.CREDENTIAL_ACCESS and context.authorization != Authorization.AUTHORIZED:
        add("P-001", "Credential access is blocked unless static authorization is AUTHORIZED.", PolicyOutcome.BLOCK)

    external_send = context.operation_type == OperationType.EXTERNAL_SEND
    if external_send and context.secret_detector_match:
        add("P-002", "A configured secret detector matched the outgoing payload.", PolicyOutcome.BLOCK)

    destination_uncertain = context.destination_trust in {DestinationTrust.UNKNOWN, DestinationTrust.RESTRICTED}
    referenced_confidential = (
        context.payload_evidence == PayloadEvidence.RESOURCE_REFERENCED
        and _severity(context.effective_sensitivity) >= _severity(Sensitivity.CONFIDENTIAL)
    )
    configured_session_secret_block = (
        config.block_external_send_when_session_secret and context.session_secret_present
    )
    p003 = external_send and (
        destination_uncertain and (referenced_confidential or context.secret_detector_match)
        or configured_session_secret_block
    )
    if p003:
        add("P-003", "Sensitive or secret-bearing data cannot be sent to a restricted or unknown destination.", PolicyOutcome.BLOCK)

    destructive = context.operation_type in {
        OperationType.DELETE,
        OperationType.EXECUTE,
        OperationType.PERMISSION_MODIFY,
    }
    if destructive and context.session_integrity == Integrity.UNTRUSTED:
        add("P-004", "Destructive operation is blocked in an UNTRUSTED session.", PolicyOutcome.BLOCK)

    if (
        context.impact_scope == ImpactScope.ORGANISATION
        and context.operation_type in {OperationType.DELETE, OperationType.PERMISSION_MODIFY}
        and context.authorization != Authorization.AUTHORIZED
    ):
        add("P-005", "Organisation-level destructive operation requires AUTHORIZED status.", PolicyOutcome.BLOCK)

    p006 = (
        destructive
        and context.impact_scope in {ImpactScope.LOCAL, ImpactScope.PROJECT, ImpactScope.ORGANISATION}
        and context.session_integrity == Integrity.TRUSTED
        and context.authorization == Authorization.AUTHORIZED
    )
    if p006:
        add("P-006", "Authorized destructive operation requires a human review.", PolicyOutcome.REVIEW)
        approvable.add("P-006")

    p007 = False
    if external_send and not (context.secret_detector_match or p003):
        sensitive_or_higher = _severity(context.effective_sensitivity) >= _severity(Sensitivity.CONFIDENTIAL)
        uncertain_payload = context.payload_evidence in {
            PayloadEvidence.RESOURCE_REFERENCED,
            PayloadEvidence.INDETERMINATE,
        }
        # A public resource reference alone is below the review threshold.
        p007 = (
            context.session_integrity == Integrity.UNTRUSTED
            or (sensitive_or_higher and (destination_uncertain or uncertain_payload))
        )
    if p007:
        add("P-007", "External send has uncertain destination or confidential payload provenance.", PolicyOutcome.REVIEW)
        approvable.add("P-007")

    if (
        context.missing_fields
        or not context.required_metadata_complete
        or context.operation_type is None
        or context.impact_scope is None
        or context.session_integrity == Integrity.UNKNOWN
        or context.session_confidentiality is None
        or context.effective_sensitivity is None
    ):
        add("P-008", "Required arguments or security-critical metadata are missing or invalid.", PolicyOutcome.BLOCK)

    if context.authorization in {Authorization.DENIED, Authorization.NOT_CONFIGURED}:
        add("P-009", f"Static authorization state is {context.authorization.value}.", PolicyOutcome.BLOCK)
    elif context.authorization == Authorization.APPROVAL_REQUIRED:
        if p007 or context.operation_type == OperationType.WRITE and context.session_integrity == Integrity.UNTRUSTED:
            add("P-009", "Static authorization requires human review for this policy-eligible operation.", PolicyOutcome.REVIEW)
            approvable.add("P-009")
        else:
            add("P-009", "Static authorization requires approval, but no policy permits review for this operation.", PolicyOutcome.BLOCK)

    p012 = context.operation_type == OperationType.WRITE and context.session_integrity == Integrity.UNTRUSTED
    if p012:
        add("P-012", "Write operation in an UNTRUSTED session requires human review.", PolicyOutcome.REVIEW)
        approvable.add("P-012")

    external_send_allow = True
    if external_send:
        external_send_allow = (
            context.destination_trust == DestinationTrust.APPROVED
            and context.payload_evidence == PayloadEvidence.CLEAN
            and context.session_integrity == Integrity.TRUSTED
            and _severity(context.effective_sensitivity) < _severity(Sensitivity.CONFIDENTIAL)
            and context.destination_redirect_safe
        )

    can_allow = (
        context.authorization == Authorization.AUTHORIZED
        and context.manifest_tool_exists
        and context.auto_allow
        and context.required_metadata_complete
        and not context.missing_fields
        and context.operation_type is not None
        and context.impact_scope is not None
        and context.resource_boundaries_satisfied
        and context.destination_redirect_safe
        and external_send_allow
        and not block
        and not review
    )
    if can_allow:
        add("P-010", "Every strict automatic-allow condition is satisfied.", PolicyOutcome.ALLOW)
        return PolicyDecision(
            verdict=PolicyOutcome.ALLOW,
            matched_policy_ids=tuple(sorted(matched)),
            approvable_policy_ids=tuple(sorted(approvable)),
            reasons=tuple(reasons),
        )

    if block:
        verdict = PolicyOutcome.BLOCK
    elif review:
        verdict = PolicyOutcome.REVIEW
    else:
        verdict = PolicyOutcome.BLOCK
        reasons.append(PolicyReason(code="NO_ALLOW_RULE", message="No explicit policy grants automatic forwarding."))

    return PolicyDecision(
        verdict=verdict,
        matched_policy_ids=tuple(sorted(matched)),
        approvable_policy_ids=tuple(sorted(approvable)),
        reasons=tuple(reasons),
    )


def evaluate(context: SecurityContext | str, config: PolicyConfig | set[str] | None = None) -> PolicyDecision | PolicyResult:
    """Evaluate a gateway context purely; retain the legacy demo call signature.

    The SecurityContext path does no I/O, randomness, or clock access. Exceptions
    on that path become a safe BLOCK. The string/set overload is only for the
    pre-existing dashboard simulation and is never called by MCP forwarding.
    """
    if isinstance(context, str):
        return _legacy_evaluate(context, config if isinstance(config, set) else set())
    try:
        if not isinstance(context, SecurityContext) or not isinstance(config, PolicyConfig):
            raise TypeError("validated security context and policy config are required")
        return _evaluate_context(context, config)
    except Exception:
        return PolicyDecision(
            verdict=PolicyOutcome.BLOCK,
            matched_policy_ids=("POLICY_ERROR",),
            reasons=(PolicyReason(code="POLICY_ERROR", message="Policy evaluation failed closed."),),
        )
