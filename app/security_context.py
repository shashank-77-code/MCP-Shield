from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, model_validator

from .gateway_config import (
    Authorization,
    DestinationTrust,
    GatewayManifest,
    ImpactScope,
    Integrity,
    OperationType,
    PayloadEvidence,
    ResourceKind,
    Sensitivity,
    ToolManifest,
    canonicalize_destination,
)
from .jcs import fingerprint


class ResourceTarget(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: ResourceKind
    value: str
    boundary_satisfied: bool | None
    sensitivity: Sensitivity


class SecurityContext(BaseModel):
    """Validated, normalized facts consumed by the pure policy engine."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str
    session_id: str | None
    trace_id: str | None
    server_id: str | None
    tool_name: str | None
    arguments_fingerprint: str
    operation_type: OperationType | None
    impact_scope: ImpactScope | None
    authorization: Authorization
    resource_targets: tuple[ResourceTarget, ...]
    effective_sensitivity: Sensitivity | None
    session_integrity: Integrity
    session_confidentiality: Sensitivity | None
    payload_evidence: PayloadEvidence
    destination_trust: DestinationTrust
    missing_fields: tuple[str, ...]
    policy_version: str | None
    manifest_tool_exists: bool
    auto_allow: bool
    resource_boundaries_satisfied: bool
    required_metadata_complete: bool
    destination_redirect_safe: bool
    session_secret_present: bool
    secret_detector_match: bool

    @model_validator(mode="after")
    def normalized_sensitivity_and_identity(self) -> SecurityContext:
        order = {
            Sensitivity.PUBLIC: 0,
            Sensitivity.INTERNAL: 1,
            Sensitivity.CONFIDENTIAL: 2,
            Sensitivity.SECRET: 3,
        }
        if (
            self.session_confidentiality is not None
            and self.effective_sensitivity is not None
            and order[self.effective_sensitivity] < order[self.session_confidentiality]
        ):
            raise ValueError("effective sensitivity cannot be below session confidentiality")
        if self.manifest_tool_exists and (not self.server_id or not self.tool_name):
            raise ValueError("mapped tools require server and tool identifiers")
        return self


def pointer_get(value: Any, pointer: str) -> tuple[bool, Any]:
    if pointer == "":
        return True, value
    if not pointer.startswith("/"):
        return False, None
    current = value
    for raw_part in pointer[1:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return False, None
    return True, current


def normalize_repo(value: str) -> str | None:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        return None
    owner, name = value.split("/", 1)
    return f"{owner.casefold()}/{name.casefold()}"


def _path_sensitivity(value: str, manifest: GatewayManifest) -> Sensitivity:
    candidate = Path(value).as_posix().casefold()
    levels = {level: index for index, level in enumerate(Sensitivity)}
    matching = [
        rule.level for rule in manifest.sensitivity_rules
        if fnmatch.fnmatchcase(candidate, rule.glob.replace("\\", "/").casefold())
    ]
    return max(matching, key=levels.__getitem__) if matching else manifest.default_sensitivity


def _tree_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [text for child in value.values() for text in _tree_strings(child)]
    if isinstance(value, list):
        return [text for child in value for text in _tree_strings(child)]
    return []


def _content_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def build_security_context(
    *,
    request_id: str,
    session_id: str | None,
    session: Any | None,
    discovered: Any | None,
    tool_policy: ToolManifest | None,
    arguments: dict[str, Any],
    authorization: Authorization,
    manifest: GatewayManifest,
) -> SecurityContext:
    """Resolve operator metadata and current session facts into a fail-closed context.

    This builder may inspect the filesystem to resolve PATH values. The policy engine
    itself receives only these normalized facts and performs no I/O.
    """
    missing: list[str] = []
    operation = tool_policy.operation_type if tool_policy else None
    impact = tool_policy.impact_scope if tool_policy else None
    if session is None:
        missing.append("application session is missing, expired, or not owned by this client")
    if discovered is None or tool_policy is None:
        missing.append("tool is not mapped by the validated manifest")

    try:
        arguments_fingerprint = fingerprint(arguments)
    except (TypeError, ValueError, OverflowError):
        arguments_fingerprint = ""
        missing.append("arguments cannot be canonicalized")

    targets: list[ResourceTarget] = []
    boundary_ok = True
    referenced_values: set[str] = set()
    sensitivity_levels = {level: index for index, level in enumerate(Sensitivity)}
    current_sensitivity: list[Sensitivity] = []

    if tool_policy is not None:
        for mapping in tool_policy.resource_args:
            present, raw_value = pointer_get(arguments, mapping.pointer)
            if not present:
                missing.append(f"required resource argument {mapping.pointer} is missing")
                continue
            if not isinstance(raw_value, str) or not raw_value:
                missing.append(f"resource argument {mapping.pointer} is malformed")
                continue

            if mapping.kind == ResourceKind.PATH:
                try:
                    resolved = Path(raw_value).expanduser().resolve(strict=False)
                    roots = [root.expanduser().resolve(strict=False) for root in manifest.allowed_roots]
                    inside = bool(roots) and any(resolved.is_relative_to(root) for root in roots)
                    normalized = str(resolved)
                    sensitivity = _path_sensitivity(normalized, manifest)
                except (OSError, RuntimeError, ValueError):
                    inside = False
                    normalized = ""
                    sensitivity = manifest.default_sensitivity
                    missing.append(f"resource argument {mapping.pointer} cannot be resolved")
                boundary_ok = boundary_ok and inside
            elif mapping.kind == ResourceKind.REPO:
                normalized_repo = normalize_repo(raw_value)
                if normalized_repo is None:
                    missing.append(f"resource argument {mapping.pointer} is not a valid owner/repository identifier")
                    continue
                normalized = normalized_repo
                inside = normalized_repo in {normalize_repo(repo) for repo in manifest.allowed_repos}
                sensitivity = _path_sensitivity(normalized, manifest)
                boundary_ok = boundary_ok and inside
            else:
                try:
                    normalized = canonicalize_destination(raw_value)
                except ValueError:
                    missing.append(f"resource argument {mapping.pointer} is not a valid HTTP(S) URL")
                    continue
                allowed = normalized in manifest.destinations.approved
                redirects_safe = bool(tool_policy.redirects_blocked)
                inside = allowed and redirects_safe
                sensitivity = _path_sensitivity(normalized, manifest)
                # URL reads are not allowed to become SSRF probes through a generic fetch tool.
                if operation != OperationType.EXTERNAL_SEND and not inside:
                    missing.append("URL resource is not pinned to an approved redirect-safe destination")

            target = ResourceTarget(
                kind=mapping.kind,
                value=normalized,
                boundary_satisfied=inside,
                sensitivity=sensitivity,
            )
            targets.append(target)
            current_sensitivity.append(sensitivity)
            referenced_values.add(normalized)

    destination_trust = DestinationTrust.NOT_APPLICABLE
    destination_redirect_safe = True
    if operation == OperationType.EXTERNAL_SEND and tool_policy is not None:
        present, destination_value = pointer_get(arguments, tool_policy.destination_arg or "")
        if not present or not isinstance(destination_value, str) or not destination_value:
            missing.append("external-send destination is missing or malformed")
            destination_trust = DestinationTrust.UNKNOWN
            destination_redirect_safe = False
        else:
            try:
                destination = canonicalize_destination(destination_value)
            except ValueError:
                missing.append("external-send destination is not a valid HTTP(S) URL")
                destination_trust = DestinationTrust.UNKNOWN
                destination_redirect_safe = False
            else:
                if destination in manifest.destinations.restricted:
                    destination_trust = DestinationTrust.RESTRICTED
                elif destination in manifest.destinations.approved:
                    destination_trust = DestinationTrust.APPROVED
                else:
                    destination_trust = DestinationTrust.UNKNOWN
                destination_redirect_safe = bool(tool_policy.redirects_blocked)
                if not destination_redirect_safe:
                    missing.append("downstream redirect behavior is not constrained by the operator manifest")

    payload_evidence = PayloadEvidence.CLEAN
    secret_detected = False
    if operation == OperationType.EXTERNAL_SEND and tool_policy is not None:
        payload_values: list[Any] = []
        payload_strings: list[str] = []
        for pointer in tool_policy.payload_args:
            present, value = pointer_get(arguments, pointer)
            if not present:
                missing.append(f"required payload argument {pointer} is missing")
                continue
            payload_values.append(value)
            payload_strings.extend(_tree_strings(value))
        payload_text = json.dumps(payload_values, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        for detector in manifest.secret_detectors:
            try:
                if re.search(detector.pattern, payload_text):
                    secret_detected = True
                    break
            except re.error:
                missing.append(f"secret detector {detector.name} could not be evaluated")

        ledger = list(getattr(session, "resources", [])) if session is not None else []
        known_values = set(referenced_values)
        known_hashes: set[str] = set()
        for resource in ledger:
            resource_id = resource.get("resource_id") if isinstance(resource, dict) else getattr(resource, "resource_id", None)
            content_hash = resource.get("content_hash") if isinstance(resource, dict) else getattr(resource, "content_hash", None)
            if resource_id:
                known_values.add(str(resource_id))
            if content_hash:
                known_hashes.add(str(content_hash))
        referenced = any(
            text in known_values or _content_digest(text) in known_hashes
            for text in payload_strings
        )
        if secret_detected:
            payload_evidence = PayloadEvidence.SECRET_DETECTED
        elif referenced:
            payload_evidence = PayloadEvidence.RESOURCE_REFERENCED
        elif any(
            (resource.get("sensitivity") if isinstance(resource, dict) else getattr(resource, "sensitivity", None))
            in {Sensitivity.INTERNAL, Sensitivity.CONFIDENTIAL, Sensitivity.SECRET, "INTERNAL", "CONFIDENTIAL", "SECRET"}
            for resource in ledger
        ):
            payload_evidence = PayloadEvidence.INDETERMINATE

    session_integrity = getattr(session, "integrity", Integrity.UNKNOWN) if session is not None else Integrity.UNKNOWN
    if not isinstance(session_integrity, Integrity):
        session_integrity = Integrity(session_integrity)
    session_confidentiality = getattr(session, "confidentiality", None) if session is not None else None
    if session_confidentiality is not None and not isinstance(session_confidentiality, Sensitivity):
        session_confidentiality = Sensitivity(session_confidentiality)

    ledger_sensitivities: list[Sensitivity] = []
    for resource in (getattr(session, "resources", []) if session is not None else []):
        level = resource.get("sensitivity") if isinstance(resource, dict) else getattr(resource, "sensitivity", None)
        try:
            ledger_sensitivities.append(level if isinstance(level, Sensitivity) else Sensitivity(level))
        except (TypeError, ValueError):
            missing.append("session ledger contains invalid sensitivity metadata")
    if ledger_sensitivities:
        if session_confidentiality is not None:
            ledger_sensitivities.append(session_confidentiality)
        session_confidentiality = max(ledger_sensitivities, key=sensitivity_levels.__getitem__)

    if session_confidentiality is not None:
        current_sensitivity.append(session_confidentiality)
    effective_sensitivity = max(current_sensitivity, key=sensitivity_levels.__getitem__) if current_sensitivity else session_confidentiality
    session_secret = any(
        (resource.get("sensitivity") if isinstance(resource, dict) else getattr(resource, "sensitivity", None))
        in {Sensitivity.SECRET, "SECRET"}
        for resource in (getattr(session, "resources", []) if session is not None else [])
    )
    metadata_complete = not missing and operation is not None and impact is not None and bool(manifest.policy_version)

    return SecurityContext(
        request_id=request_id,
        session_id=session_id,
        trace_id=request_id,
        server_id=discovered.server_id if discovered is not None else None,
        tool_name=discovered.tool_name if discovered is not None else None,
        arguments_fingerprint=arguments_fingerprint,
        operation_type=operation,
        impact_scope=impact,
        authorization=authorization,
        resource_targets=tuple(targets),
        effective_sensitivity=effective_sensitivity,
        session_integrity=session_integrity,
        session_confidentiality=session_confidentiality,
        payload_evidence=payload_evidence,
        destination_trust=destination_trust,
        missing_fields=tuple(missing),
        policy_version=manifest.policy_version or None,
        manifest_tool_exists=discovered is not None and tool_policy is not None,
        auto_allow=bool(tool_policy and tool_policy.auto_allow),
        resource_boundaries_satisfied=boundary_ok,
        required_metadata_complete=metadata_complete,
        destination_redirect_safe=destination_redirect_safe,
        session_secret_present=session_secret,
        secret_detector_match=secret_detected,
    )


def content_hash_from_result(result: Any) -> str | None:
    """Hash returned textual content only; never retain it in the session ledger."""
    values = [getattr(block, "text", None) for block in getattr(result, "content", [])]
    text = "".join(value for value in values if isinstance(value, str))
    return hashlib.sha256(text.encode("utf-8")).hexdigest() if text else None
