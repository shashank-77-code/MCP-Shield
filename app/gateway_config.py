from __future__ import annotations

import json
import ipaddress
import re
from enum import Enum
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OperationType(str, Enum):
    READ = "READ"
    WRITE = "WRITE"
    DELETE = "DELETE"
    EXECUTE = "EXECUTE"
    EXTERNAL_SEND = "EXTERNAL_SEND"
    PERMISSION_MODIFY = "PERMISSION_MODIFY"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"


class ImpactScope(str, Enum):
    LOCAL = "LOCAL"
    PROJECT = "PROJECT"
    ORGANISATION = "ORGANISATION"
    EXTERNAL = "EXTERNAL"


class Integrity(str, Enum):
    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"
    UNKNOWN = "UNKNOWN"


class Sensitivity(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"


class PayloadEvidence(str, Enum):
    CLEAN = "CLEAN"
    SECRET_DETECTED = "SECRET_DETECTED"
    RESOURCE_REFERENCED = "RESOURCE_REFERENCED"
    INDETERMINATE = "INDETERMINATE"


class DestinationTrust(str, Enum):
    APPROVED = "APPROVED"
    RESTRICTED = "RESTRICTED"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Authorization(str, Enum):
    AUTHORIZED = "AUTHORIZED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    DENIED = "DENIED"
    NOT_CONFIGURED = "NOT_CONFIGURED"


class ResourceKind(str, Enum):
    PATH = "PATH"
    REPO = "REPO"
    URL = "URL"


def canonicalize_destination(value: str) -> str:
    """Canonicalize an HTTP(S) destination without resolving DNS or contacting it."""
    try:
        parts = urlsplit(value)
        scheme = parts.scheme.lower()
        if scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError
        if parts.username is not None or parts.password is not None or "@" in parts.netloc:
            raise ValueError
        if parts.fragment:
            raise ValueError
        host = parts.hostname
        try:
            address = ipaddress.ip_address(host)
            normalized_host = f"[{address.compressed}]" if address.version == 6 else address.compressed
        except ValueError:
            host = host.rstrip(".")
            if not host:
                raise ValueError
            normalized_host = host.encode("idna").decode("ascii").lower()
            if any(not label or len(label) > 63 for label in normalized_host.split(".")):
                raise ValueError
        port = parts.port
        if port is not None and not 1 <= port <= 65_535:
            raise ValueError
        default_port = 80 if scheme == "http" else 443
        authority = normalized_host if port is None or port == default_port else f"{normalized_host}:{port}"
        path = parts.path or "/"
        return urlunsplit((scheme, authority, path, parts.query, ""))
    except (UnicodeError, ValueError, TypeError) as exc:
        raise ValueError("destination must be a valid HTTP(S) URL without userinfo or fragment") from exc


class ResourceArgument(StrictModel):
    pointer: str = Field(min_length=2, max_length=256)
    kind: ResourceKind

    @field_validator("pointer")
    @classmethod
    def valid_json_pointer(cls, value: str) -> str:
        if not value.startswith("/") or re.search(r"~(?![01])", value):
            raise ValueError("resource argument must be a valid JSON pointer")
        return value


class ToolManifest(StrictModel):
    operation_type: OperationType
    impact_scope: ImpactScope
    resource_args: list[ResourceArgument] = Field(default_factory=list)
    destination_arg: str | None = None
    payload_args: list[str] = Field(default_factory=list)
    auto_allow: bool = False
    returns_untrusted_content: bool = False
    redirects_blocked: bool = False
    description: str = "Operator-configured MCP capability"

    @field_validator("destination_arg")
    @classmethod
    def valid_destination_pointer(cls, value: str | None) -> str | None:
        if value is not None and (not value.startswith("/") or re.search(r"~(?![01])", value)):
            raise ValueError("destination_arg must be a valid JSON pointer")
        return value

    @field_validator("payload_args")
    @classmethod
    def valid_payload_pointers(cls, values: list[str]) -> list[str]:
        if any(not value.startswith("/") or re.search(r"~(?![01])", value) for value in values):
            raise ValueError("payload_args entries must be valid JSON pointers")
        return values


class ServerManifest(StrictModel):
    transport: Literal["stdio"]
    command: list[str] = Field(min_length=1)
    cwd: Path | None = None
    env: dict[str, str] = Field(default_factory=dict)
    tools: dict[str, ToolManifest]

    @field_validator("command")
    @classmethod
    def command_is_present(cls, value: list[str]) -> list[str]:
        if not value or any(not token.strip() for token in value):
            raise ValueError("stdio command must contain non-empty strings")
        return value

    @field_validator("cwd")
    @classmethod
    def cwd_is_absolute(cls, value: Path | None) -> Path | None:
        if value is not None and not value.is_absolute():
            raise ValueError("stdio cwd must be an absolute path")
        return value

    @field_validator("env")
    @classmethod
    def no_gateway_credentials(cls, value: dict[str, str]) -> dict[str, str]:
        forbidden = {"SHIELD_CLIENT_TOKEN", "SHIELD_APPROVER_TOKENS"}
        if any(key.upper() in forbidden for key in value):
            raise ValueError("gateway credentials cannot be forwarded to downstream processes")
        return value


class AuthorizationMatch(StrictModel):
    server: str
    tool: str


class AuthorizationRule(StrictModel):
    match: AuthorizationMatch
    result: Authorization


class ApprovalConfig(StrictModel):
    timeout_s: int = Field(default=300, ge=1, le=86_400)
    grant_ttl_s: int = Field(default=60, ge=1, le=3_600)


class SensitivityRule(StrictModel):
    glob: str = Field(min_length=1, max_length=1024)
    level: Sensitivity


class SecretDetector(StrictModel):
    name: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z][A-Za-z0-9_-]*$")
    pattern: str = Field(min_length=1, max_length=1024)

    @field_validator("pattern")
    @classmethod
    def regex_compiles(cls, value: str) -> str:
        try:
            re.compile(value)
        except re.error as exc:
            raise ValueError("secret detector pattern is invalid") from exc
        return value


class Destinations(StrictModel):
    approved: list[str] = Field(default_factory=list)
    restricted: list[str] = Field(default_factory=list)

    @field_validator("approved", "restricted")
    @classmethod
    def canonical_urls(cls, values: list[str]) -> list[str]:
        return [canonicalize_destination(value) for value in values]


class GatewayManifest(StrictModel):
    policy_version: str = Field(min_length=1, max_length=80)
    allowed_roots: list[Path] = Field(default_factory=list)
    allowed_repos: list[str] = Field(default_factory=list)
    approval: ApprovalConfig = Field(default_factory=ApprovalConfig)
    initial_session_integrity: Integrity = Integrity.TRUSTED
    block_external_send_when_session_secret: bool = False
    default_sensitivity: Sensitivity = Sensitivity.INTERNAL
    destinations: Destinations = Field(default_factory=Destinations)
    sensitivity_rules: list[SensitivityRule] = Field(default_factory=list)
    secret_detectors: list[SecretDetector] = Field(default_factory=list)
    servers: dict[str, ServerManifest] = Field(default_factory=dict)
    authorization: list[AuthorizationRule] = Field(default_factory=list)
    allowed_origins: list[str] = Field(default_factory=list)
    request_size_limit_bytes: int = Field(default=1_048_576, ge=1_024, le=4_194_304)
    session_ttl_s: int = Field(default=28_800, ge=60, le=604_800)
    audit_limit: int = Field(default=1_000, ge=50, le=100_000)

    @field_validator("allowed_roots")
    @classmethod
    def roots_absolute(cls, value: list[Path]) -> list[Path]:
        if any(not root.is_absolute() for root in value):
            raise ValueError("allowed_roots must contain absolute paths")
        return value

    @field_validator("allowed_repos")
    @classmethod
    def repos_normalized(cls, values: list[str]) -> list[str]:
        for repo in values:
            if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
                raise ValueError("allowed_repos entries must use owner/repository form")
        return values

    @field_validator("allowed_origins")
    @classmethod
    def origins_are_explicit(cls, values: list[str]) -> list[str]:
        if "*" in values:
            raise ValueError("wildcard CORS origins are not permitted")
        return values

    @model_validator(mode="after")
    def validate_names_and_rules(self) -> GatewayManifest:
        names: set[str] = set()
        for server_id, server in self.servers.items():
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,62}", server_id) or "__" in server_id:
                raise ValueError("server IDs must be alphanumeric with single underscores")
            for tool_name in server.tools:
                if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,62}", tool_name) or "__" in tool_name:
                    raise ValueError("tool names must be alphanumeric with single underscores")
                exposed = f"{server_id}__{tool_name}"
                if exposed in names or exposed in {"shield_status", "shield_session_open", "shield_session_close"}:
                    raise ValueError("namespaced tool name collides with another exposed tool")
                names.add(exposed)

        grouped: dict[tuple[str, str], set[Authorization]] = {}
        for rule in self.authorization:
            key = (rule.match.server, rule.match.tool)
            grouped.setdefault(key, set()).add(rule.result)
            if key not in {(server_id, tool_name) for server_id, server in self.servers.items() for tool_name in server.tools}:
                raise ValueError("authorization rule must match a manifest tool")
        for results in grouped.values():
            non_deny = results - {Authorization.DENIED}
            if len(non_deny) > 1:
                raise ValueError("conflicting non-deny authorization rules are not allowed")

        for server_id, server in self.servers.items():
            for tool_name, tool in server.tools.items():
                if tool.operation_type == OperationType.EXTERNAL_SEND and not tool.destination_arg:
                    raise ValueError(f"{server_id}.{tool_name} requires destination_arg")
        return self


def load_manifest(path: Path) -> GatewayManifest:
    """Load a bounded YAML manifest and fail closed on every parse/validation error."""
    try:
        if path.stat().st_size > 1_048_576:
            raise ValueError("manifest exceeds the 1 MiB configuration limit")
        with path.open("r", encoding="utf-8") as stream:
            raw: Any = json.load(stream)
        if not isinstance(raw, dict):
            raise ValueError("manifest root must be a YAML mapping")
        return GatewayManifest.model_validate(raw)
    except Exception as exc:
        # Callers intentionally receive only a safe configuration error, not raw YAML values.
        if isinstance(exc, ValueError) and str(exc).startswith("manifest exceeds"):
            raise
        raise ValueError(f"invalid MCP Shield manifest at {path.name}") from exc


def load_approver_tokens(raw: str | None) -> dict[str, str]:
    """Parse an optional JSON map of operator-chosen approver IDs to tokens."""
    if not raw:
        return {}
    try:
        value = json.loads(raw)
        if not isinstance(value, dict) or not value:
            raise ValueError
        if any(
            not isinstance(k, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", k)
            or not isinstance(v, str)
            or len(v) < 24
            for k, v in value.items()
        ) or len(set(value.values())) != len(value):
            raise ValueError
        return value
    except Exception as exc:
        raise ValueError("SHIELD_APPROVER_TOKENS must be a JSON object of approver IDs to tokens") from exc
