from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

UNTRUSTED = "UNTRUSTED"
SENSITIVE = "SENSITIVE"
OUTBOUND = "OUTBOUND"

_secret = re.compile(r"(?:sk-[A-Za-z0-9_-]{8,}|api[_-]?key|password|token|secret)", re.I)
_personal = re.compile(r"\b(?:\d{3}[- ]?\d{2}[- ]?\d{4}|[\w.+-]+@[\w.-]+\.[A-Za-z]{2,})\b")
_injection = re.compile(r"(?:ignore (?:all )?(?:previous|prior)|system prompt|exfiltrate|send .* to|reveal .* secret)", re.I)
_outbound = re.compile(r"(?:https?://|webhook|recipient|channel|email|slack)", re.I)


@dataclass(frozen=True)
class TaintResult:
    labels: set[str]
    findings: list[str]


def inspect_arguments(arguments: dict[str, Any], inherited: set[str] | None = None) -> TaintResult:
    text = json.dumps(arguments, ensure_ascii=False)
    labels = set(inherited or set())
    findings: list[str] = []
    if _secret.search(text) or _personal.search(text):
        labels.add(SENSITIVE)
        findings.append("arguments contain secret-like or personally identifying content")
    if _injection.search(text):
        labels.add(UNTRUSTED)
        findings.append("arguments include instruction-like untrusted content")
    if _outbound.search(text):
        labels.add(OUTBOUND)
        findings.append("arguments name an external destination")
    return TaintResult(labels=labels, findings=findings)
