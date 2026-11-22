from __future__ import annotations

from dataclasses import dataclass

from .models import Verdict
from .taint_engine import OUTBOUND, SENSITIVE, UNTRUSTED


@dataclass(frozen=True)
class PolicyResult:
    verdict: Verdict
    rule: str
    explanation: str


_egress_tools = {"slack.postMessage", "email.send", "http.request", "webhook.send", "github.createIssue"}
_write_tools = {"fs.writeFile", "github.createIssue", "github.push"}


def evaluate(tool: str, labels: set[str]) -> PolicyResult:
    if {UNTRUSTED, SENSITIVE, OUTBOUND}.issubset(labels):
        return PolicyResult(Verdict.block, "P-101", "Lethal trifecta: untrusted instructions would move sensitive data to an external destination.")
    if SENSITIVE in labels and (OUTBOUND in labels or tool in _egress_tools):
        return PolicyResult(Verdict.review, "P-072", "Sensitive data is about to cross a trust boundary; explicit human approval is required.")
    if UNTRUSTED in labels and tool in _write_tools:
        return PolicyResult(Verdict.review, "P-043", "Untrusted content is attempting a state-changing tool call; verify intent before execution.")
    if tool in _egress_tools:
        return PolicyResult(Verdict.review, "P-021", "Outbound side effects require a recorded approval in this local policy.")
    return PolicyResult(Verdict.allow, "P-001", "No policy violation detected. The request can continue through the gateway.")
