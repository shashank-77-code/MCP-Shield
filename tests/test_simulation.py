from collections.abc import Coroutine
from typing import Any

from app import main
from app.models import ToolCall, Verdict
from app.taint_engine import OUTBOUND, SENSITIVE, UNTRUSTED


def run_async(coroutine: Coroutine[Any, Any, Any]) -> Any:
    """Drive the in-memory async handlers without opening sandboxed sockets."""
    try:
        coroutine.send(None)
    except StopIteration as complete:
        return complete.value
    raise AssertionError("Expected the in-memory handler to complete without I/O")


def reset_store() -> None:
    run_async(main.store.reset())


def test_one_simulation_records_three_tool_calls_and_blocks_egress(monkeypatch) -> None:
    destination_calls: list[tuple[str, str]] = []

    async def record_only(destination: str, message: str) -> dict[str, object]:
        destination_calls.append((destination, message))
        return {"delivered": True, "destination": destination}

    monkeypatch.setattr(main, "call_mock_destination", record_only)
    reset_store()
    result = run_async(main.run_demo())

    assert [event.tool_name for event in result["events"]] == [
        "github.read_issue", "filesystem.read_sensitive", "slack.send_message"
    ]
    assert all(event.event_type == "tool_call" for event in result["events"])
    assert all(event.session_id == result["session_id"] for event in result["events"])
    assert all(event.run_id == result["run_id"] for event in result["events"])
    assert result["events"][0].decision == Verdict.allow
    assert UNTRUSTED in result["events"][0].taints
    assert result["events"][1].decision == Verdict.allow
    assert SENSITIVE in result["events"][1].taints
    assert {UNTRUSTED, SENSITIVE, OUTBOUND}.issubset(set(result["events"][2].taints))
    assert result["decision"]["verdict"] == "block"
    assert result["decision"]["rule"] == "P-101"
    assert "Lethal trifecta" in result["decision"]["explanation"]
    assert result["decision"]["destination_called"] is False
    assert destination_calls == []
    assert result["stats"]["audit_record_count"] == 3
    assert result["stats"]["tool_call_count"] == 3
    assert result["graph"]["metrics"]["tool_call_count"] == 3


def test_safe_request_is_allowed() -> None:
    reset_store()
    decision = run_async(main.inspect(ToolCall(
        tool="github.read_issue",
        arguments={"issue": 42, "visibility": "public"},
    )))

    assert decision.event.decision == Verdict.allow
    assert decision.event.session_id == main.store.session_id


def test_repeated_simulations_accumulate_counts_but_graph_shows_latest_run() -> None:
    reset_store()
    first = run_async(main.run_demo())
    second = run_async(main.run_demo())
    history = run_async(main.events())

    assert history["stats"]["audit_record_count"] == 6
    assert history["stats"]["tool_call_count"] == 6
    # Taint is session-scoped, so the second run starts with the first run's taint.
    assert history["stats"]["blocked_tool_call_count"] == 4
    assert history["stats"]["simulation_run_count"] == 2
    assert history["graph"]["scope"] == "latest_run"
    assert history["graph"]["run_id"] == second["run_id"]
    assert history["graph"]["run_id"] != first["run_id"]
    assert history["graph"]["metrics"]["tool_call_count"] == 3
    assert history["graph"]["metrics"]["unique_tool_count"] == 3
    assert history["graph"]["metrics"]["blocked_tool_call_count"] == 3
    assert history["graph"]["metrics"]["graph_node_count"] == 4
    assert history["graph"]["metrics"]["graph_edge_count"] == 3


def test_unique_tool_count_counts_names_not_repeated_call_nodes() -> None:
    reset_store()
    run_id, _ = main.store.begin_simulation()
    for _ in range(2):
        run_async(main.inspect(ToolCall(
            tool="github.read_issue",
            arguments={"issue": 42, "visibility": "public"},
            session_id=main.store.session_id,
            run_id=run_id,
        )))

    graph = main.session_graph()
    assert graph["metrics"]["tool_call_count"] == 2
    assert graph["metrics"]["unique_tool_count"] == 1
    assert graph["metrics"]["graph_node_count"] == 3
    assert graph["metrics"]["graph_edge_count"] == 2


def test_audit_count_reports_the_retained_sixty_record_window() -> None:
    reset_store()
    for _ in range(21):
        run_async(main.run_demo())

    stats = main.session_stats()
    assert stats["audit_record_count"] == 60
    assert stats["audit_record_limit"] == 60
    assert stats["tool_call_count"] == 60
    assert stats["simulation_run_count"] == 21
    assert main.session_graph()["metrics"]["tool_call_count"] == 3


def test_approval_outcome_is_audit_record_not_a_second_tool_call() -> None:
    reset_store()
    decision = run_async(main.inspect(ToolCall(
        tool="email.send",
        arguments={"to": "person@example.test", "body": "synthetic"},
    )))
    assert decision.approval_required is True

    outcome = run_async(main.store.resolve_approval(decision.approval_id, approved=True))
    snapshot = run_async(main.events())

    assert outcome is not None
    assert outcome.event_id != decision.event.event_id
    assert outcome.event_type == "approval_decision"
    assert snapshot["stats"]["audit_record_count"] == 2
    assert snapshot["stats"]["tool_call_count"] == 1
    assert snapshot["stats"]["blocked_tool_call_count"] == 0
    assert snapshot["graph"]["metrics"]["tool_call_count"] == 1
    assert snapshot["graph"]["metrics"]["graph_node_count"] == 2


def test_graph_filtering_selects_requested_run_and_latest_run_by_default() -> None:
    reset_store()
    first = run_async(main.run_demo())
    second = run_async(main.run_demo())

    first_graph = run_async(main.graph(run_id=first["run_id"]))
    latest_graph = run_async(main.graph())

    assert first_graph["run_id"] == first["run_id"]
    assert first_graph["metrics"]["tool_call_count"] == 3
    assert latest_graph["run_id"] == second["run_id"]
    assert latest_graph["metrics"]["tool_call_count"] == 3


def test_reset_clears_events_approvals_taint_runs_and_graph_state() -> None:
    reset_store()
    previous_session = main.store.session_id
    run_async(main.run_demo())
    review = run_async(main.inspect(ToolCall(
        tool="email.send",
        arguments={"to": "person@example.test", "body": "synthetic"},
        session_id="approval-session",
    )))
    assert review.approval_required is True

    result = run_async(main.reset())
    snapshot = run_async(main.events())

    assert result == {"ok": True}
    assert main.store.session_id != previous_session
    assert snapshot["events"] == []
    assert snapshot["approvals"] == []
    assert snapshot["stats"]["audit_record_count"] == 0
    assert snapshot["stats"]["tool_call_count"] == 0
    assert snapshot["stats"]["blocked_tool_call_count"] == 0
    assert snapshot["stats"]["simulation_run_count"] == 0
    assert snapshot["stats"]["pending_approvals"] == 0
    assert snapshot["stats"]["risk"] == "CLEAR"
    assert snapshot["stats"]["average_latency_ms"] == 0
    assert snapshot["graph"]["nodes"] == []
    assert snapshot["graph"]["edges"] == []
    assert snapshot["graph"]["run_id"] is None
    assert main.store.run_numbers == {}
    assert main.store.session_taints == {}
    assert main.store.mock_deliveries == []
