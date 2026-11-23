const count = value => Number.isFinite(Number(value)) ? Number(value) : 0;

export function dashboardMetrics(stats, graph) {
  const metrics = graph.metrics || {};
  return {
    auditRecords: count(stats.audit_record_count),
    auditRecordLimit: count(stats.audit_record_limit),
    toolCalls: count(stats.tool_call_count),
    blockedToolCalls: count(stats.blocked_tool_call_count),
    simulationRuns: count(stats.simulation_run_count),
    averageLatencyMs: count(stats.average_latency_ms),
    graphToolCalls: count(metrics.tool_call_count),
    uniqueTools: count(metrics.unique_tool_count),
    graphBlockedCalls: count(metrics.blocked_tool_call_count),
    graphNodes: count(metrics.graph_node_count),
    graphEdges: count(metrics.graph_edge_count),
    graphRunNumber: graph.run_number == null ? null : count(graph.run_number),
    graphScope: graph.scope || 'current_session',
  };
}
