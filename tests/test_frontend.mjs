import assert from 'node:assert/strict';
import test from 'node:test';
import { requestJson } from '../web/client.mjs';
import { dashboardMetrics } from '../web/metrics.mjs';
import { gatewayEventSummary, gatewayMetricsView, latestGatewayTrace } from '../web/gateway_view.mjs';

test('frontend converts backend error responses into visible errors', async () => {
  const fetchStub = async () => ({
    ok: false,
    status: 503,
    json: async () => ({detail: 'simulation service unavailable'}),
  });
  await assert.rejects(requestJson(fetchStub, '/api/demo/run'), /simulation service unavailable/);
});

test('frontend reports a non-JSON backend error response', async () => {
  const fetchStub = async () => ({ok: false, status: 502, json: async () => { throw new Error('bad json'); }});
  await assert.rejects(requestJson(fetchStub, '/api/demo/run'), /invalid response \(502\)/);
});

test('dashboard keeps audit totals separate from latest-run graph counts', () => {
  const display = dashboardMetrics({
    audit_record_count: 60,
    audit_record_limit: 60,
    tool_call_count: 58,
    blocked_tool_call_count: 14,
    simulation_run_count: 20,
    average_latency_ms: 1.25,
  }, {
    scope: 'latest_run',
    run_number: 20,
    metrics: {
      tool_call_count: 3,
      unique_tool_count: 3,
      blocked_tool_call_count: 1,
      graph_node_count: 4,
      graph_edge_count: 3,
    },
  });

  assert.equal(display.auditRecords, 60);
  assert.equal(display.auditRecordLimit, 60);
  assert.equal(display.toolCalls, 58);
  assert.equal(display.blockedToolCalls, 14);
  assert.equal(display.graphToolCalls, 3);
  assert.equal(display.uniqueTools, 3);
  assert.equal(display.graphBlockedCalls, 1);
  assert.equal(display.graphNodes, 4);
  assert.equal(display.graphEdges, 3);
  assert.equal(display.graphRunNumber, 20);
  assert.equal(display.graphScope, 'latest_run');
});

test('live dashboard keeps gateway outcome counters separate', () => {
  const view = gatewayMetricsView({
    tool_calls_total: 8,
    allow_count: 3,
    review_count: 2,
    block_count: 3,
    executed_count: 4,
    rejected_count: 1,
    timed_out_count: 1,
    cancelled_count: 1,
    downstream_error_count: 1,
    audit_event_count: 31,
  });
  assert.deepEqual(view, {
    toolCalls: 8, allow: 3, review: 2, block: 3, executed: 4,
    rejected: 1, timedOut: 1, cancelled: 1, downstreamErrors: 1, auditEvents: 31,
  });
});

test('live dashboard summarizes real forwarding and downstream status without arguments', () => {
  const summary = gatewayEventSummary({
    event_type: 'DOWNSTREAM_RESPONSE',
    decision: 'REVIEW_APPROVED',
    matched_policy_ids: ['P-006'],
    forwarding_status: 'FORWARDED',
    downstream_status: 'SUCCESS',
  });
  assert.match(summary, /Downstream response received/);
  assert.match(summary, /forwarding forwarded/);
  assert.match(summary, /downstream success/);
  assert.doesNotMatch(summary, /argument|secret-value/i);
});

test('latest request trace includes only observed events from one request', () => {
  const trace = latestGatewayTrace([
    {request_id: 'older', timestamp: '2026-11-23T12:00:00Z', event_type: 'REQUEST_RECEIVED', server_id: 'fs', tool_name: 'read_file'},
    {request_id: 'older', timestamp: '2026-11-23T12:00:01Z', event_type: 'POLICY_DECISION', decision: 'ALLOW'},
    {request_id: 'latest', timestamp: '2026-11-23T12:01:00Z', event_type: 'REQUEST_RECEIVED', server_id: 'fs', tool_name: 'delete_path'},
    {request_id: 'latest', timestamp: '2026-11-23T12:01:01Z', event_type: 'POLICY_DECISION', decision: 'REVIEW', matched_policy_ids: ['P-006']},
    {request_id: 'latest', timestamp: '2026-11-23T12:01:02Z', event_type: 'APPROVAL_REQUESTED'},
  ]);
  assert.equal(trace.requestId, 'latest');
  assert.equal(trace.toolName, 'fs__delete_path');
  assert.equal(trace.status, 'Waiting for authenticated approval');
  assert.equal(trace.nodes.length, 3);
  assert.equal(trace.edges.length, 2);
  assert.ok(trace.nodes.every(node => node.x >= 0 && node.x <= 100));
  assert.ok(trace.nodes.some(node => node.label === 'REVIEW · P-006'));
});
