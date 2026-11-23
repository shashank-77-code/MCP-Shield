const number = value => Number.isFinite(Number(value)) ? Number(value) : 0;

export function gatewayMetricsView(metrics = {}) {
  return {
    toolCalls: number(metrics.tool_calls_total),
    allow: number(metrics.allow_count),
    review: number(metrics.review_count),
    block: number(metrics.block_count),
    executed: number(metrics.executed_count),
    rejected: number(metrics.rejected_count),
    timedOut: number(metrics.timed_out_count),
    cancelled: number(metrics.cancelled_count),
    downstreamErrors: number(metrics.downstream_error_count),
    auditEvents: number(metrics.audit_event_count),
  };
}

const eventLabels = {
  REQUEST_RECEIVED: 'Request received by Shield',
  POLICY_DECISION: 'Initial policy decision',
  APPROVAL_REQUESTED: 'Held for human review',
  APPROVAL_GRANTED: 'Approved once by an operator',
  APPROVAL_REJECTED: 'Rejected by an operator',
  APPROVAL_EXPIRED: 'Approval expired',
  REVALIDATION: 'Policy re-evaluated after approval',
  FORWARDED: 'Forwarded to downstream MCP server',
  DOWNSTREAM_RESPONSE: 'Downstream response received',
  DOWNSTREAM_ERROR: 'Downstream server returned an error',
  REQUEST_TERMINATED: 'Request terminated',
};

export function gatewayEventSummary(event) {
  const parts = [eventLabels[event.event_type] || 'Gateway event'];
  if (event.decision) parts.push(`decision ${event.decision}`);
  if (event.matched_policy_ids?.length) parts.push(event.matched_policy_ids.join(', '));
  if (event.forwarding_status) parts.push(`forwarding ${event.forwarding_status.toLowerCase()}`);
  if (event.downstream_status) parts.push(`downstream ${event.downstream_status.toLowerCase()}`);
  return parts.join(' · ');
}

const nodeFor = event => {
  const policy = (event.matched_policy_ids || []).join(', ');
  switch (event.event_type) {
    case 'REQUEST_RECEIVED': return {label: 'REQUEST RECEIVED', kind: 'client'};
    case 'POLICY_DECISION': return {label: `${event.decision || 'POLICY'}${policy ? ` · ${policy}` : ''}`, kind: event.decision === 'ALLOW' ? 'tool' : event.decision === 'REVIEW' ? 'review' : 'danger'};
    case 'APPROVAL_REQUESTED': return {label: 'WAITING FOR HUMAN REVIEW', kind: 'review'};
    case 'APPROVAL_GRANTED': return {label: 'APPROVED ONCE', kind: 'review'};
    case 'APPROVAL_REJECTED': return {label: 'REJECTED BY OPERATOR', kind: 'danger'};
    case 'APPROVAL_EXPIRED': return {label: 'APPROVAL EXPIRED', kind: 'danger'};
    case 'REVALIDATION': return {label: `REVALIDATION · ${event.decision || 'UNKNOWN'}`, kind: event.decision === 'ALLOW' ? 'tool' : event.decision === 'REVIEW' ? 'review' : 'danger'};
    case 'FORWARDED': return {label: `FORWARDED · ${event.server_id || 'SERVER'}`, kind: 'tool'};
    case 'DOWNSTREAM_RESPONSE': return {label: `RESPONSE · ${event.downstream_status || 'UNKNOWN'}`, kind: event.downstream_status === 'SUCCESS' ? 'tool' : 'danger'};
    case 'DOWNSTREAM_ERROR': return {label: 'DOWNSTREAM ERROR', kind: 'danger'};
    case 'REQUEST_TERMINATED': return {label: `TERMINATED · ${event.forwarding_status || 'UNKNOWN'}`, kind: 'danger'};
    default: return null;
  }
};

export function latestGatewayTrace(events = []) {
  const ordered = [...events].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
  const latestEvent = [...ordered].reverse().find(event => event.request_id);
  if (!latestEvent) return {requestId: null, toolName: null, nodes: [], edges: [], status: 'No gateway requests yet'};

  const requestEvents = ordered.filter(event => event.request_id === latestEvent.request_id);
  const latest = requestEvents.at(-1);
  const routeEvent = requestEvents.find(event => event.server_id || event.tool_name) || latest;
  const nodes = requestEvents.map(nodeFor).filter(Boolean);
  if (nodes.length && nodes[0].label !== 'REQUEST RECEIVED') nodes.unshift({label: 'REQUEST', kind: 'client'});
  const placed = nodes.map((node, index) => ({
    id: `${latestEvent.request_id}-${index}`,
    label: node.label,
    kind: node.kind,
    x: nodes.length === 1 ? 50 : 7 + (86 * index / (nodes.length - 1)),
    y: nodes.length > 4 && index % 2 ? 65 : 42,
  }));

  let status = 'Request is in progress';
  if (requestEvents.some(event => event.event_type === 'DOWNSTREAM_ERROR')) status = 'Downstream error recorded';
  else if (requestEvents.some(event => event.event_type === 'DOWNSTREAM_RESPONSE')) status = `Downstream ${latest.downstream_status?.toLowerCase() || 'response recorded'}`;
  else if (requestEvents.some(event => event.event_type === 'FORWARDED')) status = 'Forwarded; waiting for downstream result';
  else if (requestEvents.some(event => event.event_type === 'REQUEST_TERMINATED')) status = `Not forwarded · ${latest.forwarding_status.toLowerCase()}`;
  else if (requestEvents.some(event => event.event_type === 'APPROVAL_REQUESTED')) status = 'Waiting for authenticated approval';
  else if (latest.decision) status = `Policy decision · ${latest.decision}`;

  return {
    requestId: latestEvent.request_id,
    toolName: routeEvent.tool_name ? `${routeEvent.server_id || 'server'}__${routeEvent.tool_name}` : null,
    nodes: placed,
    edges: placed.slice(1).map((node, index) => [`${latestEvent.request_id}-${index}`, node.id]),
    status,
  };
}
