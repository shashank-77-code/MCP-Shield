import { requestJson } from './client.mjs';
import { gatewayEventSummary, gatewayMetricsView, latestGatewayTrace } from './gateway_view.mjs';

const feed = document.querySelector('#event-feed');
const approvals = document.querySelector('#approval-feed');
const eventCount = document.querySelector('#event-count');
const approvalCount = document.querySelector('#approval-count');
const blockedCallCount = document.querySelector('#blocked-call-count');
const toolCallCount = document.querySelector('#tool-call-count');
const executedCount = document.querySelector('#executed-count');
const allowCallCount = document.querySelector('#allow-call-count');
const reviewCallCount = document.querySelector('#review-call-count');
const rejectedCount = document.querySelector('#rejected-count');
const timedOutCount = document.querySelector('#timed-out-count');
const cancelledCount = document.querySelector('#cancelled-count');
const downstreamErrorCount = document.querySelector('#downstream-error-count');
const connectionStatus = document.querySelector('#connection-status');
const gatewayStatus = document.querySelector('#gateway-status');
const gatewayPulse = document.querySelector('#gateway-pulse');
const downstreamCount = document.querySelector('#downstream-count');
const eventRetention = document.querySelector('#event-retention');
const approvalMode = document.querySelector('#approval-mode');
const resultBanner = document.querySelector('#simulation-result');
const demoButton = document.querySelector('#run-demo');
const graphNodes = document.querySelector('#session-nodes');
const graphEdges = document.querySelector('#session-edges');
const graphEmpty = document.querySelector('#graph-empty');
const graphRisk = document.querySelector('#graph-risk');
const graphDetail = document.querySelector('#graph-detail');
const graphScope = document.querySelector('#graph-scope');
const tokenInput = document.querySelector('#approver-token');
const unlockButton = document.querySelector('#unlock-approvals');
const lockButton = document.querySelector('#lock-approvals');
const approvalAuthStatus = document.querySelector('#approval-auth-status');

let allEvents = [];
let pendingApprovals = [];
let approverToken = '';
let refreshing = false;
let approvalsEnabled = false;

const escapeHtml = value => String(value).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const request = (url, options) => requestJson(fetch, url, options);
const time = iso => new Date(iso).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'});
const shortId = value => String(value || '').slice(0, 8);

function showResult(message, kind = 'allow') {
  resultBanner.hidden = false;
  resultBanner.className = `result-banner ${kind}`;
  resultBanner.textContent = message;
}

function setConnection(connected) {
  connectionStatus.classList.toggle('offline', !connected);
  connectionStatus.innerHTML = `<i></i> ${connected ? 'LIVE · 2S POLL' : 'RECONNECTING'}`;
}

function renderEvents() {
  if (!allEvents.length) {
    feed.innerHTML = '<div class="empty"><span>◌</span>Waiting for a gateway request</div>';
    return;
  }
  feed.innerHTML = allEvents.slice(0, 30).map(event => {
    const verdict = String(event.decision || '').toLowerCase();
    const badge = verdict === 'allow' || verdict === 'review' || verdict === 'block'
      ? verdict
      : event.downstream_status === 'ERROR' || event.forwarding_status === 'REJECTED' ? 'block' : 'status';
    const tool = event.tool_name ? `${event.server_id || 'server'}__${event.tool_name}` : 'Shield request';
    return `<div class="event"><time class="event-time">${escapeHtml(time(event.timestamp))}</time><div class="event-main"><b>${escapeHtml(tool)}</b><p>${escapeHtml(gatewayEventSummary(event))} · req ${escapeHtml(shortId(event.request_id))}</p></div><span class="badge ${badge}">${escapeHtml(event.downstream_status || event.forwarding_status || event.decision || event.event_type)}</span></div>`;
  }).join('');
}

function renderMetrics(metrics) {
  const view = gatewayMetricsView(metrics);
  toolCallCount.textContent = String(view.toolCalls);
  allowCallCount.textContent = String(view.allow);
  reviewCallCount.textContent = String(view.review);
  blockedCallCount.textContent = String(view.block);
  executedCount.textContent = String(view.executed);
  eventCount.textContent = String(view.auditEvents);
  rejectedCount.textContent = String(view.rejected);
  timedOutCount.textContent = String(view.timedOut);
  cancelledCount.textContent = String(view.cancelled);
  downstreamErrorCount.textContent = String(view.downstreamErrors);
}

function renderTrace() {
  const trace = latestGatewayTrace(allEvents);
  graphNodes.replaceChildren();
  graphEdges.replaceChildren();
  graphEmpty.hidden = trace.nodes.length > 0;
  graphScope.textContent = trace.requestId ? `LATEST REQUEST · ${shortId(trace.requestId)}` : 'LATEST REQUEST';
  graphRisk.textContent = trace.status;
  graphDetail.textContent = trace.requestId
    ? `${trace.toolName || 'Shield request'} · ${trace.nodes.length} recorded transition${trace.nodes.length === 1 ? '' : 's'}.`
    : 'The trace will reflect actual gateway audit events.';

  const positions = new Map(trace.nodes.map(node => [node.id, node]));
  for (const [from, to] of trace.edges) {
    const a = positions.get(from);
    const b = positions.get(to);
    if (!a || !b) continue;
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    line.setAttribute('d', `M ${a.x * 9} ${a.y * 3.6} L ${b.x * 9} ${b.y * 3.6}`);
    graphEdges.append(line);
  }
  for (const node of trace.nodes) {
    const element = document.createElement('div');
    element.className = `node ${escapeHtml(node.kind)}`;
    element.style.left = `${node.x}%`;
    element.style.top = `${node.y}%`;
    element.textContent = node.label;
    element.title = trace.requestId ? `Request ${trace.requestId}` : '';
    graphNodes.append(element);
  }
}

function renderApprovals() {
  if (!approverToken) {
    approvalCount.textContent = 'LOCKED';
    approvals.innerHTML = '<div class="empty">Unlock with an approver token to view pending requests.</div>';
    return;
  }
  approvalCount.textContent = `${pendingApprovals.length} PENDING`;
  if (!pendingApprovals.length) {
    approvals.innerHTML = '<div class="empty">No decision needs your attention.</div>';
    return;
  }
  approvals.innerHTML = pendingApprovals.map(item => `<div class="approval">
    <h4>${escapeHtml(item.server_id)}__${escapeHtml(item.tool_name)} <span class="badge review">REVIEW</span></h4>
    <p>Request ${escapeHtml(shortId(item.request_id))} · ${escapeHtml(item.argument_count)} redacted argument(s) · ${escapeHtml((item.matched_policy_ids || []).join(', '))}</p>
    <p>Evidence: ${escapeHtml((item.redacted_evidence || []).join(', ') || 'none listed')} · Expires ${escapeHtml(new Date(item.expires_at).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'}))}</p>
    <label class="reason-label" for="reason-${escapeHtml(item.request_id)}">Decision reason</label>
    <textarea id="reason-${escapeHtml(item.request_id)}" maxlength="500" rows="2" placeholder="Required for every decision"></textarea>
    <div class="approval-actions"><button class="approve" data-id="${escapeHtml(item.request_id)}" data-action="approve">Approve once</button><button class="deny" data-id="${escapeHtml(item.request_id)}" data-action="reject">Reject</button></div>
  </div>`).join('');
}

function clearApproverToken(message = 'Approvals are locked. Enter an approver token to load pending requests.') {
  approverToken = '';
  pendingApprovals = [];
  tokenInput.value = '';
  unlockButton.disabled = !approvalsEnabled;
  lockButton.disabled = true;
  approvalMode.textContent = 'locked';
  approvalAuthStatus.textContent = message;
  renderApprovals();
}

async function refreshApprovals() {
  if (!approverToken) return;
  try {
    const data = await request('/api/gateway/approvals', {headers: {Authorization: `Bearer ${approverToken}`}});
    pendingApprovals = data.approvals;
    renderApprovals();
    approvalAuthStatus.textContent = 'Approver authenticated · token stays in this page memory only.';
  } catch (error) {
    if (/401|403|authentication|credentials/i.test(error.message)) {
      clearApproverToken('Approver authentication failed. The token was cleared.');
    } else {
      approvalAuthStatus.textContent = `Could not refresh approvals: ${error.message}`;
    }
  }
}

async function refreshGateway() {
  if (refreshing) return;
  refreshing = true;
  try {
    const [data, health] = await Promise.all([
      request('/api/gateway/events'),
      request('/api/health'),
    ]);
    allEvents = data.events;
    renderEvents();
    renderMetrics(data.metrics);
    renderTrace();
    downstreamCount.textContent = String(health.downstream_server_count);
    eventRetention.textContent = String(health.audit_event_limit);
    approvalsEnabled = health.approvals_enabled === true;
    approvalMode.textContent = approverToken ? 'unlocked' : approvalsEnabled ? 'locked' : 'disabled';
    tokenInput.disabled = !approvalsEnabled;
    unlockButton.disabled = !approvalsEnabled || Boolean(approverToken);
    lockButton.disabled = !approverToken;
    if (!approvalsEnabled && !approverToken) approvalAuthStatus.textContent = 'Approvals are disabled because no approver credentials are configured.';
    gatewayStatus.textContent = health.downstream_server_count
      ? `GATEWAY READY · ${health.downstream_server_count} DOWNSTREAM`
      : 'GATEWAY READY · NO DOWNSTREAM SERVERS';
    gatewayPulse.classList.toggle('gateway-offline', false);
    setConnection(true);
    await refreshApprovals();
  } catch (error) {
    setConnection(false);
    gatewayStatus.textContent = 'GATEWAY UNAVAILABLE';
    gatewayPulse.classList.add('gateway-offline');
    showResult(`Could not load live gateway data: ${error.message}`, 'error');
  } finally {
    refreshing = false;
  }
}

async function unlockApprovals() {
  if (!approvalsEnabled) {
    approvalAuthStatus.textContent = 'Approvals are disabled because no approver credentials are configured.';
    return;
  }
  const candidate = tokenInput.value.trim();
  tokenInput.value = '';
  if (!candidate) {
    approvalAuthStatus.textContent = 'Enter an approver token first.';
    return;
  }
  unlockButton.disabled = true;
  try {
    const data = await request('/api/gateway/approvals', {headers: {Authorization: `Bearer ${candidate}`}});
    approverToken = candidate;
    pendingApprovals = data.approvals;
    lockButton.disabled = false;
    approvalMode.textContent = 'unlocked';
    approvalAuthStatus.textContent = 'Approver authenticated · token stays in this page memory only.';
    renderApprovals();
  } catch (error) {
    approverToken = '';
    pendingApprovals = [];
    approvalMode.textContent = 'locked';
    approvalAuthStatus.textContent = `Could not unlock approvals: ${error.message}`;
    unlockButton.disabled = false;
    renderApprovals();
  }
}

async function resolveApproval(id, action) {
  if (!approverToken) return;
  const reason = document.querySelector(`#reason-${CSS.escape(id)}`)?.value.trim() || '';
  if (!reason) {
    showResult('Enter a reason before approving or rejecting this request.', 'error');
    return;
  }
  try {
    await request(`/api/gateway/approvals/${encodeURIComponent(id)}`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json', Authorization: `Bearer ${approverToken}`},
      body: JSON.stringify({action, reason}),
    });
    showResult(`${action === 'approve' ? 'Approval recorded' : 'Rejection recorded'} for request ${shortId(id)}.`, action === 'approve' ? 'review' : 'block');
    await refreshGateway();
  } catch (error) {
    if (/401|403|authentication|credentials/i.test(error.message)) clearApproverToken('Approver authentication failed. The token was cleared.');
    showResult(`Could not update approval: ${error.message}`, 'error');
  }
}

async function runDemo() {
  demoButton.disabled = true;
  resultBanner.hidden = true;
  try {
    const result = await request('/api/demo/run', {method:'POST'});
    const d = result.decision;
    showResult(`DEMO DATA ONLY · ${d.verdict.toUpperCase()} · ${d.rule}: ${d.explanation} Mock destination called: ${d.destination_called ? 'yes' : 'no'}. This simulation is separate from live gateway metrics.`, d.verdict);
  } catch (error) {
    showResult(`DEMO DATA simulation failed: ${error.message}`, 'error');
  } finally {
    demoButton.disabled = false;
  }
}

async function resetDemoData() {
  try {
    await request('/api/session/reset', {method:'POST'});
    showResult('DEMO DATA was reset. Live gateway audit and request history were not changed.', 'allow');
  } catch (error) {
    showResult(`Could not reset DEMO DATA: ${error.message}`, 'error');
  }
}

approvals.addEventListener('click', event => {
  const button = event.target.closest('button[data-id][data-action]');
  if (button) resolveApproval(button.dataset.id, button.dataset.action);
});
unlockButton.addEventListener('click', unlockApprovals);
tokenInput.addEventListener('keydown', event => { if (event.key === 'Enter') unlockApprovals(); });
lockButton.addEventListener('click', () => clearApproverToken());
demoButton.addEventListener('click', runDemo);
document.querySelector('#reset').addEventListener('click', resetDemoData);

refreshGateway();
setInterval(() => refreshGateway(), 2000);
