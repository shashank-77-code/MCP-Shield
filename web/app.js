const feed = document.querySelector('#event-feed');
const approvals = document.querySelector('#approval-feed');
const eventCount = document.querySelector('#event-count');
const approvalCount = document.querySelector('#approval-count');
const risk = document.querySelector('#risk');
let allEvents = [];
let pending = new Map();

const escapeHtml = (value) => String(value).replace(/[&<>'"]/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));
const time = iso => new Date(iso).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'});
function renderEvents() {
  eventCount.textContent = String(allEvents.length).padStart(2, '0');
  risk.textContent = allEvents.some(e => e.verdict === 'block') ? 'CONTAINED' : allEvents.some(e => e.verdict === 'review') ? 'WATCH' : 'CLEAR';
  if (!allEvents.length) { feed.innerHTML = '<div class="empty"><span>◌</span>Waiting for a tool call</div>'; return; }
  feed.innerHTML = allEvents.slice(0, 20).map(e => `<div class="event"><time class="event-time">${time(e.timestamp)}</time><div class="event-main"><b>${escapeHtml(e.tool)}</b><p>${escapeHtml(e.message)}</p></div><span class="badge ${e.verdict}">${e.verdict.toUpperCase()}</span></div>`).join('');
}
function renderApprovals() {
  approvalCount.textContent = `${pending.size} PENDING`;
  if (!pending.size) { approvals.innerHTML = '<div class="empty">No decision needs your attention.</div>'; return; }
  approvals.innerHTML = [...pending.entries()].map(([id, e]) => `<div class="approval"><h4>${escapeHtml(e.tool)} <span class="badge review">REVIEW</span></h4><p>${escapeHtml(e.message)}</p><div class="approval-actions"><button class="approve" data-id="${id}" data-approved="true">Allow once</button><button class="deny" data-id="${id}" data-approved="false">Block call</button></div></div>`).join('');
}
async function resolve(id, approved) { await fetch(`/api/approvals/${id}?approved=${approved}`, {method:'POST'}); pending.delete(id); renderApprovals(); }
approvals.addEventListener('click', e => { const button = e.target.closest('button[data-id]'); if (button) resolve(button.dataset.id, button.dataset.approved === 'true'); });
async function refresh() { const data = await fetch('/api/events').then(r => r.json()); allEvents = data.events; pending = new Map(data.approvals.map(a => [a.id, a.event])); renderEvents(); renderApprovals(); }
document.querySelector('#run-demo').addEventListener('click', async () => { await fetch('/api/demo/run', {method:'POST'}); });
document.querySelector('#reset').addEventListener('click', async () => { await fetch('/api/session/reset', {method:'POST'}); allEvents=[]; pending.clear(); renderEvents(); renderApprovals(); });
function connect() { const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/live`); ws.onmessage = ({data}) => { const m = JSON.parse(data); if (m.type === 'snapshot') { allEvents = m.payload.events; renderEvents(); } if (m.type === 'event') { allEvents.unshift(m.payload); renderEvents(); } if (m.type === 'approval') { pending.set(m.payload.id, m.payload.event); renderApprovals(); } if (m.type === 'approval-resolved') { pending.delete(m.payload.id); renderApprovals(); } if (m.type === 'reset') { allEvents=[]; pending.clear(); renderEvents(); renderApprovals(); } }; ws.onclose = () => setTimeout(connect, 1500); }
refresh().then(connect).catch(() => { renderEvents(); renderApprovals(); });
