'use strict';
/* Warden XDR dashboard — dependency-free single page app. Every value coming
   from the API passes through esc() before reaching innerHTML: log lines are
   attacker-controlled. */

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const view = () => $('#view');
let TOKEN = sessionStorage.getItem('wtoken') || '';
let AGENTS = [];
let MITRE = {};
let stream = null;

// ---------------- icons ----------------
const P = (d) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${d}</svg>`;
const ICONS = {
  grid: P('<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>'),
  bell: P('<path d="M6 8a6 6 0 1 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>'),
  server: P('<rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 7h.01M6 17h.01"/>'),
  file: P('<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M9 15l2 2 4-4"/>'),
  bug: P('<path d="M8 2l1.9 1.9M16 2l-1.9 1.9M9 7.1V6a3 3 0 1 1 6 0v1.1"/><path d="M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6zM12 20v-9M6 13H2M22 13h-4M3 21l3-2M21 21l-3-2M3 5l3 2M21 5l-3 2"/>'),
  check: P('<path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>'),
  target: P('<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>'),
  zap: P('<path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>'),
  code: P('<path d="M16 18l6-6-6-6M8 6l-6 6 6 6"/>'),
  layers: P('<path d="M12 2 2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>'),
  cpu: P('<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"/>'),
};
$$('[data-icon]').forEach((i) => (i.innerHTML = ICONS[i.dataset.icon] || ''));

// ---------------- helpers ----------------
async function api(path, opts = {}) {
  const res = await fetch('/api' + path, {
    method: opts.method || 'GET',
    headers: { Authorization: 'Bearer ' + TOKEN, 'Content-Type': 'application/json' },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (res.status === 401) { logout(); throw new Error('unauthorized'); }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}
const lvlClass = (l) => (l >= 12 ? 'crit' : l >= 10 ? 'high' : l >= 7 ? 'med' : '');
const lvl = (l) => `<span class="lvl ${lvlClass(l)}">${esc(l)}</span>`;
const fmtTime = (ts) => { if (!ts) return '—'; const d = new Date(ts * 1000); return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) + ' ' + d.toLocaleTimeString(undefined, { hour12: false }); };
function ago(ts) {
  if (!ts) return 'never';
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return Math.floor(s) + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}
const num = (n) => Number(n || 0).toLocaleString();
const agentName = (id) => (AGENTS.find((a) => a.id === id) || {}).name || (id === '000' ? 'warden-manager' : id);
const mitrePills = (arr) => (arr || []).map((t) => `<span class="pill mitre" title="${esc((MITRE[t] || {}).name || '')}">${esc(t)}</span>`).join('');
const empty = (msg) => `<div class="empty">${esc(msg)}</div>`;
function toast(msg, err) {
  const t = $('#toast');
  t.textContent = msg; t.className = 'toast' + (err ? ' err' : '');
  clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.add('hidden'), 4000);
}
function setActions(html) { $('#page-actions').innerHTML = html; }
function drawer(html) { $('#drawer-body').innerHTML = html; $('#drawer').classList.remove('hidden'); }
function closeDrawer() { $('#drawer').classList.add('hidden'); }
$('#drawer').addEventListener('click', (e) => { if (e.target.id === 'drawer' || e.target.classList.contains('drawer-close')) closeDrawer(); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDrawer(); });
const agentOptions = (sel, all = 'All endpoints') => `<option value="">${esc(all)}</option>` + AGENTS.map((a) => `<option value="${esc(a.id)}" ${a.id === sel ? 'selected' : ''}>${esc(a.id)} · ${esc(a.name)}</option>`).join('');
async function loadAgents() { AGENTS = await api('/agents'); return AGENTS; }
const qs = (o) => Object.entries(o).filter(([, v]) => v !== '' && v != null && v !== 0).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');

// ---------------- charts ----------------
function timelineChart(rows, hours) {
  const bucket = 3600, now = Math.floor(Date.now() / 1000 / bucket) * bucket;
  const span = Math.min(hours, 24 * 7);
  const map = Object.fromEntries((rows || []).map((r) => [Number(r.key), r.count]));
  const data = [];
  for (let i = span - 1; i >= 0; i--) data.push({ t: now - i * bucket, v: map[now - i * bucket] || 0 });
  const W = 900, H = 170, pad = 26, max = Math.max(1, ...data.map((d) => d.v));
  const bw = (W - pad) / data.length;
  let bars = '', labels = '';
  data.forEach((d, i) => {
    const h = (d.v / max) * (H - 34);
    const color = d.v === max && d.v > 0 ? 'var(--accent-2)' : 'var(--accent)';
    bars += `<rect x="${pad + i * bw + 1}" y="${H - 18 - h}" width="${Math.max(1, bw - 2)}" height="${h}" rx="1.5" fill="${color}" opacity="${d.v ? 0.9 : 0.15}"><title>${new Date(d.t * 1000).toLocaleString()} — ${d.v} alerts</title></rect>`;
    if (i % Math.ceil(data.length / 8) === 0) labels += `<text x="${pad + i * bw}" y="${H - 3}" fill="var(--dim)" font-size="10">${new Date(d.t * 1000).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', hour12: false })}</text>`;
  });
  const grid = [0.5, 1].map((f) => `<line x1="${pad}" x2="${W}" y1="${H - 18 - f * (H - 34)}" y2="${H - 18 - f * (H - 34)}" stroke="var(--line)"/><text x="0" y="${H - 14 - f * (H - 34)}" fill="var(--dim)" font-size="10">${Math.round(max * f)}</text>`).join('');
  return `<div class="chart"><svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" height="170">${grid}${bars}${labels}</svg></div>`;
}
function donut(parts) {
  const total = parts.reduce((s, p) => s + p.v, 0) || 1;
  let a = -Math.PI / 2, paths = '';
  const R = 52, r = 34, cx = 60, cy = 60;
  parts.forEach((p) => {
    if (!p.v) return;
    const a2 = a + (p.v / total) * Math.PI * 2 - 0.0001;
    const large = a2 - a > Math.PI ? 1 : 0;
    const pt = (rad, ang) => `${cx + rad * Math.cos(ang)} ${cy + rad * Math.sin(ang)}`;
    paths += `<path d="M ${pt(R, a)} A ${R} ${R} 0 ${large} 1 ${pt(R, a2)} L ${pt(r, a2)} A ${r} ${r} 0 ${large} 0 ${pt(r, a)} Z" fill="${p.c}"><title>${p.label}: ${p.v}</title></path>`;
    a = a2 + 0.0001;
  });
  if (!paths) paths = `<circle cx="60" cy="60" r="43" fill="none" stroke="var(--line)" stroke-width="18"/>`;
  return `<div class="donut"><svg viewBox="0 0 120 120" width="120" height="120">${paths}<text x="60" y="64" text-anchor="middle" fill="var(--text)" font-size="18" font-weight="600">${num(parts.reduce((s, p) => s + p.v, 0))}</text></svg>
    <div class="legend">${parts.map((p) => `<span style="--c:${p.c}">${esc(p.label)} <b class="mono">${num(p.v)}</b></span>`).join('')}</div></div>`;
}
function bars(rows, fmt = (r) => esc(r.key), link) {
  if (!rows || !rows.length) return empty('No data yet');
  const max = Math.max(...rows.map((r) => r.count));
  return `<div class="bars">${rows.map((r) => `<div class="row">
    <span class="name">${link ? `<a href="${link(r)}">${fmt(r)}</a>` : fmt(r)}</span><span class="n">${num(r.count)}</span>
    <div class="track"><div class="fill" style="width:${(r.count / max) * 100}%"></div></div></div>`).join('')}</div>`;
}

// ---------------- auth ----------------
function logout() {
  TOKEN = ''; sessionStorage.removeItem('wtoken');
  if (stream) { stream.close(); stream = null; }
  $('#app').classList.add('hidden'); $('#login').classList.remove('hidden');
}
$('#logout').onclick = logout;
$('#login-form').onsubmit = async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const res = await fetch('/api/login', { method: 'POST', body: JSON.stringify({ username: f.get('username'), password: f.get('password') }) });
  if (!res.ok) { $('#login-error').textContent = 'Invalid username or password'; return; }
  TOKEN = (await res.json()).token;
  sessionStorage.setItem('wtoken', TOKEN);
  start();
};

// ---------------- live stream ----------------
const liveHandlers = new Set();
function connectStream() {
  if (stream) stream.close();
  stream = new EventSource('/api/alerts/stream?token=' + encodeURIComponent(TOKEN));
  stream.onopen = () => { $('#live-dot').className = 'dot on'; $('#live-text').textContent = 'live'; };
  stream.onerror = () => { $('#live-dot').className = 'dot off'; $('#live-text').textContent = 'reconnecting'; };
  stream.onmessage = (m) => {
    const a = JSON.parse(m.data);
    if (a.level >= 10) toast(`Level ${a.level} · ${a.agent_name}: ${a.description}`, a.level >= 12);
    liveHandlers.forEach((h) => h(a));
  };
}

// ---------------- router ----------------
const ROUTES = {
  overview: ['Overview', viewOverview], alerts: ['Threat hunting', viewAlerts], agents: ['Endpoints', viewAgents],
  fim: ['File integrity monitoring', viewFIM], vulns: ['Vulnerability detection', viewVulns], sca: ['Security configuration assessment', viewSCA],
  mitre: ['MITRE ATT&CK', viewMitre], response: ['Active response', viewResponse], rules: ['Rules & logtest', viewRules],
  groups: ['Agent groups', viewGroups], manager: ['Manager status', viewManager],
};
function parseHash() {
  const [path, query] = (location.hash.slice(2) || 'overview').split('?');
  const parts = path.split('/');
  return { route: parts[0], arg: parts[1], params: Object.fromEntries(new URLSearchParams(query || '')) };
}
async function render() {
  const { route, arg, params } = parseHash();
  const [title, fn] = ROUTES[route] || ROUTES.overview;
  liveHandlers.clear(); closeDrawer(); setActions('');
  $('#page-title').textContent = title;
  $$('#nav a').forEach((a) => a.classList.toggle('active', a.dataset.route === route));
  view().innerHTML = '<div class="empty">Loading…</div>';
  try { await fn(arg, params); } catch (e) { if (e.message !== 'unauthorized') view().innerHTML = empty('Error: ' + e.message); }
}
window.addEventListener('hashchange', render);

async function start() {
  $('#login').classList.add('hidden'); $('#app').classList.remove('hidden');
  try {
    await loadAgents();
    (await api('/mitre')).forEach((t) => (MITRE[t.id] = t));
  } catch (e) { return; }
  connectStream();
  render();
}

// ================= views =================

async function viewOverview(_, params) {
  const hours = Number(params.hours || 24);
  setActions(`<select id="range">${[[24, 'Last 24 hours'], [168, 'Last 7 days'], [720, 'Last 30 days']].map(([v, l]) => `<option value="${v}" ${v === hours ? 'selected' : ''}>${l}</option>`).join('')}</select>`);
  $('#range').onchange = (e) => (location.hash = '#/overview?hours=' + e.target.value);
  const [o, crit] = await Promise.all([api('/overview?hours=' + hours), api(`/alerts?level=10&limit=8&hours=${hours}`)]);
  const lv = Object.fromEntries((o.by_level || []).map((r) => [Number(r.key), r.count]));
  const sum = (a, b) => Object.entries(lv).filter(([k]) => k >= a && k <= b).reduce((s, [, v]) => s + v, 0);
  const scaTotal = o.sca_passed + o.sca_failed;
  const score = scaTotal ? Math.round((o.sca_passed / scaTotal) * 100) : null;
  view().innerHTML = `
  <div class="grid g4">
    <div class="card stat accent"><span class="label">Alerts</span><span class="value">${num(o.alerts)}</span><span class="sub">${num(o.auth_failures)} authentication failures</span></div>
    <div class="card stat crit"><span class="label">Critical (level 12+)</span><span class="value">${num(o.high)}</span><span class="sub">${num(sum(10, 11))} high (10–11)</span></div>
    <div class="card stat ${o.agents.disconnected ? 'high' : 'ok'}"><span class="label">Endpoints active</span><span class="value">${num(o.agents.active || 0)}<span class="muted" style="font-size:16px"> / ${num(o.agents_total)}</span></span><span class="sub">${num(o.agents.disconnected || 0)} disconnected · ${num(o.agents.never_connected || 0)} pending</span></div>
    <div class="card stat ${o.vulns_high ? 'high' : 'ok'}"><span class="label">Vulnerabilities</span><span class="value">${num(o.vulns)}</span><span class="sub">${num(o.vulns_high)} high or critical · SCA score ${score == null ? '—' : score + '%'}</span></div>
  </div>
  <div class="grid g21" style="margin-top:16px">
    <div class="card"><h2>Alert volume</h2>${timelineChart(o.timeline, hours)}</div>
    <div class="card"><h2>Severity</h2>${donut([{ label: 'Low (3–6)', v: sum(0, 6), c: '#475569' }, { label: 'Medium (7–9)', v: sum(7, 9), c: '#eab308' }, { label: 'High (10–11)', v: sum(10, 11), c: '#f97316' }, { label: 'Critical (12+)', v: sum(12, 16), c: '#ef4444' }])}</div>
  </div>
  <div class="grid g3" style="margin-top:16px">
    <div class="card"><h2>Top rules</h2>${bars(o.top_rules, (r) => `<span class="mono muted">${esc(r.key)}</span> ${esc(r.label)}`, (r) => '#/alerts?rule=' + encodeURIComponent(r.key))}</div>
    <div class="card"><h2>MITRE ATT&amp;CK techniques</h2>${bars((o.mitre || []).slice(0, 8), (r) => `<span class="mono muted">${esc(r.key)}</span> ${esc((MITRE[r.key] || {}).name || '')}`, (r) => '#/alerts?mitre=' + encodeURIComponent(r.key))}</div>
    <div class="card"><h2>Top source IPs</h2>${bars(o.top_srcip, (r) => `<span class="mono">${esc(r.key)}</span>`, (r) => '#/alerts?q=' + encodeURIComponent(r.key))}</div>
  </div>
  <div class="card flush" style="margin-top:16px"><h2>Recent high-severity alerts</h2>${alertTable(crit.items, true)}</div>`;
  bindAlertRows(crit.items);
  liveHandlers.add(() => { clearTimeout(viewOverview.t); viewOverview.t = setTimeout(render, 3000); });
}

function alertTable(items, compact) {
  if (!items.length) return empty('No alerts match');
  return `<div class="table-wrap"><table><thead><tr><th>Time</th><th>Endpoint</th><th>Rule</th><th>Lvl</th><th>Description</th><th>MITRE</th>${compact ? '' : '<th>Source IP</th>'}</tr></thead>
  <tbody>${items.map((a) => alertRow(a, compact)).join('')}</tbody></table></div>`;
}
const alertRow = (a, compact, fresh) => `<tr class="click${fresh ? ' new' : ''}" data-alert="${a.id}">
  <td class="nowrap mono">${fmtTime(a.timestamp)}</td><td class="nowrap">${esc(a.agent_name)}</td><td class="mono">${esc(a.rule_id)}</td><td>${lvl(a.level)}</td>
  <td>${esc(a.description)}<div class="log" style="color:var(--dim);font:11.5px var(--mono);max-width:560px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(a.full_log)}</div></td>
  <td>${mitrePills(a.mitre)}</td>${compact ? '' : `<td class="mono">${esc(a.srcip)}</td>`}</tr>`;
const alertIndex = new Map();
function bindAlertRows(items) {
  items.forEach((a) => alertIndex.set(String(a.id), a));
  view().onclick = (e) => { const tr = e.target.closest('tr[data-alert]'); if (tr) showAlert(alertIndex.get(tr.dataset.alert)); };
}
function showAlert(a) {
  if (!a) return;
  const fields = Object.entries(a.fields || {}).sort();
  const comp = Object.entries(a.compliance || {}).map(([k, v]) => v.map((x) => `<span class="pill">${esc(k)} ${esc(x)}</span>`).join('')).join('');
  const mitre = (a.mitre || []).map((t) => `<div><span class="pill mitre">${esc(t)}</span> ${esc((MITRE[t] || {}).name || '')} <span class="muted">· ${esc((MITRE[t] || {}).tactic || '')}</span></div>`).join('');
  drawer(`<div class="stack">
    <div><div class="muted mono" style="font-size:12px">Alert #${esc(a.id)} · ${fmtTime(a.timestamp)}</div><h3 style="margin:6px 0 0;font-size:18px">${lvl(a.level)} ${esc(a.description)}</h3></div>
    <div class="actions">
      <a class="btn small" href="#/alerts?rule=${a.rule_id}">Same rule</a>
      <a class="btn small" href="#/agents/${esc(a.agent_id)}">Endpoint ${esc(a.agent_name)}</a>
      ${a.srcip && a.agent_id !== '000' ? `<button class="btn small danger" id="block-ip">Block ${esc(a.srcip)} on ${esc(a.agent_name)}</button>` : ''}
    </div>
    <div><h2>Full log</h2><pre class="log">${esc(a.full_log)}</pre></div>
    <div class="kv"><div>rule.id</div><div>${esc(a.rule_id)}</div><div>rule.level</div><div>${esc(a.level)}</div><div>rule.groups</div><div>${(a.groups || []).map((g) => `<span class="pill">${esc(g)}</span>`).join('')}</div>
      <div>rule.firedtimes</div><div>${esc(a.firedtimes)}</div><div>decoder</div><div>${esc(a.decoder)}</div><div>location</div><div class="mono">${esc(a.location)}</div><div>agent</div><div>${esc(a.agent_id)} · ${esc(a.agent_name)}</div></div>
    ${mitre ? `<div><h2>MITRE ATT&amp;CK</h2>${mitre}</div>` : ''}
    ${comp ? `<div><h2>Compliance</h2>${comp}</div>` : ''}
    <div><h2>Decoded fields</h2><div class="kv">${fields.map(([k, v]) => `<div>${esc(k)}</div><div class="mono">${esc(v)}</div>`).join('') || '<div>—</div><div></div>'}</div></div>
  </div>`);
  const b = $('#block-ip');
  if (b) b.onclick = async () => {
    try { await api(`/agents/${a.agent_id}/commands`, { method: 'POST', body: { name: 'firewall-drop', args: { target: a.srcip }, timeout: 3600 } }); toast('firewall-drop queued for ' + a.srcip + ' (1h)'); closeDrawer(); }
    catch (e) { toast(e.message, true); }
  };
}

async function viewAlerts(_, p) {
  const f = { q: p.q || '', agent: p.agent || '', level: Number(p.level || 0), hours: Number(p.hours || 0), rule: p.rule || '', group: p.group || '', mitre: p.mitre || '', offset: Number(p.offset || 0) };
  const limit = 50;
  const data = await api('/alerts?' + qs({ ...f, limit }));
  view().innerHTML = `
    <form class="filters" id="af">
      <input type="search" name="q" placeholder="Search log, description or IP…" value="${esc(f.q)}">
      <select name="agent">${agentOptions(f.agent)}</select>
      <select name="level">${[[0, 'Any level'], [5, 'Level ≥ 5'], [7, 'Level ≥ 7'], [10, 'Level ≥ 10'], [12, 'Level ≥ 12']].map(([v, l]) => `<option value="${v}" ${v === f.level ? 'selected' : ''}>${l}</option>`).join('')}</select>
      <select name="hours">${[[0, 'All time'], [1, 'Last hour'], [24, 'Last 24h'], [168, 'Last 7d']].map(([v, l]) => `<option value="${v}" ${v === f.hours ? 'selected' : ''}>${l}</option>`).join('')}</select>
      <input name="rule" placeholder="Rule ID" value="${esc(f.rule)}" style="width:96px">
      <input name="mitre" placeholder="Technique" value="${esc(f.mitre)}" style="width:110px">
      <input name="group" placeholder="Rule group" value="${esc(f.group)}" style="width:150px">
      <button class="btn primary">Apply</button><a class="btn" href="#/alerts">Reset</a>
      <span class="muted" style="margin-left:auto">${num(data.total)} alerts</span>
    </form>
    <div class="card flush" id="alert-list">${alertTable(data.items)}</div>
    <div class="filters" style="margin-top:14px;justify-content:flex-end">
      ${f.offset > 0 ? `<a class="btn small" href="#/alerts?${qs({ ...f, offset: Math.max(0, f.offset - limit) })}">← Newer</a>` : ''}
      ${f.offset + limit < data.total ? `<a class="btn small" href="#/alerts?${qs({ ...f, offset: f.offset + limit })}">Older →</a>` : ''}
    </div>`;
  $('#af').onsubmit = (e) => { e.preventDefault(); const d = Object.fromEntries(new FormData(e.target)); location.hash = '#/alerts?' + qs(d); };
  bindAlertRows(data.items);
  const filtered = f.q || f.agent || f.level || f.rule || f.group || f.mitre || f.offset;
  if (!filtered) liveHandlers.add((a) => {
    alertIndex.set(String(a.id), a);
    const tb = $('#alert-list tbody');
    if (tb) tb.insertAdjacentHTML('afterbegin', alertRow(a, false, true));
    else render();
  });
}

async function viewAgents(arg, p) {
  if (arg) return viewAgent(arg, p);
  await loadAgents();
  setActions(`<button class="btn primary" id="deploy">+ Deploy new agent</button>`);
  $('#deploy').onclick = deployDrawer;
  view().innerHTML = AGENTS.length ? `<div class="card flush"><div class="table-wrap"><table>
    <thead><tr><th>ID</th><th>Name</th><th>IP</th><th>Operating system</th><th>Group</th><th>Version</th><th>Status</th><th>Last keepalive</th></tr></thead>
    <tbody>${AGENTS.map((a) => `<tr class="click" data-id="${esc(a.id)}"><td class="mono">${esc(a.id)}</td><td><b>${esc(a.name)}</b></td><td class="mono">${esc(a.ip)}</td>
      <td>${esc(a.os.name)} ${esc(a.os.version)} <span class="muted">${esc(a.os.arch)}</span></td><td><span class="pill">${esc(a.group)}</span></td><td class="mono">${esc(a.version)}</td>
      <td><span class="status ${esc(a.status)}">${esc(a.status.replace('_', ' '))}</span></td><td class="muted">${ago(a.last_seen)}</td></tr>`).join('')}</tbody></table></div></div>`
    : `<div class="card empty"><p>No endpoints enrolled yet.</p><button class="btn primary" id="deploy2">Deploy your first agent</button></div>`;
  if ($('#deploy2')) $('#deploy2').onclick = deployDrawer;
  view().onclick = (e) => { const tr = e.target.closest('tr[data-id]'); if (tr) location.hash = '#/agents/' + tr.dataset.id; };
}

async function deployDrawer() {
  const m = await api('/manager');
  const host = location.hostname;
  drawer(`<div class="stack"><h3 style="margin:0">Deploy a new agent</h3>
    <p class="muted">Build or download <code>warden-agent</code> for the endpoint, then run it with the enrollment password (stored on the manager in <code>data/enrollment-password.txt</code>).</p>
    <h2>Linux (systemd)</h2>
    <pre class="log">sudo install -m 0755 warden-agent /usr/local/bin/
sudo mkdir -p /etc/warden-agent
sudo tee /etc/warden-agent/agent.yml &lt;&lt;'EOF'
manager: ${esc(host)}:1514
enrollment_password: &lt;ENROLLMENT_PASSWORD&gt;
group: default
manager_fingerprint: ${esc(m.cert_fingerprint)}
EOF
sudo install -m 0644 deploy/warden-agent.service /etc/systemd/system/
sudo systemctl enable --now warden-agent</pre>
    <h2>One-off / container</h2>
    <pre class="log">WARDEN_MANAGER=${esc(host)}:1514 \\
WARDEN_ENROLLMENT_PASSWORD=&lt;ENROLLMENT_PASSWORD&gt; \\
WARDEN_MANAGER_FINGERPRINT=${esc(m.cert_fingerprint)} \\
sudo -E warden-agent</pre>
    <p class="muted">The fingerprint pins the manager's TLS certificate, so an attacker on the network can't impersonate the manager. Leave it out to trust the first certificate seen.</p></div>`);
}

async function viewAgent(id, p) {
  const tab = p.tab || 'alerts';
  const [a, groups] = await Promise.all([api('/agents/' + id), api('/groups')]);
  $('#page-title').textContent = a.name;
  setActions(`${['fim', 'inventory', 'sca', 'rootcheck'].map((s) => `<button class="btn small" data-cmd="${s}-scan">Scan ${s === 'fim' ? 'FIM' : s === 'sca' ? 'SCA' : s}</button>`).join('')}
    <button class="btn small" data-cmd="restart">Restart</button><button class="btn small danger" id="del-agent">Remove</button>`);
  $$('[data-cmd]').forEach((b) => (b.onclick = async () => { await api(`/agents/${id}/commands`, { method: 'POST', body: { name: b.dataset.cmd } }); toast(b.dataset.cmd + ' queued; the agent picks it up on its next heartbeat'); }));
  $('#del-agent').onclick = async () => { if (!confirm(`Remove agent ${a.name}? Its key is revoked and its data deleted.`)) return; await api('/agents/' + id, { method: 'DELETE' }); location.hash = '#/agents'; };
  const tabs = [['alerts', 'Alerts'], ['inventory', 'Inventory'], ['fim', 'File integrity'], ['sca', 'Configuration'], ['vulns', 'Vulnerabilities'], ['commands', 'Responses']];
  view().innerHTML = `
    <div class="card" style="margin-bottom:18px"><div class="grid g4">
      <div><div class="muted">Status</div><span class="status ${esc(a.status)}">${esc(a.status.replace('_', ' '))}</span> <span class="muted">· ${ago(a.last_seen)}</span></div>
      <div><div class="muted">Operating system</div>${esc(a.os.name)} ${esc(a.os.version)} <span class="muted mono">${esc(a.os.kernel)}</span></div>
      <div><div class="muted">Address · ID</div><span class="mono">${esc(a.ip)} · ${esc(a.id)}</span></div>
      <div><div class="muted">Group</div><select id="grp">${groups.map((g) => `<option ${g.name === a.group ? 'selected' : ''}>${esc(g.name)}</option>`).join('')}</select>
        <span class="muted mono" title="config hash reported by agent">${a.config_hash ? '✓ ' + esc(a.config_hash.slice(0, 8)) : ''}</span></div>
    </div></div>
    <div class="tabs">${tabs.map(([k, l]) => `<button data-tab="${k}" class="${k === tab ? 'active' : ''}">${l}</button>`).join('')}</div>
    <div id="tab"></div>`;
  $('#grp').onchange = async (e) => { await api(`/agents/${id}/group`, { method: 'PUT', body: { group: e.target.value } }); toast('Group changed; config is pushed on the next heartbeat'); };
  $$('[data-tab]').forEach((b) => (b.onclick = () => (location.hash = `#/agents/${id}?tab=${b.dataset.tab}`)));
  const el = $('#tab');
  if (tab === 'alerts') { const d = await api(`/alerts?agent=${id}&limit=50`); el.innerHTML = `<div class="card flush">${alertTable(d.items)}</div>`; bindAlertRows(d.items); }
  if (tab === 'inventory') await inventoryTab(el, id);
  if (tab === 'fim') { const d = await api('/fim?agent=' + id); el.innerHTML = `<div class="card flush">${fimTable(d)}</div>`; }
  if (tab === 'sca') { const d = await api('/sca?agent=' + id); el.innerHTML = scaBlocks(d); bindSCA(d); }
  if (tab === 'vulns') { const d = await api('/vulns?agent=' + id); el.innerHTML = `<div class="card flush">${vulnTable(d.items)}</div>`; }
  if (tab === 'commands') { const d = await api('/commands?agent=' + id); el.innerHTML = `<div class="card flush">${commandTable(d)}</div>`; }
}

async function inventoryTab(el, id) {
  let inv;
  try { inv = await api(`/agents/${id}/inventory`); } catch { el.innerHTML = `<div class="card">${empty('No inventory received yet')}</div>`; return; }
  const ports = inv.ports || [], procs = inv.processes || [], pkgs = inv.packages || [];
  el.innerHTML = `<div class="grid g2">
    <div class="card flush"><h2>Listening ports (${ports.length})</h2><div class="table-wrap"><table><thead><tr><th>Proto</th><th>Address</th><th>Port</th><th>Process</th></tr></thead>
      <tbody>${ports.map((x) => `<tr><td class="mono">${esc(x.protocol)}</td><td class="mono">${esc(x.local_ip)}</td><td class="mono">${esc(x.port)}</td><td>${esc(x.process)} <span class="muted mono">${x.pid ? esc(x.pid) : ''}</span></td></tr>`).join('')}</tbody></table></div></div>
    <div class="card flush"><h2>Network interfaces</h2><div class="table-wrap"><table><thead><tr><th>Name</th><th>MAC</th><th>Addresses</th></tr></thead>
      <tbody>${(inv.interfaces || []).map((x) => `<tr><td>${esc(x.name)}</td><td class="mono">${esc(x.mac)}</td><td class="mono">${(x.addresses || []).map(esc).join('<br>')}</td></tr>`).join('')}</tbody></table></div></div>
  </div>
  <div class="card flush" style="margin-top:16px"><h2>Packages (${pkgs.length}) <input id="pkgq" type="search" placeholder="Filter packages…" style="float:right;margin-top:-8px;text-transform:none;letter-spacing:0"></h2><div class="table-wrap" style="max-height:420px"><table><thead><tr><th>Name</th><th>Version</th><th>Arch</th><th>Format</th><th>Source</th></tr></thead><tbody id="pkgs"></tbody></table></div></div>
  <div class="card flush" style="margin-top:16px"><h2>Processes (${procs.length})</h2><div class="table-wrap" style="max-height:420px"><table><thead><tr><th>PID</th><th>PPID</th><th>User</th><th>Name</th><th>Command line</th></tr></thead>
    <tbody>${procs.map((x) => `<tr><td class="mono">${esc(x.pid)}</td><td class="mono">${esc(x.ppid)}</td><td>${esc(x.user)}</td><td>${esc(x.name)}</td><td class="log">${esc(x.cmdline)}</td></tr>`).join('')}</tbody></table></div></div>
  <p class="muted">Scanned ${esc(new Date(inv.scanned_at).toLocaleString())}</p>`;
  const draw = (q) => ($('#pkgs').innerHTML = pkgs.filter((x) => !q || x.name.includes(q)).slice(0, 500).map((x) => `<tr><td>${esc(x.name)}</td><td class="mono">${esc(x.version)}</td><td>${esc(x.arch)}</td><td>${esc(x.format)}</td><td class="muted">${esc(x.source)}</td></tr>`).join(''));
  draw('');
  $('#pkgq').oninput = (e) => draw(e.target.value.trim());
}

const fimTable = (rows) => (rows.length ? `<div class="table-wrap"><table><thead><tr><th>Path</th><th>Endpoint</th><th>Last event</th><th>SHA-256</th><th>Size</th><th>Mode</th><th>Owner</th><th>Changed</th></tr></thead>
  <tbody>${rows.map((f) => `<tr><td class="mono">${esc(f.path)}</td><td>${esc(agentName(f.agent_id))}</td><td><span class="pill ${f.last_event === 'deleted' ? 'bad' : f.last_event === 'modified' ? 'warn' : 'ok'}">${esc(f.last_event)}</span></td>
  <td class="mono muted" title="${esc(f.sha256)}">${esc((f.sha256 || '').slice(0, 16))}…</td><td class="mono">${num(f.size)}</td><td class="mono">${esc(f.mode)}</td><td class="mono">${esc(f.uid)}:${esc(f.gid)}</td><td class="muted nowrap">${ago(f.updated_at)}</td></tr>`).join('')}</tbody></table></div>`
  : empty('No file changes recorded yet. The first scan builds a baseline silently; later changes appear here.'));

async function viewFIM(_, p) {
  const d = await api('/fim?' + qs({ agent: p.agent || '', q: p.q || '' }));
  view().innerHTML = `<form class="filters" id="ff"><input type="search" name="q" placeholder="Filter by path…" value="${esc(p.q || '')}"><select name="agent">${agentOptions(p.agent)}</select><button class="btn primary">Apply</button></form>
    <div class="card flush">${fimTable(d)}</div>`;
  $('#ff').onsubmit = (e) => { e.preventDefault(); location.hash = '#/fim?' + qs(Object.fromEntries(new FormData(e.target))); };
}

const vulnTable = (items) => (items.length ? `<div class="table-wrap"><table><thead><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Package</th><th>Installed</th><th>Fixed in</th><th>Endpoint</th><th>Summary</th></tr></thead>
  <tbody>${items.map((v) => `<tr><td class="nowrap"><a class="mono" target="_blank" rel="noopener" href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.cve)}">${esc(v.cve)}</a></td>
  <td class="sev-${esc(v.severity)}">${esc(v.severity)}</td><td class="mono">${v.score ? esc(v.score.toFixed(1)) : '—'}</td><td>${esc(v.package)}</td><td class="mono">${esc(v.version)}</td><td class="mono">${esc(v.fixed || 'no fix yet')}</td>
  <td>${esc(agentName(v.agent_id))}</td><td class="muted" style="max-width:380px">${esc(v.summary)}</td></tr>`).join('')}</tbody></table></div>` : empty('No vulnerabilities detected'));

async function viewVulns(_, p) {
  const d = await api('/vulns?' + qs({ agent: p.agent || '', severity: p.severity || '' }));
  const all = p.severity ? null : d.items;
  const count = (s) => (all || []).filter((v) => v.severity === s).length;
  setActions(`<button class="btn" id="sync">Sync OSV feed</button>`);
  $('#sync').onclick = async (e) => {
    e.target.disabled = true; e.target.textContent = 'Syncing…';
    try { const r = await api('/vulns/sync', { method: 'POST', body: {} }); toast('Feed synced: ' + Object.entries(r.synced || {}).map(([k, v]) => `${k} ${v}`).join(', ')); render(); }
    catch (err) { toast('Sync failed: ' + err.message, true); e.target.disabled = false; e.target.textContent = 'Sync OSV feed'; }
  };
  view().innerHTML = `
    ${all ? `<div class="grid g4" style="margin-bottom:16px">${[['Critical', 'crit'], ['High', 'high'], ['Medium', ''], ['Low', '']].map(([s, c]) => `<a class="card stat ${c}" href="#/vulns?severity=${s}" style="text-decoration:none;color:inherit"><span class="label">${s}</span><span class="value">${count(s)}</span></a>`).join('')}</div>` : ''}
    <form class="filters" id="vf"><select name="agent">${agentOptions(p.agent)}</select><select name="severity"><option value="">Any severity</option>${['Critical', 'High', 'Medium', 'Low'].map((s) => `<option ${s === p.severity ? 'selected' : ''}>${s}</option>`).join('')}</select><button class="btn primary">Apply</button>
      <span class="muted" style="margin-left:auto">Feed: ${Object.entries(d.feed || {}).map(([k, v]) => `${esc(k)} (${num(v)})`).join(', ') || 'empty'}</span></form>
    <div class="card flush">${vulnTable(d.items)}</div>`;
  $('#vf').onsubmit = (e) => { e.preventDefault(); location.hash = '#/vulns?' + qs(Object.fromEntries(new FormData(e.target))); };
}

function scaBlocks(rows) {
  if (!rows.length) return `<div class="card">${empty('No SCA results yet')}</div>`;
  const groups = {};
  rows.forEach((r) => (groups[r.agent_id + '|' + r.policy_id] ||= []).push(r));
  return Object.entries(groups).map(([k, list]) => {
    const pass = list.filter((r) => r.result === 'passed').length, fail = list.filter((r) => r.result === 'failed').length;
    const score = Math.round((pass / Math.max(1, pass + fail)) * 100);
    return `<div class="card flush" style="margin-bottom:16px"><div style="padding:16px 18px;display:flex;gap:24px;align-items:center;flex-wrap:wrap">
      <div style="flex:1;min-width:240px"><div class="muted" style="font-size:12px">${esc(agentName(list[0].agent_id))} · ${esc(list[0].policy_id)}</div><div style="font-size:16px;font-weight:600">${esc(list[0].policy_name)}</div></div>
      <div><span class="pill ok">${pass} passed</span><span class="pill bad">${fail} failed</span><span class="pill">${list.length - pass - fail} n/a</span></div>
      <div style="width:220px"><div style="display:flex;justify-content:space-between;font-size:12px"><span class="muted">Score</span><b>${score}%</b></div><div class="progress"><div style="width:${score}%"></div></div></div></div>
      <div class="table-wrap"><table><thead><tr><th>ID</th><th>Check</th><th>Result</th><th>Compliance</th></tr></thead><tbody>
      ${list.map((r) => `<tr class="click" data-sca="${esc(k)}|${r.check_id}"><td class="mono">${esc(r.check_id)}</td><td>${esc(r.title)}</td>
      <td><span class="pill ${r.result === 'passed' ? 'ok' : r.result === 'failed' ? 'bad' : ''}">${esc(r.result)}</span></td>
      <td>${Object.entries(r.compliance || {}).slice(0, 3).map(([s, v]) => `<span class="pill">${esc(s)} ${esc(v.join(', '))}</span>`).join('')}</td></tr>`).join('')}</tbody></table></div></div>`;
  }).join('');
}
function bindSCA(rows) {
  view().onclick = (e) => {
    const tr = e.target.closest('tr[data-sca]');
    if (!tr) return;
    const [aid, pid, cid] = tr.dataset.sca.split('|');
    const r = rows.find((x) => x.agent_id === aid && x.policy_id === pid && String(x.check_id) === cid);
    drawer(`<div class="stack"><div class="muted mono">${esc(r.policy_id)} · check ${esc(r.check_id)}</div><h3 style="margin:0">${esc(r.title)}</h3>
      <div><span class="pill ${r.result === 'passed' ? 'ok' : 'bad'}">${esc(r.result)}</span> <span class="muted">${esc(agentName(r.agent_id))} · evaluated ${ago(r.updated_at)}</span></div>
      ${r.reason ? `<div><h2>Reason</h2><pre class="log">${esc(r.reason)}</pre></div>` : ''}
      <div><h2>Remediation</h2><p>${esc(r.remediation || '—')}</p></div>
      <div><h2>Compliance</h2>${Object.entries(r.compliance || {}).map(([s, v]) => v.map((x) => `<span class="pill">${esc(s)} ${esc(x)}</span>`).join('')).join('') || '—'}</div></div>`);
  };
}
async function viewSCA(_, p) {
  const d = await api('/sca?' + qs({ agent: p.agent || '' }));
  view().innerHTML = `<form class="filters" id="sf"><select name="agent">${agentOptions(p.agent)}</select><button class="btn primary">Apply</button></form>${scaBlocks(d)}`;
  $('#sf').onsubmit = (e) => { e.preventDefault(); location.hash = '#/sca?' + qs(Object.fromEntries(new FormData(e.target))); };
  bindSCA(d);
}

async function viewMitre(_, p) {
  const hours = Number(p.hours || 168);
  setActions(`<select id="mr">${[[24, 'Last 24h'], [168, 'Last 7 days'], [720, 'Last 30 days']].map(([v, l]) => `<option value="${v}" ${v === hours ? 'selected' : ''}>${l}</option>`).join('')}</select>`);
  $('#mr').onchange = (e) => (location.hash = '#/mitre?hours=' + e.target.value);
  const techs = await api('/mitre?hours=' + hours);
  const order = ['Reconnaissance', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Command and Control', 'Exfiltration', 'Impact'];
  const by = {};
  techs.forEach((t) => t.tactic.split(', ').forEach((tac) => (by[tac] ||= []).push(t)));
  const covered = techs.filter((t) => t.rules && t.rules.length).length;
  const hit = techs.filter((t) => t.alerts).length;
  view().innerHTML = `<p class="muted" style="margin-top:0">${covered} techniques covered by detection rules · ${hit} observed in this period. Click a technique to hunt its alerts.</p>
    <div class="matrix">${order.filter((o) => by[o]).map((tac) => `<div class="tactic"><h3>${esc(tac)}</h3>${by[tac].sort((a, b) => b.alerts - a.alerts).map((t) => `
      <div class="tech ${t.rules && t.rules.length ? 'covered' : ''} ${t.alerts > 20 ? 'hit-2' : t.alerts ? 'hit-1' : ''}" data-t="${esc(t.id)}" title="Rules: ${esc((t.rules || []).join(', ') || 'none')}">
        ${t.alerts ? `<span class="cnt">${num(t.alerts)}</span>` : ''}<div class="id">${esc(t.id)}</div>${esc(t.name)}</div>`).join('')}</div>`).join('')}</div>`;
  view().onclick = (e) => { const t = e.target.closest('[data-t]'); if (t) location.hash = '#/alerts?mitre=' + encodeURIComponent(t.dataset.t); };
}

const commandTable = (rows) => (rows.length ? `<div class="table-wrap"><table><thead><tr><th>#</th><th>Endpoint</th><th>Command</th><th>Target</th><th>Timeout</th><th>Origin</th><th>Status</th><th>Result</th><th>Queued</th></tr></thead>
  <tbody>${rows.map((c) => `<tr><td class="mono">${esc(c.id)}</td><td>${esc(agentName(c.agent_id))}</td><td class="mono">${esc(c.name)}</td><td class="mono">${esc((c.args || {}).target || '')}</td>
  <td class="mono">${c.timeout ? esc(c.timeout) + 's' : '—'}</td><td class="muted">${esc(c.origin)}</td><td><span class="pill ${c.status === 'done' ? 'ok' : c.status === 'failed' ? 'bad' : 'warn'}">${esc(c.status)}</span></td>
  <td class="log">${esc(c.result)}</td><td class="muted nowrap">${ago(c.created_at)}</td></tr>`).join('')}</tbody></table></div>` : empty('No responses executed yet'));

async function viewResponse() {
  await loadAgents();
  const rows = await api('/commands');
  view().innerHTML = `<div class="card" style="margin-bottom:16px"><h2>Run a response</h2>
    <form class="filters" id="rf" style="margin:0"><select name="agent" required>${agentOptions('', 'Choose endpoint…')}</select>
      <select name="name">${['firewall-drop', 'host-deny', 'kill-process', 'disable-account', 'fim-scan', 'inventory-scan', 'sca-scan', 'rootcheck-scan', 'restart'].map((c) => `<option>${c}</option>`).join('')}</select>
      <input name="target" placeholder="IP / PID / user"><input name="timeout" type="number" min="0" placeholder="Timeout (s)" style="width:130px">
      <button class="btn primary">Queue</button></form>
    <p class="muted" style="margin:10px 0 0">Rules with an <code>active_response</code> block queue these automatically, for example rule 5720 blocks SSH brute-force sources for 10 minutes. A timeout reverts the action.</p></div>
    <div class="card flush">${commandTable(rows)}</div>`;
  $('#rf').onsubmit = async (e) => {
    e.preventDefault();
    const d = Object.fromEntries(new FormData(e.target));
    if (!d.agent) return toast('Choose an endpoint', true);
    try { await api(`/agents/${d.agent}/commands`, { method: 'POST', body: { name: d.name, args: d.target ? { target: d.target } : {}, timeout: Number(d.timeout || 0) } }); toast('Queued'); render(); }
    catch (err) { toast(err.message, true); }
  };
}

async function viewRules(_, p) {
  const rules = await api('/rules');
  setActions(`<button class="btn" id="reload">Reload ruleset</button>`);
  $('#reload').onclick = async () => { try { const r = await api('/rules/reload', { method: 'POST' }); toast(`Reloaded: ${r.decoders} decoders, ${r.rules} rules`); render(); } catch (e) { toast(e.message, true); } };
  view().innerHTML = `
  <div class="card"><h2>Logtest</h2>
    <p class="muted" style="margin-top:0">Paste a log line to see how it is pre-decoded, decoded and which rule matches. Nothing is stored. Repeat a line to exercise frequency rules.</p>
    <form id="lt" class="stack"><textarea name="log" rows="3" placeholder="Nov 19 10:00:01 web1 sshd[811]: Failed password for root from 203.0.113.9 port 50122 ssh2">${esc(p.log || '')}</textarea>
      <div class="filters" style="margin:0"><button class="btn primary">Test</button></div></form><div id="lt-out"></div></div>
  <div class="card flush" style="margin-top:16px"><h2>Ruleset (${rules.length} rules) <input id="rq" type="search" placeholder="Filter by id, description, group or technique…" style="float:right;margin-top:-8px;width:340px;text-transform:none;letter-spacing:0"></h2>
    <div class="table-wrap"><table><thead><tr><th>ID</th><th>Lvl</th><th>Description</th><th>Groups</th><th>MITRE</th><th>Parent / correlation</th><th>File</th></tr></thead><tbody id="rt"></tbody></table></div></div>`;
  const draw = (q) => {
    q = q.toLowerCase();
    $('#rt').innerHTML = rules.filter((r) => !q || JSON.stringify([r.id, r.description, r.groups, r.mitre]).toLowerCase().includes(q)).map((r) => `<tr>
      <td class="mono">${esc(r.id)}</td><td>${lvl(r.level)}</td><td>${esc(r.description)}${r.active_response ? ` <span class="pill bad">AR: ${esc(r.active_response.command)}</span>` : ''}</td>
      <td>${(r.groups || []).map((g) => `<span class="pill">${esc(g)}</span>`).join('')}</td><td>${mitrePills(r.mitre)}</td>
      <td class="mono muted">${r.if_sid ? 'if_sid ' + esc(r.if_sid.join(',')) : ''}${r.if_matched_sid ? `${esc(r.frequency)}× ${esc(r.if_matched_sid)} / ${esc(r.timeframe)}s` : ''}${r.if_matched_group ? `${esc(r.frequency)}× group ${esc(r.if_matched_group)} / ${esc(r.timeframe)}s` : ''}</td>
      <td class="muted">${esc(r.file)}</td></tr>`).join('');
  };
  draw('');
  $('#rq').oninput = (e) => draw(e.target.value);
  $('#lt').onsubmit = async (e) => {
    e.preventDefault();
    const out = $('#lt-out');
    const lines = new FormData(e.target).get('log').split('\n').filter((l) => l.trim());
    let html = '';
    for (const line of lines) {
      const r = await api('/logtest', { method: 'POST', body: { log: line } });
      html += `<div class="grid g3" style="margin-top:14px">
        <div><h2>Phase 1 · pre-decoding</h2><div class="kv"><div>hostname</div><div class="mono">${esc(r.predecoded.hostname)}</div><div>program</div><div class="mono">${esc(r.predecoded.program)}</div></div></div>
        <div><h2>Phase 2 · decoding</h2><div class="kv"><div>decoder</div><div class="mono">${esc(r.decoder || '—')}</div>${Object.entries(r.fields || {}).map(([k, v]) => `<div>${esc(k)}</div><div class="mono">${esc(v)}</div>`).join('')}</div></div>
        <div><h2>Phase 3 · rule</h2>${r.rule ? `<div class="kv"><div>id</div><div class="mono">${esc(r.rule.id)}</div><div>level</div><div>${lvl(r.rule.level)}</div><div>description</div><div>${esc(r.rule.description)}</div><div>mitre</div><div>${mitrePills(r.rule.mitre)}</div><div>alert</div><div>${r.alert ? '<span class="pill bad">yes</span>' : '<span class="pill">no (below alert level)</span>'}</div></div>` : empty('No rule matched')}</div></div>`;
    }
    out.innerHTML = html;
  };
}

async function viewGroups() {
  const groups = await api('/groups');
  setActions(`<button class="btn" id="newg">+ New group</button>`);
  $('#newg').onclick = async () => {
    const name = prompt('Group name (letters, digits, . _ -)');
    if (!name) return;
    const base = (groups.find((g) => g.name === 'default') || {}).config || '';
    try { await api('/groups/' + encodeURIComponent(name), { method: 'PUT', body: { config: base } }); render(); } catch (e) { toast(e.message, true); }
  };
  view().innerHTML = groups.map((g) => `<div class="card" style="margin-bottom:16px"><h2 style="display:flex;justify-content:space-between">${esc(g.name)} <span class="muted" style="text-transform:none;letter-spacing:0">${g.agents} agents · hash ${esc(g.hash)}</span></h2>
    <textarea rows="18" style="width:100%" data-g="${esc(g.name)}">${esc(g.config)}</textarea>
    <div class="filters" style="margin:10px 0 0"><button class="btn primary" data-save="${esc(g.name)}">Save &amp; push to agents</button><span class="muted">Agents apply changes on their next heartbeat (~10s).</span></div></div>`).join('');
  $$('[data-save]').forEach((b) => (b.onclick = async () => {
    const ta = $(`textarea[data-g="${CSS.escape(b.dataset.save)}"]`);
    try { await api('/groups/' + encodeURIComponent(b.dataset.save), { method: 'PUT', body: { config: ta.value } }); toast('Saved'); render(); } catch (e) { toast(e.message, true); }
  }));
}

async function viewManager() {
  const m = await api('/manager');
  const up = m.uptime_sec, uptime = `${Math.floor(up / 86400)}d ${Math.floor((up % 86400) / 3600)}h ${Math.floor((up % 3600) / 60)}m`;
  view().innerHTML = `<div class="grid g4">
    <div class="card stat accent"><span class="label">Events processed</span><span class="value">${num(m.events_processed)}</span><span class="sub">since start</span></div>
    <div class="card stat"><span class="label">Alerts generated</span><span class="value">${num(m.alerts_generated)}</span><span class="sub">alert level ≥ ${esc(m.alert_level)}</span></div>
    <div class="card stat"><span class="label">Analysis queue</span><span class="value">${num(m.queue_len)}</span><span class="sub">capacity ${num(m.queue_cap)}</span></div>
    <div class="card stat ok"><span class="label">Uptime</span><span class="value" style="font-size:24px">${uptime}</span><span class="sub">version ${esc(m.version)}</span></div></div>
    <div class="card" style="margin-top:16px"><h2>Configuration</h2><div class="kv">
      <div>ruleset</div><div>${num(m.decoders)} decoders · ${num(m.rules)} rules</div>
      <div>tls fingerprint</div><div class="mono">${esc(m.cert_fingerprint)}</div>
      <div>active response</div><div>${m.active_response ? 'enabled' : 'disabled'}</div>
      <div>syslog receiver</div><div class="mono">${esc(m.syslog || 'disabled')}</div>
      <div>vulnerability feed</div><div>${Object.entries(m.feed || {}).map(([k, v]) => `${esc(k)}: ${num(v)}`).join('<br>') || 'empty'}</div></div></div>`;
}

// ---------------- boot ----------------
if (TOKEN) start(); else logout();
