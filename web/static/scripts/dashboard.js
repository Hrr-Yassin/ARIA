/* ═══════════════════════════════════════════════════════════════════════
   ARIA — Operations overview
   Reads the existing owner-scoped APIs. No fixture data, no simulated
   campaign state, no invented agent capabilities. All API-sourced text is
   rendered with textContent or createElementNS.
   ═══════════════════════════════════════════════════════════════════════ */
(function () {
'use strict';

const REFRESH_MS = 30000;
const PHASES = [
  { key: 'scope', label: 'Scope', aliases: ['scope'] },
  { key: 'reconnaissance', label: 'Reconnaissance', aliases: ['recon', 'reconnaissance'] },
  { key: 'scanning', label: 'Scanning', aliases: ['scan', 'scanning'] },
  { key: 'vulnerability_analysis', label: 'Vulnerability analysis', aliases: ['vuln', 'vulnerability_analysis'] },
  { key: 'exploitation', label: 'Exploitation', aliases: ['exploit', 'exploitation'] },
  { key: 'post_exploitation', label: 'Post-exploitation', aliases: ['post', 'post_exploitation'] },
  { key: 'reporting', label: 'Reporting', aliases: ['report', 'reporting'] },
];
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const TERMINAL_STATES = new Set(['completed', 'cancelled', 'stopped', 'failed']);

const state = {
  token: '',
  user: null,
  sessions: [],
  sessionId: '',
  data: {},
  warnings: [],
  loading: false,
  requestGeneration: 0,
  lastSync: 0,
  syncTimer: null,
  refreshTimer: null,
  autoRefresh: true,
  selectedNodeId: null,
  graphFilter: 'all',
  graphModel: null,
  timelineFilter: 'all',
  evidenceTab: 'findings',
  actionPending: false,
  resizeTimer: null,
  graphObserver: null,
};

const $ = (id) => document.getElementById(id);

// ── DOM construction ────────────────────────────────────────────────────
function h(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}
function clear(node) {
  if (!node) return;
  while (node.firstChild) node.removeChild(node.firstChild);
}
function setText(id, text) {
  const node = $(id);
  if (node) node.textContent = text === undefined || text === null ? '' : String(text);
}
function append(parent, ...children) {
  for (const child of children) {
    if (child) parent.appendChild(child);
  }
  return parent;
}
function svgEl(tag, attrs) {
  const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
  if (attrs) {
    for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, String(value));
  }
  return node;
}

// ── Formatting ──────────────────────────────────────────────────────────
const intFormatter = new Intl.NumberFormat('en-US');
function fmtInt(value) {
  const number = Number(value);
  return Number.isFinite(number) ? intFormatter.format(Math.max(0, Math.trunc(number))) : '0';
}
function fmtCompact(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return '0';
  if (number >= 1_000_000) return (number / 1_000_000).toFixed(number >= 10_000_000 ? 0 : 1) + 'm';
  if (number >= 1_000) return (number / 1_000).toFixed(number >= 10_000 ? 0 : 1) + 'k';
  return fmtInt(number);
}
function fmtUsdMicro(value) {
  if (!Number.isSafeInteger(value) || value < 0) return 'Unavailable';
  const amount = value / 1_000_000;
  return new Intl.NumberFormat('en-US', {
    style: 'currency', currency: 'USD',
    minimumFractionDigits: 2, maximumFractionDigits: 6,
  }).format(amount);
}
function pct(part, total) {
  const p = Number(part) || 0;
  const t = Number(total) || 0;
  if (t <= 0) return 0;
  return Math.max(0, Math.min(100, Math.round((p / t) * 1000) / 10));
}
function parseTime(value) {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value === 'number') {
    const date = new Date(value < 1e12 ? value * 1000 : value);
    return Number.isNaN(date.getTime()) ? null : date;
  }
  let text = String(value).trim();
  if (!text) return null;
  if (!/[zZ]$|[+-]\d\d:?\d\d$/.test(text)) {
    text = text.replace(' ', 'T') + 'Z';
  }
  const date = new Date(text);
  return Number.isNaN(date.getTime()) ? null : date;
}
function fmtClock(date) {
  if (!date) return '—';
  return new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' }).format(date);
}
function fmtDate(date) {
  if (!date) return '—';
  return new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short' }).format(date);
}
function fmtDateTime(date) {
  if (!date) return '—';
  return new Intl.DateTimeFormat(undefined, {
    day: 'numeric', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  }).format(date);
}
function relativeTime(date) {
  if (!date) return 'unknown time';
  const seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
  if (seconds < 45) return 'just now';
  if (seconds < 3600) return Math.floor(seconds / 60) + 'm ago';
  if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ago';
  if (seconds < 604800) return Math.floor(seconds / 86400) + 'd ago';
  return fmtDate(date);
}
function fmtDuration(seconds) {
  const value = Math.max(0, Number(seconds) || 0);
  if (value < 60) return Math.floor(value) + 's';
  if (value < 3600) return Math.floor(value / 60) + 'm';
  const hours = Math.floor(value / 3600);
  const minutes = Math.floor((value % 3600) / 60);
  return minutes ? hours + 'h ' + minutes + 'm' : hours + 'h';
}
function humanize(value) {
  if (value === null || value === undefined || value === '') return '';
  return String(value)
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/^[a-z]/, (letter) => letter.toUpperCase());
}
function shorten(value, limit) {
  const text = String(value || '').replace(/\s+/g, ' ').trim();
  return text.length > limit ? text.slice(0, Math.max(0, limit - 1)).trimEnd() + '…' : text;
}
function severityOf(value) {
  const key = String(value || '').toLowerCase();
  return SEVERITIES.includes(key) ? key : 'info';
}
function severityRank(value) { return SEVERITY_RANK[severityOf(value)]; }
function highestSeverity(counts) {
  for (const severity of SEVERITIES) {
    if (Number(counts?.[severity]) > 0) return severity;
  }
  return 'info';
}
function phaseIndex(value) {
  const key = String(value || '').toLowerCase();
  const index = PHASES.findIndex((phase) => phase.aliases.includes(key));
  return index >= 0 ? index : 0;
}
function phaseLabel(value) {
  return PHASES[phaseIndex(value)].label;
}
function normalizeUsage(value) {
  const fields = [
    'calls', 'reserved_tokens', 'reserved_cost_microusd',
    'reported_tokens', 'reported_cost_microusd',
    'unknown_usage_calls', 'unknown_cost_calls',
  ];
  const usage = {};
  for (const field of fields) {
    const number = Number(value?.[field]);
    usage[field] = Number.isFinite(number) && number >= 0 ? Math.trunc(number) : 0;
  }
  usage.stopped = Boolean(value?.stopped);
  usage.stop_reason = typeof value?.stop_reason === 'string' ? value.stop_reason : '';
  return usage;
}

// ── API ─────────────────────────────────────────────────────────────────
let unauthorizedHandled = false;
function handleUnauthorized() {
  if (unauthorizedHandled) return;
  unauthorizedHandled = true;
  localStorage.removeItem('pentestai_token');
  localStorage.removeItem('pentestai_user');
  localStorage.removeItem('current_session');
  window.location.href = '/login.html';
}

async function api(path, options = {}) {
  const started = typeof performance === 'undefined' ? null : performance.now();
  const headers = { 'Content-Type': 'application/json' };
  if (state.token) headers.Authorization = 'Bearer ' + state.token;
  let response;
  try {
    response = await fetch(path, {
      method: options.method || 'GET',
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
  } catch (error) {
    recordHttpTiming(started, null, path);
    const failure = new Error('The ARIA API is unreachable.');
    failure.cause = error;
    throw failure;
  }
  recordHttpTiming(started, response, path);
  if (response.status === 401) {
    handleUnauthorized();
    const expired = new Error('Your session expired.');
    expired.status = 401;
    throw expired;
  }
  if (options.allow404 && response.status === 404) return null;
  const contentType = response.headers.get('content-type') || '';
  const data = contentType.includes('application/json')
    ? await response.json().catch(() => ({}))
    : await response.text();
  if (!response.ok) {
    const detail = data && typeof data === 'object' ? data.detail : '';
    const failure = new Error(typeof detail === 'string' && detail ? detail : response.statusText || 'Request failed');
    failure.status = response.status;
    throw failure;
  }
  return data;
}

function recordHttpTiming(started, response, path) {
  if (started === null || typeof performance.measure !== 'function') return;
  const id = response?.headers?.get('x-request-id');
  const rawDuration = response?.headers?.get('x-aria-handler-ms');
  const handler = typeof rawDuration === 'string' && rawDuration.trim() !== '' && Number.isFinite(Number(rawDuration))
    && Number(rawDuration) >= 0 ? Number(rawDuration) : null;
  if (performance.getEntriesByName('aria.http.headers').length >= 64) performance.clearMeasures('aria.http.headers');
  performance.measure('aria.http.headers', {start: started, end: performance.now(), detail:{
    request_id: typeof id === 'string' && /^[a-f0-9]{32}$/.test(id) ? id : null,
    server_handler_ms: handler, status: response?.status ?? null,
    route: path.startsWith('/api/pentest/') ? 'mission' : path.startsWith('/api/team/') ? 'team'
      : path.startsWith('/api/session/') ? 'session' : 'other',
  }});
}

// ── Toasts ──────────────────────────────────────────────────────────────
function toast(kind, title, message) {
  const region = $('toast-region');
  if (!region) return;
  const node = h('div', 'toast');
  node.dataset.kind = kind || 'info';
  append(node, h('strong', null, title));
  if (message) node.appendChild(document.createTextNode(message));
  region.appendChild(node);
  window.setTimeout(() => {
    node.style.transition = 'opacity 180ms ease';
    node.style.opacity = '0';
    window.setTimeout(() => node.remove(), 190);
  }, 4200);
}

// ── Small composite pieces ──────────────────────────────────────────────
function meter(value, max, label) {
  const wrapper = h('div', 'meter');
  wrapper.setAttribute('role', 'progressbar');
  wrapper.setAttribute('aria-label', label || 'Usage');
  wrapper.setAttribute('aria-valuemin', '0');
  wrapper.setAttribute('aria-valuemax', '100');
  const percentage = pct(value, max);
  wrapper.setAttribute('aria-valuenow', String(percentage));
  if (percentage >= 100) wrapper.dataset.level = 'critical';
  else if (percentage >= 80) wrapper.dataset.level = 'warn';
  const fill = h('span');
  fill.style.width = percentage + '%';
  wrapper.appendChild(fill);
  return wrapper;
}
function budgetLine(label, valueText, value, max, note) {
  const block = h('div', 'budget-line');
  const head = h('div', 'budget-line-head');
  append(head, h('span', null, label), h('strong', null, valueText));
  block.appendChild(head);
  block.appendChild(meter(value, max, label));
  if (note) block.appendChild(h('div', 'budget-footnote', note));
  return block;
}
function kvRow(label, value) {
  const row = h('div', 'kv-row');
  append(row, h('span', null, label), h('strong', null, value));
  return row;
}
function emptyState(title, copy, action) {
  const wrap = h('div', 'empty-state');
  wrap.appendChild(h('h3', null, title));
  if (copy) wrap.appendChild(h('p', null, copy));
  if (action) {
    if (action.href) {
      const link = h('a', 'button button-secondary', action.label);
      link.href = action.href;
      wrap.appendChild(link);
    } else if (action.onClick) {
      const button = h('button', 'button button-secondary', action.label);
      button.type = 'button';
      button.addEventListener('click', action.onClick);
      wrap.appendChild(button);
    }
  }
  return wrap;
}
function emptyLedger(title, copy) {
  const wrap = h('div', 'empty-ledger');
  wrap.appendChild(h('span', 'empty-ledger-mark'));
  const text = h('div', 'empty-ledger-text');
  append(text, h('div', 'empty-ledger-title', title), h('div', 'empty-ledger-copy', copy));
  wrap.appendChild(text);
  return wrap;
}
function statePill(node, value, label) {
  if (!node) return;
  node.dataset.state = value || 'none';
  node.textContent = label;
}
function panelLoading(message) {
  return h('div', 'panel-loading', message || 'Reading live state…');
}

// ── Data accessors ──────────────────────────────────────────────────────
function sessionRecord() { return state.data.session || {}; }
function findingsList() {
  const findings = state.data.findings?.findings
    || state.data.restore?.findings
    || state.data.status?.findings
    || [];
  return Array.isArray(findings) ? findings.filter((item) => item && typeof item === 'object') : [];
}
function findingCounts() {
  const explicit = state.data.findings?.counts || state.data.restore?.counts || state.data.status?.counts;
  if (explicit && typeof explicit === 'object') return explicit;
  const counts = {};
  for (const finding of findingsList()) {
    const severity = severityOf(finding.severity);
    counts[severity] = (counts[severity] || 0) + 1;
  }
  return counts;
}
function teamData() {
  return state.data.team && typeof state.data.team === 'object' ? state.data.team : {};
}
function tasksList() {
  const tasks = teamData().tasks;
  return Array.isArray(tasks) ? tasks.filter((item) => item && typeof item === 'object') : [];
}
function evidenceList() {
  const evidence = teamData().evidence;
  return Array.isArray(evidence) ? evidence.filter((item) => item && typeof item === 'object') : [];
}
function verificationList() {
  const findings = state.data.verification?.findings;
  return Array.isArray(findings) ? findings.filter((item) => item && typeof item === 'object') : [];
}
function researchList() {
  const hypotheses = state.data.research?.hypotheses;
  return Array.isArray(hypotheses) ? hypotheses : [];
}
function researchLabel(item) {
  if (item.confirmed === true && item.context_current === true) return 'Independently verified with human signoff';
  return 'Unverified hypothesis / recorded ' + humanize(item.state || 'unknown')
    + (item.context_current === false ? ' / context stale' : '');
}
function verificationLabel(item) {
  return item.ready_for_external_submission === true && item.verification_current === true
    ? 'Independently verified with human signoff'
    : 'Unverified or requires revalidation / recorded ' + humanize(item.state || 'unknown');
}
function campaignData() { return state.data.campaign || null; }
function healthData() { return state.data.campaignHealth || null; }
function autoStatus() { return state.data.autonomous || null; }
function modelBudget() {
  return state.data.budget && typeof state.data.budget === 'object' ? state.data.budget : null;
}
function sortedFindings() {
  return findingsList().slice().sort((a, b) => {
    const severity = severityRank(a.severity) - severityRank(b.severity);
    if (severity) return severity;
    const cvss = (Number(b.cvss_score) || 0) - (Number(a.cvss_score) || 0);
    if (cvss) return cvss;
    return String(b.created_at || '').localeCompare(String(a.created_at || ''));
  });
}

// ── Hero & phase ────────────────────────────────────────────────────────
function missionSummary(auto, available = true) {
  if (!available) return 'Mission state unavailable; the current run could not be refreshed.';
  const mission = auto && auto.mission;
  if (!mission || typeof mission !== 'object') {
    return auto && (auto.run_id || auto.run_state)
      ? 'Last autonomous cycle: ' + humanize(auto.run_state || 'recorded') + '.'
      : 'No autonomous cycle recorded for this engagement.';
  }
  const parts = ['Bounded cycle: ' + humanize(auto.run_state || 'unknown') + '.',
    'Mission for current objective: ' + humanize(mission.state || 'unknown') + '.'];
  parts.push(Array.isArray(mission.pending_tasks)
    ? 'Pending team tasks: ' + mission.pending_tasks.length + '.'
    : 'Pending team task count unavailable.');
  if (mission.reason) parts.push(mission.reason);
  if (mission.objective) parts.push('Objective: ' + mission.objective);
  return parts.join(' ');
}

function questionReadiness(status) {
  const r = status?.progress?.readiness;
  if (!r || !['ready', 'not_ready'].includes(r.state)
      || !Number.isSafeInteger(r.questions_total) || r.questions_total <= 0
      || !Number.isSafeInteger(r.questions_tested) || r.questions_tested < 0
      || r.questions_tested > r.questions_total
      || typeof r.percent !== 'number' || !Number.isFinite(r.percent)
      || r.percent !== Math.round(100 * r.questions_tested / r.questions_total)) return null;
  return r.percent;
}

function renderHero() {
  const session = sessionRecord();
  const status = state.data.status || {};
  const campaign = campaignData();
  const auto = autoStatus();
  const hasSession = Boolean(state.sessionId && (session.session_id || state.data.restore));

  setText('engagement-title', hasSession ? (session.name || 'Untitled engagement') : 'No engagement selected');
  setText('hero-target', hasSession ? (session.target || 'No target recorded') : 'Create an engagement in the workspace');
  setText('hero-scope', hasSession ? scopeSummary(session, state.data.restore) : 'No scope recorded');
  const created = parseTime(session.created_at);
  setText('hero-created', created ? 'Created ' + fmtDate(created) : 'Creation date unavailable');
  setText('hero-note', hasSession
    ? (campaign
      ? 'Supervisor state is read from the durable campaign.'
      : missionSummary(auto, state.data.autonomous !== null))
    : 'The overview reads real session data. Create an engagement to begin.');

  if (campaign) {
    statePill($('hero-state'), campaign.state || 'unknown', humanize(campaign.state || 'Unknown'));
  } else if (auto && auto.run_id) {
    statePill($('hero-state'), auto.run_state || 'idle', 'Last cycle ' + humanize(auto.run_state || 'recorded').toLowerCase());
  } else {
    statePill($('hero-state'), 'none', 'No campaign');
  }

  const phaseInfo = status.phase_info || {};
  const currentPhase = phaseInfo.current_phase || status.phase || session.phase || 'scope';
  const index = Number.isFinite(Number(phaseInfo.phase_index))
    ? Math.max(0, Math.min(PHASES.length - 1, Number(phaseInfo.phase_index)))
    : phaseIndex(currentPhase);
  setText('phase-index', String(index + 1).padStart(2, '0') + ' / ' + String(PHASES.length));
  setText('phase-name', hasSession ? phaseLabel(currentPhase) : 'No phase');

  const rail = $('phase-rail');
  if (rail) {
    clear(rail);
    const labels = PHASES.map((phase, i) => {
      const stateName = i < index ? 'earlier; completion unreported' : i === index ? 'current' : 'upcoming';
      return phase.label + ': ' + stateName;
    });
    rail.setAttribute('aria-label', 'Phase progress. ' + labels.join('. '));
    PHASES.forEach((phase, i) => {
      const tick = h('span', 'phase-tick');
      tick.dataset.state = i < index ? 'earlier' : i === index ? 'current' : 'upcoming';
      tick.title = phase.label + (i < index ? ' (earlier; completion unreported)' : i === index ? ' (current)' : '');
      rail.appendChild(tick);
    });
  }

  const value = hasSession ? questionReadiness(status) : null;
  setText('phase-readiness', value === null ? 'Unavailable' : value + '%');
  const meterNode = $('phase-readiness-meter');
  if (meterNode) {
    if (value === null) meterNode.removeAttribute('aria-valuenow');
    else meterNode.setAttribute('aria-valuenow', String(value));
    meterNode.setAttribute('aria-valuetext', value === null ? 'Question readiness unavailable' : value + '% of recorded questions tested');
    const fill = $('phase-readiness-bar');
    if (fill) fill.style.width = (value ?? 0) + '%';
  }

  const live = campaign && ['starting', 'running', 'pausing', 'cancelling'].includes(String(campaign.state || '').toLowerCase());
  const beacon = document.querySelector('.phase-beacon');
  if (beacon) beacon.classList.toggle('is-live', Boolean(live || auto?.active));
}

function scopeSummary(session, restored) {
  const scope = session.scope || {};
  const targets = Array.isArray(scope.targets) ? scope.targets.length : (session.target ? 1 : 0);
  const ports = Array.isArray(scope.ports) ? scope.ports.length : (Array.isArray(session.open_ports) ? session.open_ports.length : 0);
  const exclusions = Array.isArray(scope.exclusions) ? scope.exclusions.length : 0;
  const parts = [targets + (targets === 1 ? ' target' : ' targets'), ports + (ports === 1 ? ' port' : ' ports')];
  if (exclusions) parts.push(exclusions + (exclusions === 1 ? ' exclusion' : ' exclusions'));
  if (session.context_type) parts.push(humanize(session.context_type));
  if (restored?.tools_run?.length) parts.push('Tools: ' + restored.tools_run.join(', '));
  return parts.join(' / ');
}

// ── Signal strip ────────────────────────────────────────────────────────
function renderMetrics() {
  const findings = findingsList();
  const counts = findingCounts();
  const total = Number(state.data.findings?.total ?? state.data.restore?.total ?? findings.length ?? 0);
  const verified = findings.filter((finding) => finding.human_verified === true).length;
  const severitySummary = SEVERITIES
    .filter((severity) => Number(counts?.[severity]) > 0)
    .map((severity) => fmtInt(counts[severity]) + ' ' + severity)
    .join(', ');
  setText('metric-findings', state.data.findings || state.data.restore || state.data.status ? fmtInt(total) : '—');
  setText('metric-findings-note', state.data.findings || state.data.restore || state.data.status
    ? (severitySummary ? severitySummary + ', ' + verified + ' verified' : 'No findings recorded')
    : 'Findings unavailable');

  const session = sessionRecord();
  const services = Array.isArray(session.open_ports) ? session.open_ports.length : Number(state.data.restore?.ports_count) || 0;
  const tools = Array.isArray(session.tools_run) ? session.tools_run : (state.data.restore?.tools_run || []);
  setText('metric-services', state.data.session || state.data.restore ? fmtInt(services) : '—');
  setText('metric-services-note', tools.length ? 'Tools run: ' + tools.join(', ') : 'No tools recorded');

  const tasks = tasksList();
  const activeStates = new Set(['queued', 'running', 'awaiting_review']);
  const active = tasks.filter((task) => activeStates.has(task.state)).length;
  const review = tasks.filter((task) => task.state === 'awaiting_review').length;
  setText('metric-tasks', state.data.team ? fmtInt(tasks.length) : '—');
  setText('metric-tasks-note', state.data.team
    ? (tasks.length ? active + ' active, ' + review + ' awaiting review' : 'No delegated tasks')
    : 'Task ledger unavailable');

  const evidence = evidenceList();
  const verifiedTeam = verificationList().filter((item) => item.ready_for_external_submission === true && item.verification_current === true).length;
  setText('metric-evidence', state.data.team ? fmtInt(evidence.length) : '—');
  setText('metric-evidence-note', state.data.team
    ? (evidence.length ? verifiedTeam + ' independently verified, ' + evidence.length + ' observations' : 'No catalogued evidence')
    : 'Evidence ledger unavailable');

  const budget = modelBudget();
  const usage = normalizeUsage(budget?.usage);
  const limits = budget?.limits || {};
  const maxCalls = Number(limits.max_calls);
  const calls = Number(usage.calls) || 0;
  setText('metric-calls', budget ? fmtInt(calls) : '—');
  setText('metric-calls-unit', budget && Number.isFinite(maxCalls) && maxCalls > 0 ? 'of ' + fmtInt(maxCalls) : 'recorded');
  setText('metric-calls-note', budget
    ? (calls || usage.reserved_tokens ? fmtCompact(usage.reserved_tokens) + ' tokens reserved' : 'No provider usage recorded')
    : 'Model budget unavailable');
}

// ── Campaign supervision ────────────────────────────────────────────────
function blockerRows(auto) {
  const blocker = auto?.mission?.blocker;
  if (!blocker || typeof blocker !== 'object') return [];
  return [
    ['Reason code', blocker.reason_code || 'Unavailable'],
    ['Status', humanize(blocker.status || 'unknown')],
    ['Component', humanize(blocker.component || 'unknown')],
    ['Explanation', blocker.explanation || 'Unavailable'],
    ['Operator action', blocker.operator_action || 'Review the recorded state before resuming.'],
  ];
}

function renderCampaign() {
  const body = $('campaign-body');
  if (!body) return;
  clear(body);
  const campaign = campaignData();
  const health = healthData();
  const auto = autoStatus();
  if (auto?.timings) {
    const timing = h('div', 'campaign-alerts');
    timing.appendChild(h('h3', null, 'Mission state timings'));
    for (const [label, key] of [['Run status load', 'run_status_load_ms'],
      ['Owned task ledger load', 'task_ledger_load_ms'], ['Mission projection', 'mission_projection_ms']]) {
      timing.appendChild(kvRow(label, measuredValue(auto.timings[key], ' ms')));
    }
    body.appendChild(timing);
  }
  const rows = blockerRows(auto);
  if (rows.length) {
    const panel = h('div', 'campaign-alerts');
    panel.appendChild(h('h3', null, 'Mission blocker'));
    rows.forEach(([label, value]) => panel.appendChild(kvRow(label, value)));
    body.appendChild(panel);
  }

  if (state.loading && !campaign && !state.data.session) {
    body.appendChild(panelLoading('Reading campaign state…'));
    statePill($('campaign-state'), 'none', 'Loading');
    return;
  }

  if (!campaign) {
    statePill($('campaign-state'), 'none', 'No campaign');
    body.appendChild(emptyState(
      'No supervised campaign',
      'This engagement has no durable campaign. Start one from the workspace to record scheduling, model budget, retries and supervisor heartbeat here.',
      { label: 'Open workspace', href: '/' }
    ));
    const autoHasState = auto && (auto.run_id || auto.run_state);
    if (autoHasState) {
      const legacy = h('div', 'legacy-run');
      legacy.appendChild(h('h3', null, 'Last autonomous cycle'));
      const run = auto.run || auto;
      const rows = [
        ['State', humanize(run.run_state || auto.run_state || 'recorded')],
        ['Goal', humanize(run.goal || auto.goal || '—')],
        ['Steps', fmtInt(run.steps_taken || auto.steps_taken || 0) + ' of ' + fmtInt(run.max_steps || auto.max_steps || 0)],
      ];
      if (run.reason || auto.reason) rows.push(['Reason', shorten(run.reason || auto.reason, 160)]);
      rows.forEach(([label, value]) => legacy.appendChild(kvRow(label, value)));
      body.appendChild(legacy);
    }
    return;
  }

  const stateName = String(campaign.state || 'unknown').toLowerCase();
  statePill($('campaign-state'), stateName, humanize(stateName));
  const run = campaign.run || health?.run || {};
  const progress = health?.progress || {};
  const stepsTaken = Number(progress.steps_taken ?? run.steps_taken ?? 0) || 0;
  const successful = Number(progress.successful_steps ?? run.successful_steps ?? 0) || 0;
  const maxSteps = Number(progress.max_steps ?? run.max_steps ?? campaign.max_steps ?? 0) || 0;
  const modelCalls = Number(progress.model_calls ?? run.model_calls ?? 0) || 0;
  const retry = campaign.retry || health?.failures || {};

  const summary = h('div', 'campaign-summary');
  append(summary,
    h('strong', null, fmtInt(stepsTaken) + ' / ' + fmtInt(maxSteps)),
    h('span', null, 'steps attempted this run'));
  const goal = h('span', null, 'Goal: ' + humanize(campaign.goal || '—'));
  summary.appendChild(goal);
  const risk = h('span', null, 'Risk: ' + humanize(campaign.auto_risk_threshold || '—'));
  summary.appendChild(risk);
  if (campaign.invalid) summary.appendChild(h('span', 'campaign-reason', 'Durable state is invalid; the supervisor will not act.'));
  else if (campaign.reason) summary.appendChild(h('span', 'campaign-reason', shorten(campaign.reason, 180)));
  body.appendChild(summary);

  const progressBlock = h('div', 'campaign-progress-block');
  const progressHead = h('div', 'campaign-progress-head');
  append(progressHead, h('h3', null, 'Run progress'), h('span', null, 'steps ' + fmtInt(stepsTaken) + ' of ' + fmtInt(maxSteps)));
  progressBlock.appendChild(progressHead);
  if (maxSteps > 0 && maxSteps <= 24) {
    const segments = h('div', 'segmented-meter');
    segments.setAttribute('role', 'img');
    segments.setAttribute('aria-label', successful + ' successful steps of ' + maxSteps);
    for (let i = 0; i < maxSteps; i += 1) {
      const segment = h('span');
      if (i < stepsTaken) segment.dataset.state = 'done';
      else if (i === stepsTaken && !TERMINAL_STATES.has(stateName)) segment.dataset.state = 'current';
      segments.appendChild(segment);
    }
    progressBlock.appendChild(segments);
  } else {
    progressBlock.appendChild(meter(stepsTaken, maxSteps, 'Run progress'));
  }
  const counters = h('div', 'campaign-counters');
  [
    ['Successful', successful],
    ['Model calls', modelCalls],
    ['Retries', Number(retry.count ?? health?.failures?.count ?? 0) || 0],
    ['Runtime', fmtDuration(health?.runtime?.total_seconds ?? campaign.runtime?.total_seconds ?? 0)],
  ].forEach(([label, value]) => {
    const counter = h('span', 'campaign-counter');
    append(counter, h('strong', null, String(value)), h('span', null, label));
    counters.appendChild(counter);
  });
  progressBlock.appendChild(counters);
  body.appendChild(progressBlock);

  const split = h('div', 'campaign-split');
  const supervisor = h('div', 'campaign-column');
  supervisor.appendChild(h('h3', null, 'Supervisor'));
  const heartbeat = health?.heartbeat || {};
  const lastHeartbeat = parseTime(heartbeat.last_heartbeat_at || campaign.supervisor?.last_heartbeat_at);
  supervisor.appendChild(kvRow('Last heartbeat', lastHeartbeat ? relativeTime(lastHeartbeat) : 'None recorded'));
  supervisor.appendChild(kvRow('Lease', heartbeat.lease_held ? (heartbeat.lease_expired ? 'Expired' : 'Held') : 'Not held'));
  const nextExecution = parseTime(health?.next_execution_at || campaign.next_execution_at);
  supervisor.appendChild(kvRow('Next action', nextExecution ? fmtDateTime(nextExecution) : 'None scheduled'));
  const windowInfo = campaign.schedule || {};
  supervisor.appendChild(kvRow('Window', windowInfo.within_window === undefined ? 'Not reported' : (windowInfo.within_window ? 'Open' : 'Outside window')));
  supervisor.appendChild(kvRow('Auto-resume', campaign.auto_resume ? 'Enabled' : 'Disabled'));

  const budgetColumn = h('div', 'campaign-column');
  budgetColumn.appendChild(h('h3', null, 'Campaign budget'));
  const budget = health?.budget || campaign.budget || {};
  const reservedTokens = Number(budget.reserved_tokens ?? budget.reported_tokens ?? 0) || 0;
  const maxTokens = Number(budget.max_tokens ?? 0) || 0;
  const reservedCost = Number(budget.reserved_cost_microusd ?? 0) || 0;
  const maxCost = Number(budget.max_cost_microusd ?? 0) || 0;
  budgetColumn.appendChild(budgetLine('Tokens reserved', fmtCompact(reservedTokens) + ' / ' + fmtCompact(maxTokens), reservedTokens, maxTokens));
  budgetColumn.appendChild(budgetLine('Cost ceiling', fmtUsdMicro(reservedCost) + ' / ' + fmtUsdMicro(maxCost), reservedCost, maxCost));
  if (budget.stopped) {
    const stopped = h('div', 'alert-row');
    stopped.dataset.severity = 'critical';
    stopped.appendChild(h('div', null, 'Accounting is stopped: ' + humanize(budget.stop_reason || 'unknown reason') + '.'));
    budgetColumn.appendChild(stopped);
  }
  split.append(supervisor, budgetColumn);
  body.appendChild(split);

  const alerts = Array.isArray(health?.alerts) ? health.alerts : [];
  const alertBlock = h('div', 'campaign-alerts');
  alertBlock.appendChild(h('h3', null, alerts.length ? 'Operational alerts' : 'Operational alerts'));
  if (alerts.length) {
    for (const alert of alerts) {
      const row = h('div', 'alert-row');
      row.dataset.severity = String(alert.severity || 'info');
      const content = h('div');
      const meta = h('div', 'alert-meta');
      append(meta, h('strong', null, humanize(alert.severity || 'info')), h('span', null, humanize(alert.code || 'alert')));
      content.appendChild(meta);
      content.appendChild(h('div', 'alert-copy', alert.detail || 'No detail recorded.'));
      row.appendChild(content);
      alertBlock.appendChild(row);
    }
  } else {
    alertBlock.appendChild(h('div', 'budget-empty', 'No operational alerts are recorded for this campaign.'));
  }
  body.appendChild(alertBlock);

  const controls = h('div', 'campaign-controls');
  const canPause = ['starting', 'running', 'scheduled'].includes(stateName);
  const canResume = stateName === 'paused';
  const canCancel = !TERMINAL_STATES.has(stateName);
  if (canPause) controls.appendChild(actionButton('Pause', 'pause', false));
  if (canResume) controls.appendChild(actionButton('Resume', 'resume', false));
  if (canCancel) controls.appendChild(actionButton('Cancel campaign', 'cancel', true));
  if (controls.children.length) {
    controls.appendChild(h('span', 'campaign-control-note', 'These controls call the existing campaign supervisor. They do not grant execution.'));
    body.appendChild(controls);
  }
}

function actionButton(label, action, danger) {
  const button = h('button', 'button ' + (danger ? 'button-danger' : 'button-secondary'), label);
  button.type = 'button';
  button.disabled = state.actionPending;
  button.addEventListener('click', () => campaignAction(action));
  return button;
}

async function campaignAction(action) {
  if (state.actionPending || !state.sessionId) return;
  if (action === 'cancel' && !window.confirm('Cancel this campaign? This stops the supervisor and cannot be undone.')) return;
  state.actionPending = true;
  renderCampaign();
  try {
    await api('/api/pentest/' + encodeURIComponent(state.sessionId) + '/campaign/' + action, { method: 'POST' });
    toast('success', humanize(action) + ' accepted', 'The supervisor accepted the request.');
    await loadAll();
  } catch (error) {
    toast('error', 'Campaign action failed', error.message);
    state.actionPending = false;
    renderCampaign();
  }
}

// ── Agent activity ──────────────────────────────────────────────────────
function renderAgents() {
  const body = $('agents-body');
  if (!body) return;
  clear(body);
  const tasks = tasksList();
  setText('agents-count', fmtInt(tasks.length));

  if (state.loading && !state.data.team) {
    body.appendChild(panelLoading('Reading specialist tasks…'));
    return;
  }
  if (!state.data.team) {
    body.appendChild(emptyState('Task ledger unavailable', 'The team task API did not return a readable response.'));
    return;
  }
  if (!tasks.length) {
    body.appendChild(emptyState(
      'No specialist tasks recorded',
      'Tasks delegated from the workspace appear here with their owner role, review state, attempts and model budget.'
    ));
    return;
  }

  const activeStates = ['queued', 'running', 'awaiting_review', 'blocked'];
  const counts = {};
  for (const stateName of activeStates) counts[stateName] = 0;
  for (const task of tasks) {
    const key = String(task.state || 'unknown');
    if (counts[key] !== undefined) counts[key] += 1;
  }
  const lanes = h('div', 'agent-states');
  activeStates.forEach((stateName) => {
    const lane = h('div', 'agent-state');
    lane.dataset.state = stateName;
    const label = h('span', 'agent-state-label');
    append(label, h('span', 'state-dot'), document.createTextNode(humanize(stateName)));
    append(lane, label, h('div', 'agent-state-value', fmtInt(counts[stateName])));
    lanes.appendChild(lane);
  });
  body.appendChild(lanes);

  const sorted = tasks.slice().sort((a, b) => {
    const rank = (task) => {
      const value = String(task.state || '');
      if (value === 'running') return 0;
      if (value === 'awaiting_review') return 1;
      if (value === 'queued') return 2;
      if (value === 'blocked') return 3;
      return 4;
    };
    const order = rank(a) - rank(b);
    if (order) return order;
    return String(b.created_at || '').localeCompare(String(a.created_at || ''));
  });
  const list = h('ul', 'agent-list');
  for (const task of sorted.slice(0, 6)) {
    const item = h('li', 'agent-item');
    const head = h('div', 'agent-item-head');
    const role = h('span', 'agent-role', humanize(task.owner_role || task.owner || 'specialist'));
    const chip = h('span', 'agent-state-chip', humanize(task.state || 'unknown'));
    chip.dataset.state = String(task.state || 'unknown');
    append(head, role, chip);
    item.appendChild(head);
    item.appendChild(h('div', 'agent-objective', shorten(task.objective || task.expected_output || 'No objective recorded', 190)));
    const meta = h('div', 'agent-meta');
    const attempts = Number(task.attempts) || 0;
    const calls = Number(task.budget?.max_model_calls);
    meta.appendChild(h('span', null, attempts + ' attempt' + (attempts === 1 ? '' : 's')));
    if (Number.isFinite(calls)) meta.appendChild(h('span', null, 'Model limit ' + calls));
    if (task.specialty) meta.appendChild(h('span', null, humanize(task.specialty)));
    meta.appendChild(h('span', null, 'Task ' + String(task.id || task.task_id || 'unknown').slice(0, 8)));
    item.appendChild(meta);
    list.appendChild(item);
  }
  body.appendChild(list);
  if (sorted.length > 6) {
    body.appendChild(h('div', 'budget-footnote', (sorted.length - 6) + ' more task' + (sorted.length - 6 === 1 ? '' : 's') + ' recorded.'));
  }
}

// ── Investigation graph ─────────────────────────────────────────────────
function renderGraphFilters() {
  const filters = $('graph-filters');
  if (!filters) return;
  clear(filters);
  const counts = {};
  for (const severity of SEVERITIES) counts[severity] = 0;
  for (const finding of findingsList()) counts[severityOf(finding.severity)] += 1;
  const total = findingsList().length;
  if (!total) return;
  const all = h('button', 'filter-button', 'All');
  all.type = 'button';
  all.setAttribute('aria-pressed', String(state.graphFilter === 'all'));
  const allCount = h('span', 'filter-count', fmtInt(total));
  all.appendChild(allCount);
  all.addEventListener('click', () => setGraphFilter('all'));
  filters.appendChild(all);
  for (const severity of SEVERITIES) {
    if (!counts[severity]) continue;
    const button = h('button', 'filter-button', humanize(severity));
    button.type = 'button';
    button.setAttribute('aria-pressed', String(state.graphFilter === severity));
    button.appendChild(h('span', 'filter-count', fmtInt(counts[severity])));
    button.addEventListener('click', () => setGraphFilter(severity));
    filters.appendChild(button);
  }
}

function setGraphFilter(filter) {
  state.graphFilter = filter;
  if (state.selectedNodeId && String(state.selectedNodeId).startsWith('finding-')) {
    const selected = graphNodeById(state.selectedNodeId);
    if (selected && selected.severity && filter !== 'all' && selected.severity !== filter) {
      state.selectedNodeId = null;
    }
  }
  renderGraphFilters();
  renderGraph();
}

function filteredFindings() {
  const findings = sortedFindings();
  if (state.graphFilter === 'all') return findings;
  return findings.filter((finding) => severityOf(finding.severity) === state.graphFilter);
}

function buildGraphModel(width) {
  const session = sessionRecord();
  const target = session.target || '';
  const services = Array.isArray(session.open_ports)
    ? session.open_ports.filter((port) => port && port.port !== undefined).slice(0, 10)
    : [];
  let findings = filteredFindings();
  const limit = width < 560 ? 9 : 16;
  const hidden = Math.max(0, findings.length - limit);
  findings = findings.slice(0, limit);
  const nodes = [{
    id: 'target',
    kind: 'target',
    label: target || 'Engagement',
    sub: 'Target',
    full: target || 'Engagement target',
    severity: '',
    data: session,
  }];
  const edges = [];
  services.forEach((service, index) => {
    const id = 'service-' + String(service.port);
    nodes.push({
      id,
      kind: 'service',
      label: String(service.port) + ' ' + (service.service || 'service'),
      sub: shorten(service.version || 'Open service', 28),
      full: String(service.port) + '/' + String(service.service || 'tcp'),
      severity: '',
      data: service,
      index,
    });
    edges.push({ from: 'target', to: id });
  });
  const servicePorts = new Map(services.map((service) => [String(service.port), 'service-' + String(service.port)]));
  findings.forEach((finding, index) => {
    const id = 'finding-' + String(finding.id || index);
    const severity = severityOf(finding.severity);
    nodes.push({
      id,
      kind: 'finding',
      label: shorten(finding.title || 'Finding', 28),
      sub: humanize(severity) + (finding.cvss_score ? ', CVSS ' + finding.cvss_score : ''),
      full: finding.title || 'Finding',
      severity,
      data: finding,
      index,
    });
    edges.push({ from: 'target', to: id });
    const evidence = String(finding.evidence || '');
    for (const [port, serviceId] of servicePorts.entries()) {
      if (evidence.includes(port + '/') || evidence.includes(':' + port)) {
        edges.push({ from: serviceId, to: id });
        break;
      }
    }
  });
  return { nodes, edges, hidden, services: services.length, findings: findings.length };
}

function graphNodeById(id) {
  return state.graphModel?.nodes.find((node) => node.id === id) || null;
}

function renderGraph() {
  const svg = $('graph-svg');
  const stage = $('graph-stage');
  if (!svg || !stage) return;
  clear(svg);
  const width = Math.max(300, Math.round(svg.getBoundingClientRect().width || stage.getBoundingClientRect().width || 620));
  const height = Math.max(340, Math.round(svg.getBoundingClientRect().height || 410));
  svg.setAttribute('viewBox', '0 0 ' + width + ' ' + height);
  svg.setAttribute('width', String(width));
  svg.setAttribute('height', String(height));

  if (!state.sessionId) {
    state.graphModel = null;
    const text = svgEl('text', { x: width / 2, y: height / 2, 'text-anchor': 'middle', fill: '#7c9186', 'font-size': 12 });
    text.textContent = 'No engagement selected';
    svg.appendChild(text);
    renderGraphDetail();
    renderGraphLegend();
    return;
  }

  const model = buildGraphModel(width);
  state.graphModel = model;
  const nodeMap = new Map(model.nodes.map((node) => [node.id, node]));
  const centerX = width / 2;
  const centerY = height / 2;
  const target = nodeMap.get('target');
  target.x = centerX;
  target.y = centerY;

  const serviceNodes = model.nodes.filter((node) => node.kind === 'service');
  const findingNodes = model.nodes.filter((node) => node.kind === 'finding');
  const serviceRing = Math.min(width * 0.22, height * 0.26, 142);
  const findingRing = Math.max(serviceRing + 58, Math.min(width * 0.38, height * 0.4, 212));

  // Background orbits and axes give the map a measurable field.
  const orbitService = svgEl('circle', { cx: centerX, cy: centerY, r: serviceRing, class: 'graph-orbit' });
  const orbitFinding = svgEl('circle', { cx: centerX, cy: centerY, r: findingRing, class: 'graph-orbit' });
  svg.append(orbitService, orbitFinding);
  svg.appendChild(svgEl('line', { x1: centerX - findingRing, y1: centerY, x2: centerX + findingRing, y2: centerY, class: 'graph-axis' }));
  svg.appendChild(svgEl('line', { x1: centerX, y1: centerY - findingRing, x2: centerX, y2: centerY + findingRing, class: 'graph-axis' }));

  if (serviceNodes.length) {
    const offset = -Math.PI / 2;
    serviceNodes.forEach((node, index) => {
      const angle = offset + (index / serviceNodes.length) * Math.PI * 2;
      node.x = centerX + Math.cos(angle) * serviceRing;
      node.y = centerY + Math.sin(angle) * serviceRing;
    });
  }

  if (findingNodes.length) {
    const twoRings = findingNodes.length > 8;
    const perRing = twoRings ? Math.ceil(findingNodes.length / 2) : findingNodes.length;
    const ringA = twoRings ? findingRing * 0.8 : findingRing;
    const ringB = findingRing;
    let ringACount = 0;
    let ringBCount = 0;
    findingNodes.forEach((node, index) => {
      const onOuter = twoRings && index % 2 === 1;
      const ring = onOuter ? ringB : ringA;
      const count = onOuter ? Math.ceil(findingNodes.length / 2) : perRing;
      const position = onOuter ? ringBCount++ : ringACount++;
      const angle = -Math.PI / 2 + (position / Math.max(1, count)) * Math.PI * 2 + (onOuter ? Math.PI / Math.max(1, count) : 0);
      node.x = centerX + Math.cos(angle) * ring;
      node.y = centerY + Math.sin(angle) * ring;
    });
  }

  const edgeLayer = svgEl('g', { class: 'graph-edges' });
  const nodeLayer = svgEl('g', { class: 'graph-nodes' });
  for (const edge of model.edges) {
    const from = nodeMap.get(edge.from);
    const to = nodeMap.get(edge.to);
    if (!from || !to) continue;
    const line = svgEl('line', {
      x1: from.x, y1: from.y, x2: to.x, y2: to.y,
      class: 'graph-edge',
      'data-from': edge.from,
      'data-to': edge.to,
    });
    edgeLayer.appendChild(line);
  }
  svg.append(edgeLayer, nodeLayer);

  for (const node of model.nodes) {
    const group = svgEl('g', {
      class: 'graph-node graph-node-' + node.kind,
      tabindex: '0',
      role: 'button',
      'data-node-id': node.id,
      'aria-label': graphNodeAria(node),
    });
    if (node.kind === 'finding') group.dataset.severity = node.severity;
    const radius = node.kind === 'target' ? 26 : node.kind === 'service' ? 8 : 9;
    group.appendChild(svgEl('circle', { cx: node.x, cy: node.y, r: radius }));
    if (node.kind === 'target') {
      const inner = svgEl('text', { x: node.x, y: node.y + 3.5, 'text-anchor': 'middle', class: 'graph-node-label is-strong' });
      inner.textContent = 'TARGET';
      group.appendChild(inner);
      const label = svgEl('text', { x: node.x, y: node.y + radius + 16, 'text-anchor': 'middle', class: 'graph-node-label is-strong' });
      label.textContent = shorten(node.label, 34);
      group.appendChild(label);
      const sub = svgEl('text', { x: node.x, y: node.y + radius + 28, 'text-anchor': 'middle', class: 'graph-node-sub' });
      sub.textContent = 'engagement target';
      group.appendChild(sub);
    } else {
      const labelText = shorten(node.label, node.kind === 'service' ? 18 : 26);
      const subText = shorten(node.sub || '', node.kind === 'service' ? 24 : 28);
      const estimated = Math.min(200, Math.max(40, Math.max(labelText.length, subText.length) * 6.4));
      let labelX = node.x;
      let anchor = 'middle';
      if (node.x - estimated / 2 < 8) {
        labelX = 8;
        anchor = 'start';
      } else if (node.x + estimated / 2 > width - 8) {
        labelX = width - 8;
        anchor = 'end';
      }
      const labelY = node.y + radius + 14;
      const subY = labelY + 11;
      const label = svgEl('text', { x: labelX, y: labelY, 'text-anchor': anchor, class: 'graph-node-label' });
      label.textContent = labelText;
      group.appendChild(label);
      const sub = svgEl('text', { x: labelX, y: subY, 'text-anchor': anchor, class: 'graph-node-sub' });
      sub.textContent = subText;
      group.appendChild(sub);
    }
    group.addEventListener('click', () => selectGraphNode(node.id));
    group.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        selectGraphNode(node.id);
      }
    });
    group.addEventListener('mouseenter', (event) => showGraphTooltip(event, node));
    group.addEventListener('mouseleave', hideGraphTooltip);
    group.addEventListener('focus', () => selectGraphNode(node.id, false));
    group.addEventListener('blur', hideGraphTooltip);
    nodeLayer.appendChild(group);
  }

  if (model.nodes.length === 1) {
    const note = svgEl('text', {
      x: centerX, y: height - 24, 'text-anchor': 'middle',
      fill: '#7c9186', 'font-size': 11,
    });
    note.textContent = 'No services or findings are recorded yet.';
    svg.appendChild(note);
  }
  if (model.hidden) {
    const note = svgEl('text', {
      x: width - 14, y: height - 14, 'text-anchor': 'end',
      fill: '#7c9186', 'font-size': 9.5,
    });
    note.textContent = model.hidden + ' more finding' + (model.hidden === 1 ? '' : 's') + ' not shown';
    svg.appendChild(note);
  }

  applyGraphSelection();
  renderGraphDetail();
  renderGraphLegend();
}

function graphNodeAria(node) {
  if (node.kind === 'target') return 'Target ' + node.full + '. Select for engagement scope.';
  if (node.kind === 'service') return 'Service ' + node.full + '. Select for service details.';
  return 'Finding ' + node.full + ', severity ' + severityOf(node.severity) + '. Select for evidence.';
}

function applyGraphSelection() {
  const svg = $('graph-svg');
  if (!svg) return;
  svg.querySelectorAll('.graph-node').forEach((group) => {
    group.classList.toggle('is-selected', group.dataset.nodeId === state.selectedNodeId);
  });
  svg.querySelectorAll('.graph-edge').forEach((edge) => {
    edge.classList.toggle('is-active',
      edge.dataset.from === state.selectedNodeId || edge.dataset.to === state.selectedNodeId);
  });
}

function selectGraphNode(id, focusDetail = true) {
  state.selectedNodeId = id;
  applyGraphSelection();
  renderGraphDetail();
  renderEvidenceSelection();
  if (focusDetail) {
    const detail = $('graph-detail');
    if (detail && window.matchMedia('(max-width: 860px)').matches) {
      const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      detail.scrollIntoView({ block: 'nearest', behavior: reduced ? 'auto' : 'smooth' });
    }
  }
}

function renderGraphDetail() {
  const detail = $('graph-detail');
  if (!detail) return;
  clear(detail);
  const node = graphNodeById(state.selectedNodeId);
  if (!node) {
    const placeholder = h('div', 'graph-detail-placeholder');
    placeholder.appendChild(h('div', 'graph-detail-kicker', 'Inspector'));
    append(placeholder,
      h('h3', null, 'Select a node'),
      h('p', null, 'Hover for a summary. Activate a node to read the recorded evidence and scope.'));
    detail.appendChild(placeholder);
    return;
  }
  detail.appendChild(h('div', 'graph-detail-kicker', node.kind === 'target' ? 'Engagement target' : node.kind === 'service' ? 'Open service' : 'Finding'));
  detail.appendChild(h('h3', null, node.full || node.label));
  if (node.kind === 'target') {
    const session = sessionRecord();
    const meta = h('dl', 'graph-detail-meta');
    append(meta,
      h('dt', null, 'Scope'), h('dd', null, scopeSummary(session, state.data.restore)),
      h('dt', null, 'Phase'), h('dd', null, phaseLabel(state.data.status?.phase_info?.current_phase || session.phase || 'scope')),
      h('dt', null, 'Services'), h('dd', null, fmtInt(Array.isArray(session.open_ports) ? session.open_ports.length : 0)),
      h('dt', null, 'Findings'), h('dd', null, fmtInt(findingsList().length)));
    detail.appendChild(meta);
    detail.appendChild(h('p', null, 'This map is built from the engagement record, its observed services and findings returned by the ARIA API.'));
    return;
  }
  if (node.kind === 'service') {
    const service = node.data || {};
    const meta = h('dl', 'graph-detail-meta');
    append(meta,
      h('dt', null, 'Port'), h('dd', null, String(service.port ?? '—')),
      h('dt', null, 'Service'), h('dd', null, humanize(service.service || 'unknown')),
      h('dt', null, 'Version'), h('dd', null, service.version || 'Not recorded'),
      h('dt', null, 'State'), h('dd', null, humanize(service.state || 'open')));
    detail.appendChild(meta);
    return;
  }
  const finding = node.data || {};
  const meta = h('dl', 'graph-detail-meta');
  append(meta,
    h('dt', null, 'Severity'), h('dd', null, humanize(severityOf(finding.severity))),
    h('dt', null, 'CVSS'), h('dd', null, finding.cvss_score === null || finding.cvss_score === undefined ? 'Not scored' : String(finding.cvss_score)),
    h('dt', null, 'Confidence'), h('dd', null, Number.isFinite(Number(finding.confidence)) ? Math.round(Number(finding.confidence) * 100) + '%' : 'Not recorded'),
    h('dt', null, 'Reviewed'), h('dd', null, finding.human_verified ? 'Human verified' : 'Not human verified'),
    h('dt', null, 'Source'), h('dd', null, humanize(finding.evidence_source || 'unknown')),
    h('dt', null, 'Agent'), h('dd', null, humanize(finding.agent_type || 'unknown')));
  detail.appendChild(meta);
  if (finding.description) detail.appendChild(h('p', null, finding.description));
  if (finding.evidence) {
    const block = h('div', 'graph-detail-block');
    append(block, h('h4', null, 'Recorded evidence'), h('p', null, finding.evidence));
    detail.appendChild(block);
  }
  if (Array.isArray(finding.cve_ids) && finding.cve_ids.length) {
    const block = h('div', 'graph-detail-block');
    append(block, h('h4', null, 'CVE references'), h('p', null, finding.cve_ids.join(', ')));
    detail.appendChild(block);
  }
  if (finding.recommendation) {
    const block = h('div', 'graph-detail-block');
    append(block, h('h4', null, 'Suggested next check'), h('p', null, finding.recommendation));
    detail.appendChild(block);
  }
}

function renderGraphLegend() {
  const legend = $('graph-legend');
  if (!legend) return;
  clear(legend);
  const entries = [['target', 'Target'], ['service', 'Service']];
  const counts = findingCounts();
  for (const severity of SEVERITIES) {
    if (Number(counts?.[severity]) > 0) entries.push([severity, humanize(severity)]);
  }
  entries.forEach(([kind, label]) => {
    const item = h('span', 'legend-item');
    const dot = h('span', 'legend-dot');
    dot.dataset.kind = kind;
    append(item, dot, document.createTextNode(label));
    legend.appendChild(item);
  });
  if (state.sessionId) {
    const hint = h('span', 'legend-item', 'Select a node to inspect its evidence');
    hint.style.marginLeft = 'auto';
    legend.appendChild(hint);
  }
}

function showGraphTooltip(event, node) {
  const stage = $('graph-stage');
  const tooltip = $('graph-tooltip');
  if (!stage || !tooltip) return;
  clear(tooltip);
  tooltip.appendChild(h('strong', null, node.full || node.label));
  const kind = node.kind === 'target' ? 'Engagement target' : node.kind === 'service' ? 'Open service' : humanize(severityOf(node.severity)) + ' finding';
  tooltip.appendChild(h('span', null, kind));
  if (node.kind === 'finding' && node.data?.cvss_score !== undefined && node.data?.cvss_score !== null) {
    tooltip.appendChild(h('span', null, 'CVSS ' + node.data.cvss_score));
  }
  const rect = stage.getBoundingClientRect();
  tooltip.hidden = false;
  const left = Math.min(Math.max(8, event.clientX - rect.left + 12), Math.max(8, rect.width - 292));
  const top = Math.min(Math.max(8, event.clientY - rect.top + 12), Math.max(8, rect.height - 100));
  tooltip.style.left = left + 'px';
  tooltip.style.top = top + 'px';
}

function hideGraphTooltip() {
  const tooltip = $('graph-tooltip');
  if (tooltip) tooltip.hidden = true;
}

// ── Timeline ────────────────────────────────────────────────────────────
function buildTimelineEvents() {
  const events = [];
  const team = state.data.teamEvents?.events;
  const teamIds = new Set(Array.isArray(team) ? team.filter(entry => typeof entry.id === 'string'
    && entry.id && parseTime(entry.timestamp)).map(entry => entry.id) : []);
  const seenDecisions = new Set();
  const decisions = state.data.decisions?.entries;
  if (Array.isArray(decisions)) {
    for (const entry of decisions) {
      const time = parseTime(entry.created_at);
      if (!time) continue;
      if (entry.type === 'team_event' && teamIds.has(entry.id)) continue;
      if (typeof entry.id === 'string' && entry.id) {
        if (seenDecisions.has(entry.id)) continue;
        seenDecisions.add(entry.id);
      }
      events.push({
        id: 'decision-' + String(entry.id || events.length),
        category: 'decision',
        time,
        title: humanize(entry.type || 'Decision'),
        copy: entry.reasoning || entry.action || entry.observation || '',
        human: Boolean(entry.human_involved),
        agent: entry.agent || '',
      });
    }
  }
  const campaign = state.data.campaignEvents?.events;
  if (Array.isArray(campaign)) {
    for (const entry of campaign) {
      const time = parseTime(entry.timestamp);
      if (!time) continue;
      events.push({
        id: 'campaign-' + String(entry.id || entry.sequence || events.length),
        category: 'campaign',
        time,
        title: humanize(entry.event || 'Campaign event'),
        copy: entry.message || entry.reason_code || '',
        human: false,
        agent: '',
      });
    }
  }
  const seenTeam = new Set();
  if (Array.isArray(team)) {
    for (const entry of team) {
      const time = parseTime(entry.timestamp);
      if (!time) continue;
      if (typeof entry.id === 'string' && entry.id) {
        if (seenTeam.has(entry.id)) continue;
        seenTeam.add(entry.id);
      }
      const collection = String(entry.collection || '');
      const data = entry.data || {};
      let title = humanize(collection || 'Team event');
      if (collection === 'tasks') title = 'Task ' + humanize(data.state || 'updated');
      else if (collection === 'evidence') title = 'Evidence catalogued';
      else if (collection === 'knowledge') title = 'Observation saved';
      else if (collection === 'coverage') title = 'Coverage updated';
      else if (collection === 'verification_findings') title = 'Finding ' + humanize(data.state || 'updated');
      events.push({
        id: 'team-' + String(entry.id || entry.sequence || events.length),
        category: 'team',
        time,
        title,
        copy: data.reason || data.text || data.question || '',
        human: Boolean(data.reviewed_by),
        agent: humanize(entry.actor || ''),
      });
    }
  }
  return events.sort((a, b) => b.time.getTime() - a.time.getTime());
}

function renderTimelineFilters(events) {
  const filters = $('timeline-filters');
  if (!filters) return;
  clear(filters);
  if (!events.length) return;
  const counts = { all: events.length, decision: 0, campaign: 0, team: 0 };
  for (const event of events) counts[event.category] = (counts[event.category] || 0) + 1;
  const entries = [['all', 'All'], ['decision', 'Decisions'], ['campaign', 'Campaign'], ['team', 'Team']];
  for (const [key, label] of entries) {
    if (key !== 'all' && !counts[key]) continue;
    const button = h('button', 'filter-button', label);
    button.type = 'button';
    button.setAttribute('aria-pressed', String(state.timelineFilter === key));
    button.appendChild(h('span', 'filter-count', fmtInt(counts[key])));
    button.addEventListener('click', () => {
      state.timelineFilter = key;
      renderTimeline();
    });
    filters.appendChild(button);
  }
}

function renderTimeline() {
  const body = $('timeline-body');
  if (!body) return;
  clear(body);
  if (state.loading && !state.data.decisions && !state.data.campaignEvents && !state.data.teamEvents) {
    body.appendChild(panelLoading('Reading operational events…'));
    return;
  }
  const events = buildTimelineEvents();
  renderTimelineFilters(events);
  if (!events.length) {
    body.appendChild(emptyState(
      'No operational events recorded',
      'Decisions, campaign events and team task changes are written to the audit ledger as they happen.'
    ));
    return;
  }
  const filtered = state.timelineFilter === 'all'
    ? events
    : events.filter((event) => event.category === state.timelineFilter);
  if (!filtered.length) {
    body.appendChild(emptyState('No events in this view', 'Choose another category to read the recorded audit trail.'));
    return;
  }
  const list = h('ol', 'timeline-list');
  for (const event of filtered.slice(0, 14)) {
    const item = h('li', 'timeline-item');
    const time = h('div', 'timeline-time');
    time.title = fmtDateTime(event.time);
    append(time, h('span', null, fmtClock(event.time)), h('span', 'timeline-relative', relativeTime(event.time)));
    const content = h('div', 'timeline-content');
    const head = h('div', 'timeline-head');
    const category = h('span', 'timeline-category', humanize(event.category));
    category.dataset.category = event.category;
    head.appendChild(category);
    if (event.human) head.appendChild(h('span', 'timeline-human', 'Human review'));
    head.appendChild(h('span', 'timeline-title', event.title));
    content.appendChild(head);
    if (event.copy) {
      const copy = h('div', 'timeline-copy' + (event.category === 'decision' ? ' is-mono' : ''), shorten(event.copy, 220));
      content.appendChild(copy);
    }
    item.append(time, content);
    list.appendChild(item);
  }
  body.appendChild(list);
  if (filtered.length > 14) {
    body.appendChild(h('div', 'budget-footnote', 'Showing the latest 14 of ' + fmtInt(filtered.length) + ' events.'));
  }
}

// ── Evidence ledger ─────────────────────────────────────────────────────
function renderEvidence() {
  const body = $('evidence-body');
  if (!body) return;
  clear(body);
  const findings = sortedFindings();
  const evidence = evidenceList();
  const verification = verificationList();
  const hypotheses = researchList();
  setText('evidence-findings-count', fmtInt(findings.length));
  setText('evidence-catalog-count', fmtInt(evidence.length + verification.length + hypotheses.length));

  const findingsTab = $('evidence-tab-findings');
  const catalogTab = $('evidence-tab-catalog');
  if (findingsTab && catalogTab) {
    const findingsActive = state.evidenceTab === 'findings';
    findingsTab.classList.toggle('tab-active', findingsActive);
    findingsTab.setAttribute('aria-selected', String(findingsActive));
    findingsTab.tabIndex = findingsActive ? 0 : -1;
    catalogTab.classList.toggle('tab-active', !findingsActive);
    catalogTab.setAttribute('aria-selected', String(!findingsActive));
    catalogTab.tabIndex = findingsActive ? -1 : 0;
    body.setAttribute('aria-labelledby', findingsActive ? 'evidence-tab-findings' : 'evidence-tab-catalog');
  }

  if (state.loading && !state.data.findings && !state.data.team) {
    body.appendChild(panelLoading('Reading the evidence ledger…'));
    return;
  }
  if (state.evidenceTab === 'catalog' && !state.data.team) {
    body.appendChild(emptyState('Evidence ledger unavailable', 'The team evidence API did not return a readable response.'));
    return;
  }

  if (state.evidenceTab === 'findings') {
    if (!findings.length) {
      body.appendChild(emptyState(
        'No findings recorded',
        'Recorded findings show their human-review status. Independent verification is reported separately in the evidence catalog.'
      ));
      return;
    }
    const list = h('ul', 'evidence-list');
    for (const finding of findings.slice(0, 8)) {
      const item = h('li');
      const button = h('button', 'finding-row');
      button.type = 'button';
      button.dataset.findingId = String(finding.id || '');
      if (state.selectedNodeId === 'finding-' + finding.id) button.classList.add('is-selected');
      const top = h('div', 'finding-top');
      const title = h('span', 'finding-title', finding.title || 'Untitled finding');
      const chip = h('span', 'severity-chip', humanize(severityOf(finding.severity)));
      chip.dataset.severity = severityOf(finding.severity);
      append(top, title, chip);
      button.appendChild(top);
      const meta = h('div', 'finding-meta');
      const confidence = Number(finding.confidence);
      if (Number.isFinite(confidence)) meta.appendChild(h('span', null, 'Confidence ' + Math.round(confidence * 100) + '%'));
      if (finding.evidence_source) meta.appendChild(h('span', null, humanize(finding.evidence_source)));
      meta.appendChild(h('span', null, finding.human_verified ? 'Human verified' : 'Unverified'));
      if (finding.cvss_score !== null && finding.cvss_score !== undefined) meta.appendChild(h('span', null, 'CVSS ' + finding.cvss_score));
      button.appendChild(meta);
      button.addEventListener('click', () => focusFinding(finding.id));
      item.appendChild(button);
      list.appendChild(item);
    }
    body.appendChild(list);
    if (findings.length > 8) body.appendChild(h('div', 'budget-footnote', (findings.length - 8) + ' more findings recorded in the workspace.'));
    return;
  }

  if (state.data.research === null) body.appendChild(h('div', 'budget-empty', 'Research state unavailable.'));
  if (state.data.verification === null) body.appendChild(h('div', 'budget-empty', 'Independent verification state unavailable.'));
  if (hypotheses.length) {
    body.appendChild(h('h3', null, 'Research assertions'));
    const list = h('ul', 'catalog-list');
    for (const item of hypotheses.slice(0, 6)) {
      const row = h('li', 'catalog-item');
      row.appendChild(h('div', 'catalog-title', shorten(item.claim || item.title || 'Research assertion', 180)));
      row.appendChild(h('div', 'catalog-meta', researchLabel(item)));
      list.appendChild(row);
    }
    body.appendChild(list);
  }
  if (!evidence.length && !verification.length && !hypotheses.length) {
    body.appendChild(emptyState(
      'No catalogued evidence',
      'Evidence is catalogued in the workspace from saved worker receipts or reviewed chat output. Specialist findings appear here after collection.'
    ));
    return;
  }
  if (evidence.length) {
    const list = h('ul', 'catalog-list');
    for (const item of evidence.slice(0, 8)) {
      const row = h('li', 'catalog-item');
      const title = item.summary || item.title || item.source_kind || 'Catalogued evidence';
      row.appendChild(h('div', 'catalog-title', shorten(title, 150)));
      const meta = h('div', 'catalog-meta');
      const parts = [];
      parts.push('Observation; content is untrusted');
      if (item.source_kind) parts.push(humanize(item.source_kind));
      if (item.source_id) parts.push('Source ' + shorten(item.source_id, 30));
      if (item.created_at) parts.push(relativeTime(parseTime(item.created_at)));
      meta.textContent = parts.join(' / ');
      row.appendChild(meta);
      list.appendChild(row);
    }
    body.appendChild(list);
  }
  if (verification.length) {
    const list = h('ul', 'catalog-list');
    for (const item of verification.slice(0, 6)) {
      const row = h('li', 'catalog-item');
      row.appendChild(h('div', 'catalog-title', shorten(item.title || item.underlying_cause || 'Verification finding', 150)));
      const meta = h('div', 'catalog-meta');
      meta.textContent = [verificationLabel(item), item.severity ? humanize(item.severity) : '']
        .filter(Boolean).join(' / ');
      row.appendChild(meta);
      list.appendChild(row);
    }
    body.appendChild(list);
  }
}

function focusFinding(id) {
  if (state.graphFilter !== 'all') {
    const finding = findingsList().find((item) => String(item.id) === String(id));
    if (finding && severityOf(finding.severity) !== state.graphFilter) {
      state.graphFilter = 'all';
      renderGraphFilters();
      renderGraph();
    }
  }
  state.selectedNodeId = 'finding-' + String(id);
  applyGraphSelection();
  renderGraphDetail();
  renderEvidenceSelection();
}

function renderEvidenceSelection() {
  const body = $('evidence-body');
  if (!body) return;
  body.querySelectorAll('.finding-row').forEach((row) => {
    row.classList.toggle('is-selected', row.dataset.findingId === String(state.selectedNodeId || '').replace(/^finding-/, ''));
  });
}

// ── Model budget ────────────────────────────────────────────────────────
function measuredValue(value, unit = '', integer = false) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0
      || (integer && !Number.isSafeInteger(value))) return 'Unavailable';
  return (integer ? fmtInt(value) : value.toFixed(2)) + unit;
}

function attemptMetricRows(attempt) {
  const timing = attempt.timings || {};
  return [
    ['HTTP attempts', measuredValue(timing.http_attempts, '', true)],
    ['Request construction', measuredValue(timing.request_construction_ms, ' ms')],
    ['HTTP request / response', measuredValue(timing.provider_attempt_ms, ' ms')],
    ['Response processing', measuredValue(timing.response_processing_ms, ' ms')],
    ['Structured validation', measuredValue(timing.structured_validation_ms, ' ms')],
    ['Pool client invocation', measuredValue(timing.pool_attempt_ms, ' ms')],
    ['Reported input tokens', measuredValue(attempt.input_tokens, '', true)],
    ['Reported output tokens', measuredValue(attempt.output_tokens, '', true)],
  ];
}

function providerCharge(attempt) {
  const cost = attempt.provider_usage?.cost;
  return typeof cost === 'string' && cost.length <= 100
    && /^(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/.test(cost)
    && Number.isFinite(Number(cost)) && Number(cost) >= 0
    ? '$' + cost + ' USD (provider receipt)' : 'Unavailable';
}

function renderBudget() {
  const body = $('budget-body');
  if (!body) return;
  clear(body);
  const budget = modelBudget();
  const llm = state.data.llm;
  const providers = Array.isArray(llm?.keys) ? llm.keys.length : null;
  setText('budget-providers', providers === null
    ? 'Providers unavailable'
    : providers
      ? providers + ' provider key' + (providers === 1 ? '' : 's')
      : 'No providers');

  if (state.loading && !budget) {
    body.appendChild(panelLoading('Reading model accounting…'));
    return;
  }
  if (!budget) {
    body.appendChild(emptyState('Budget unavailable', 'The engagement model ledger did not return a readable response.'));
    return;
  }

  const limits = budget.limits || {};
  const usage = normalizeUsage(budget.usage);
  const maxCalls = Number(limits.max_calls) || 0;
  const maxTokens = Number(limits.max_tokens) || 0;
  const maxCost = Number(limits.max_cost_microusd) || 0;
  const attempts = Array.isArray(budget.attempts) ? budget.attempts : [];
  const tariffs = Array.isArray(limits.tariffs) ? limits.tariffs : [];

  const engagement = h('div', 'budget-section');
  engagement.appendChild(h('h3', null, 'Engagement ceiling'));
  engagement.appendChild(budgetLine('Model call reservations', fmtInt(usage.calls) + ' / ' + fmtInt(maxCalls), usage.calls, maxCalls));
  engagement.appendChild(budgetLine('Reserved tokens', fmtCompact(usage.reserved_tokens) + ' / ' + fmtCompact(maxTokens), usage.reserved_tokens, maxTokens,
    fmtInt(usage.reported_tokens) + ' tokens reported'));
  engagement.appendChild(budgetLine('Reserved cost', fmtUsdMicro(usage.reserved_cost_microusd) + ' / ' + fmtUsdMicro(maxCost), usage.reserved_cost_microusd, maxCost,
    fmtUsdMicro(usage.reported_cost_microusd) + ' reported, rounded up to micro-USD'));
  if (!usage.calls && !usage.reserved_tokens && !usage.reserved_cost_microusd) {
    engagement.appendChild(h('div', 'budget-empty', 'No provider calls are recorded for this engagement.'));
  }
  if (usage.unknown_usage_calls) {
    engagement.appendChild(h('div', 'budget-footnote', fmtInt(usage.unknown_usage_calls) + ' call(s) reported no token usage and remain charged at their reservation.'));
  }
  if (usage.stopped) {
    const stopped = h('div', 'alert-row');
    stopped.dataset.severity = 'critical';
    stopped.appendChild(h('div', null, 'Accounting is stopped: ' + humanize(usage.stop_reason || 'unknown reason') + '. Further provider calls are denied.'));
    engagement.appendChild(stopped);
  }
  body.appendChild(engagement);

  const attemptsBlock = h('div', 'budget-section');
  attemptsBlock.appendChild(h('h3', null, 'Provider attempts'));
  if (attempts.length) {
    const last = attempts[attempts.length - 1] || {};
    const provider = last.provider || last.provider_name || 'Provider';
    const model = last.model || last.model_name || 'model not recorded';
    attemptsBlock.appendChild(kvRow('Recorded attempts', fmtInt(attempts.length) + ' of ' + fmtInt(budget.attempts_limit || attempts.length)));
    attemptsBlock.appendChild(kvRow('Last provider', humanize(provider)));
    attemptsBlock.appendChild(kvRow('Last model', String(model)));
    attemptsBlock.appendChild(kvRow('Attempt ID', last.id || 'Unavailable'));
    attemptsBlock.appendChild(kvRow('Logical model request', last.logical_request_id || 'Unavailable'));
    attemptsBlock.appendChild(kvRow('Reservation attempt', measuredValue(last.attempt_index, '', true)));
    attemptsBlock.appendChild(kvRow('Exact reported charge', providerCharge(last)));
    attemptMetricRows(last).forEach(([label, value]) => attemptsBlock.appendChild(kvRow(label, value)));
    attemptsBlock.appendChild(h('div', 'budget-footnote', 'Latest recorded attempt only. HTTP duration includes transport and provider work; it does not measure model inference or mission duration.'));
  } else {
    attemptsBlock.appendChild(h('div', 'budget-empty', 'No model attempts are recorded.'));
  }
  attemptsBlock.appendChild(kvRow('Tariffs', tariffs.length ? fmtInt(tariffs.length) + ' configured' : 'None configured'));
  body.appendChild(attemptsBlock);

  if (budget.cost_basis) body.appendChild(h('div', 'budget-footnote', budget.cost_basis));

  const campaign = campaignData();
  if (campaign) {
    const campaignBudget = healthData()?.budget || campaign.budget || {};
    const campaignUsage = normalizeUsage(campaignBudget);
    const section = h('div', 'budget-section');
    section.appendChild(h('h3', null, 'Campaign ceiling'));
    section.appendChild(budgetLine('Reserved tokens',
      fmtCompact(campaignUsage.reserved_tokens) + ' / ' + fmtCompact(campaignBudget.max_tokens || 0),
      campaignUsage.reserved_tokens, campaignBudget.max_tokens || 0));
    section.appendChild(budgetLine('Reserved cost',
      fmtUsdMicro(campaignUsage.reserved_cost_microusd) + ' / ' + fmtUsdMicro(campaignBudget.max_cost_microusd || 0),
      campaignUsage.reserved_cost_microusd, campaignBudget.max_cost_microusd || 0));
    section.appendChild(kvRow('Provider calls', fmtInt(campaignUsage.calls)));
    body.appendChild(section);
  }
}

// ── Shell, sessions, sync ───────────────────────────────────────────────
function renderAccount() {
  const username = state.user?.display_name || state.user?.username || 'Owner';
  setText('account-name', username);
  const initial = String(username || 'A').trim().charAt(0).toUpperCase() || 'A';
  setText('account-initial', initial);
  $('account')?.setAttribute('title', 'Signed in as ' + username);
}

function renderWorker(capabilities) {
  const node = $('rail-worker');
  if (!node) return;
  if (!capabilities || !capabilities.worker) {
    node.dataset.state = 'unknown';
    setText('rail-worker-label', 'Worker status unavailable');
    node.title = 'The capabilities API did not return a readable worker status.';
    return;
  }
  const worker = capabilities.worker;
  const status = String(worker.status || 'unknown');
  node.dataset.state = status === 'online' ? 'online' : status === 'not_configured' ? 'offline' : 'unknown';
  const label = status === 'online' ? 'Worker online' : status === 'not_configured' ? 'Worker unset' : 'Worker unreachable';
  setText('rail-worker-label', label);
  const tools = Array.isArray(worker.available_tools) && worker.available_tools.length
    ? 'Available tools: ' + worker.available_tools.join(', ')
    : 'No supported tools advertised';
  node.title = label + '. ' + tools + '.';
}

function renderFooter(health) {
  const version = health?.version;
  setText('footer-version', version ? 'ARIA ' + version + ' / evidence-driven security research' : 'ARIA / evidence-driven security research');
  setText('rail-version', version ? 'v' + version : 'v10');
}

function renderWarnings() {
  const warning = $('data-warning');
  if (!warning) return;
  if (!state.warnings.length) {
    warning.hidden = true;
    return;
  }
  warning.hidden = false;
  const count = state.warnings.length;
  setText('data-warning-text', count + ' live source' + (count === 1 ? '' : 's') + ' could not be refreshed. Affected current state is unavailable.');
}

function renderLoading() {
  setText('engagement-title', 'Reading engagement');
  setText('hero-target', '—');
  setText('hero-scope', '—');
  setText('hero-created', '—');
  setText('hero-note', 'Reading owner-scoped state from the ARIA API.');
  setText('phase-index', '— / 7');
  setText('phase-name', 'Loading');
  setText('phase-readiness', '—');
  for (const [id, label] of [
    ['campaign-body', 'Reading campaign state…'],
    ['agents-body', 'Reading specialist tasks…'],
    ['timeline-body', 'Reading operational events…'],
    ['evidence-body', 'Reading the evidence ledger…'],
    ['budget-body', 'Reading model accounting…'],
  ]) {
    const node = $(id);
    if (node) {
      clear(node);
      node.appendChild(panelLoading(label));
    }
  }
  setText('graph-subtitle', 'Target, services and recorded findings');
  document.body.dataset.dashboardReady = 'false';
}

let renderMeasurement = 0;
function renderAll() {
  const renderId = ++renderMeasurement;
  const started = typeof performance === 'undefined' ? null : performance.now();
  renderHero();
  renderMetrics();
  renderCampaign();
  renderAgents();
  renderGraphFilters();
  renderGraph();
  renderTimeline();
  renderEvidence();
  renderBudget();
  renderWorker(state.data.capabilities);
  renderFooter(state.data.health);
  renderWarnings();
  document.body.dataset.dashboardReady = 'true';
  if (started !== null && !state.loading && typeof performance.measure === 'function') {
    const detail = {run_id: state.data.autonomous?.run_id || null, session_id: state.sessionId || null};
    performance.clearMeasures('aria.dashboard.dom_update');
    performance.measure('aria.dashboard.dom_update', {start: started, end: performance.now(), detail});
    if (typeof window.requestAnimationFrame === 'function') window.requestAnimationFrame(() => window.requestAnimationFrame(() => {
      if (renderId !== renderMeasurement) return;
      performance.clearMeasures('aria.dashboard.paint_opportunity');
      performance.measure('aria.dashboard.paint_opportunity', {start: started, end: performance.now(), detail});
    }));
  }
}

function renderPicker() {
  const select = $('engagement-select');
  if (!select) return;
  clear(select);
  if (!state.sessions.length) {
    const option = document.createElement('option');
    option.value = '';
    option.textContent = 'No engagements';
    select.appendChild(option);
    select.disabled = true;
    setText('engagement-count', '0 engagements');
    return;
  }
  select.disabled = false;
  for (const session of state.sessions) {
    const option = document.createElement('option');
    option.value = session.session_id;
    const name = session.name || 'Untitled engagement';
    const target = session.target ? ' (' + session.target + ')' : '';
    option.textContent = name + target;
    select.appendChild(option);
  }
  select.value = state.sessionId;
  setText('engagement-count', state.sessions.length + ' engagement' + (state.sessions.length === 1 ? '' : 's'));
}

function setSync(mode, label) {
  const node = $('sync-state');
  if (node) node.dataset.state = mode;
  setText('sync-label', label);
}

function updateSyncLabel() {
  if (state.loading) {
    setSync('loading', 'Syncing');
    return;
  }
  if (state.warnings.length) {
    setSync('error', 'Partial sync');
    return;
  }
  if (!state.lastSync) {
    setSync('loading', 'Connecting');
    return;
  }
  const seconds = Math.max(0, Math.floor((Date.now() - state.lastSync) / 1000));
  setSync('ok', seconds < 45 ? 'Updated now' : 'Updated ' + fmtDuration(seconds) + ' ago');
}

async function loadUser() {
  try {
    const profile = await api('/api/profile');
    if (profile && typeof profile === 'object') {
      state.user = { ...(state.user || {}), ...profile };
      localStorage.setItem('pentestai_user', JSON.stringify(state.user));
    }
  } catch (_) {
    // The stored identity remains usable; /api/profile is not critical.
  }
  renderAccount();
}

function loadStoredUser() {
  try {
    const raw = localStorage.getItem('pentestai_user');
    if (raw) state.user = JSON.parse(raw);
  } catch (_) {
    state.user = null;
  }
}

async function loadSessions() {
  const result = await api('/api/session/list');
  state.sessions = Array.isArray(result?.sessions) ? result.sessions : [];
  const stored = localStorage.getItem('current_session') || '';
  const exists = state.sessions.some((session) => session.session_id === stored);
  state.sessionId = exists ? stored : (state.sessions[0]?.session_id || '');
  if (state.sessionId) localStorage.setItem('current_session', state.sessionId);
  renderPicker();
}

async function loadAll() {
  if (!state.sessionId) {
    state.loading = false;
    state.data = {};
    renderAll();
    updateSyncLabel();
    return;
  }
  const generation = ++state.requestGeneration;
  state.loading = true;
  setSync('loading', 'Syncing');
  const refresh = $('refresh-button');
  refresh?.classList.add('is-spinning');

  const sid = state.sessionId;
  const requests = {
    session: api('/api/session/' + encodeURIComponent(sid)),
    restore: api('/api/session/' + encodeURIComponent(sid) + '/restore?offset=0&limit=100'),
    findings: api('/api/findings/' + encodeURIComponent(sid), { allow404: true }),
    status: api('/api/v8/status/' + encodeURIComponent(sid)),
    team: api('/api/team/' + encodeURIComponent(sid)),
    research: api('/api/team/' + encodeURIComponent(sid) + '/research'),
    verification: api('/api/team/' + encodeURIComponent(sid) + '/findings'),
    budget: api('/api/team/' + encodeURIComponent(sid) + '/model-budget'),
    autonomous: api('/api/pentest/' + encodeURIComponent(sid) + '/autonomous/status'),
    decisions: api('/api/pentest/' + encodeURIComponent(sid) + '/decision-log?limit=200'),
    teamEvents: api('/api/team/' + encodeURIComponent(sid) + '/events?after=0'),
    capabilities: api('/api/capabilities'),
    campaign: api('/api/pentest/' + encodeURIComponent(sid) + '/campaign', { allow404: true }),
    llm: api('/api/v8/llm-status'),
    health: api('/api/health'),
  };
  const names = Object.keys(requests);
  const results = await Promise.allSettled(Object.values(requests));
  if (generation !== state.requestGeneration || sid !== state.sessionId) return;

  const data = {};
  const warnings = [];
  results.forEach((result, index) => {
    const name = names[index];
    if (result.status === 'fulfilled') {
      data[name] = result.value;
    } else {
      if (result.reason?.status === 401) return;
      data[name] = null;
      warnings.push({ name, message: result.reason?.message || 'Unavailable' });
    }
  });

  // Health and the event ring are only meaningful when a campaign exists.
  // Avoid probing missing sub-resources and producing expected 404 noise.
  if (data.campaign) {
    const [healthResult, eventsResult] = await Promise.allSettled([
      api('/api/pentest/' + encodeURIComponent(sid) + '/campaign/health', { allow404: true }),
      api('/api/pentest/' + encodeURIComponent(sid) + '/campaign/events', { allow404: true }),
    ]);
    if (generation !== state.requestGeneration || sid !== state.sessionId) return;
    if (healthResult.status === 'fulfilled') data.campaignHealth = healthResult.value;
    else {
      data.campaignHealth = null;
      warnings.push({ name: 'campaignHealth', message: healthResult.reason?.message || 'Unavailable' });
    }
    if (eventsResult.status === 'fulfilled') data.campaignEvents = eventsResult.value;
    else {
      data.campaignEvents = null;
      warnings.push({ name: 'campaignEvents', message: eventsResult.reason?.message || 'Unavailable' });
    }
  } else {
    data.campaignHealth = null;
    data.campaignEvents = null;
  }

  state.data = data;
  state.warnings = warnings;
  state.loading = false;
  state.lastSync = Date.now();
  refresh?.classList.remove('is-spinning');
  renderAll();
  updateSyncLabel();
}

function startTimers() {
  if (state.syncTimer) window.clearInterval(state.syncTimer);
  if (state.refreshTimer) window.clearInterval(state.refreshTimer);
  state.syncTimer = window.setInterval(updateSyncLabel, 5000);
  state.refreshTimer = window.setInterval(() => {
    if (!state.autoRefresh || state.loading) return;
    if (document.visibilityState === 'hidden') return;
    loadAll();
  }, REFRESH_MS);
}

// ── Bindings & boot ─────────────────────────────────────────────────────
function bindEvents() {
  $('engagement-select')?.addEventListener('change', (event) => {
    const sid = event.target.value;
    if (!sid || sid === state.sessionId) return;
    state.sessionId = sid;
    state.selectedNodeId = null;
    state.graphFilter = 'all';
    state.timelineFilter = 'all';
    state.evidenceTab = 'findings';
    state.data = {};
    state.warnings = [];
    localStorage.setItem('current_session', sid);
    renderLoading();
    loadAll();
  });

  $('refresh-button')?.addEventListener('click', () => loadAll());
  $('data-warning-retry')?.addEventListener('click', () => loadAll());

  $('signout-button')?.addEventListener('click', async () => {
    try {
      await api('/api/logout', { method: 'POST' });
    } catch (error) {
      toast('error', 'Sign out failed', error.message);
      return;
    }
    localStorage.removeItem('pentestai_token');
    localStorage.removeItem('pentestai_user');
    localStorage.removeItem('current_session');
    window.location.href = '/login.html';
  });

  const evidenceTabs = [$('evidence-tab-findings'), $('evidence-tab-catalog')];
  evidenceTabs.forEach((tab, index) => {
    if (!tab) return;
    tab.addEventListener('click', () => {
      state.evidenceTab = tab.id === 'evidence-tab-catalog' ? 'catalog' : 'findings';
      renderEvidence();
    });
    tab.addEventListener('keydown', (event) => {
      if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight' && event.key !== 'Home' && event.key !== 'End') return;
      event.preventDefault();
      let nextIndex = index;
      if (event.key === 'ArrowLeft') nextIndex = (index + evidenceTabs.length - 1) % evidenceTabs.length;
      else if (event.key === 'ArrowRight') nextIndex = (index + 1) % evidenceTabs.length;
      else if (event.key === 'Home') nextIndex = 0;
      else if (event.key === 'End') nextIndex = evidenceTabs.length - 1;
      const next = evidenceTabs[nextIndex];
      if (!next) return;
      state.evidenceTab = next.id === 'evidence-tab-catalog' ? 'catalog' : 'findings';
      renderEvidence();
      next.focus();
    });
  });

  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && state.autoRefresh && !state.loading
        && Date.now() - state.lastSync > REFRESH_MS) {
      loadAll();
    }
  });

  if (typeof ResizeObserver !== 'undefined') {
    state.graphObserver = new ResizeObserver(() => {
      if (state.resizeTimer) window.clearTimeout(state.resizeTimer);
      state.resizeTimer = window.setTimeout(() => {
        if (state.data.session || state.data.restore) renderGraph();
      }, 120);
    });
    const stage = $('graph-stage');
    if (stage) state.graphObserver.observe(stage);
  }
}

async function boot() {
  state.token = localStorage.getItem('pentestai_token') || '';
  if (!state.token) {
    window.location.href = '/login.html';
    return;
  }
  loadStoredUser();
  renderAccount();
  bindEvents();
  startTimers();
  renderLoading();
  try {
    await loadSessions();
    await loadUser();
  } catch (error) {
    state.warnings = [{ name: 'sessions', message: error.message }];
    setSync('error', 'Unavailable');
    renderAll();
    document.body.dataset.dashboardReady = 'true';
    return;
  }
  if (!state.sessionId) {
    state.loading = false;
    state.data = {};
    renderAll();
    updateSyncLabel();
    return;
  }
  await loadAll();
}

document.addEventListener('DOMContentLoaded', boot);
})();
