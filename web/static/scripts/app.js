/* ═══════════════════════════════════════════════════════════════════════
 * PentestAI v10 — Tactical Terminal Frontend
 *
 * Wires up:
 *   • Chat flow with ARIA (send/receive messages, render commands/findings)
 *   • AUTO mode toggle + WebSocket live activity stream
 *   • Intel panel (hosts / findings / shells / creds / timeline /
 *                  decisions / playbooks) — refreshed via kb-snapshot
 *   • Approval banner for red-risk steps (blocking gate — academic brief req't)
 *   • Decision Log tab — audit trail for the jury
 *   • Settings slide-in
 *
 * All dynamic text uses textContent or element-by-element construction —
 * no innerHTML with user-supplied data (XSS-safe).
 * ═══════════════════════════════════════════════════════════════════════ */
(function () {
'use strict';

// ── State ──────────────────────────────────────────────────────────────
const state = {
  sessionId: localStorage.getItem('current_session') || '',
  target:    '',
  phase:     'scope',
  token:     localStorage.getItem('auth_token') || '',
  skill:     localStorage.getItem('skill') || 'intermediate',
  autoActive: false,
  ws:        null,
  autoStep:  0,
  autoMaxSteps: 12,
  pendingApprovals: [],
  goalSelect: '',
  modeSelect: 'lab',
};

// ── DOM refs ───────────────────────────────────────────────────────────
const $ = (id) => document.getElementById(id);
const el = {
  messages:   $('messages'),
  input:      $('user-input'),
  sendBtn:    $('send-button'),
  goalSel:    $('goal-select'),
  modeSel:    $('mode-select'),
  autoBtn:    $('auto-button'),
  autoLabel:  $('auto-label'),
  autoLog:    $('auto-log'),
  autoLines:  $('auto-log-lines'),
  autoCount:  $('auto-log-counter'),
  thinking:   $('thinking-indicator'),
  autoRun:    $('auto-running-indicator'),
  targetChip: $('target-chip'),
  targetVal:  $('target-value'),
  inputTarget: $('input-target-chip'),
  inputTargetLabel: $('input-target-label'),
  inputTargetClear: $('input-target-clear'),
  phaseChip:  $('phase-chip'),
  phaseVal:   $('phase-value'),
  sessionName:$('session-name'),
  phaseStep:  $('phase-stepper'),
  toolPills:  $('tools-run'),
  tabs:       document.querySelectorAll('.intel-tab'),
  bodies:     {
    hosts:     $('tab-hosts'),
    findings:  $('tab-findings'),
    shells:    $('tab-shells'),
    creds:     $('tab-creds'),
    timeline:  $('tab-timeline'),
    decisions: $('tab-decisions'),
    playbooks: $('tab-playbooks'),
  },
  toastContainer: $('toast-container'),
  approvalBanner: $('approval-banner'),
  approvalDetail: $('approval-detail'),
  approvalCommand: $('approval-command'),
  btnApprove: $('approval-approve'),
  btnReject:  $('approval-reject'),
  btnModify:  $('approval-modify'),
  settingsBtn: $('settings-button'),
  settingsPanel: $('settings-panel'),
  settingsClose: $('settings-close'),
  newSessionBtn: $('new-session-btn'),
  sessionList: $('session-list'),
  maxStepsInput: $('max-steps'),
  maxStepsValue: $('max-steps-value'),
  riskThreshold: $('risk-threshold'),
  llmKeysList:   $('llm-keys-list'),
  newKeyProvider:$('new-key-provider'),
  newKeyValue:   $('new-key-value'),
  newKeyLabel:   $('new-key-label'),
  newKeyAdd:     $('new-key-add'),
};

// ── API helper ─────────────────────────────────────────────────────────
async function api(path, opts = {}) {
  const headers = Object.assign({
    'Content-Type': 'application/json',
    'Authorization': state.token ? `Bearer ${state.token}` : '',
  }, opts.headers || {});
  const resp = await fetch(path, {
    method: opts.method || 'GET',
    headers,
    body:   opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (resp.status === 401) {
    toast('danger', 'Session expired', 'Please log in again.');
    window.location.href = '/login.html';
    return null;
  }
  const ct = resp.headers.get('content-type') || '';
  const data = ct.includes('application/json')
    ? await resp.json().catch(() => ({}))
    : await resp.text();
  if (!resp.ok) {
    const msg = (data && data.detail) || resp.statusText;
    throw new Error(msg);
  }
  return data;
}

// ── Toast ──────────────────────────────────────────────────────────────
function toast(kind, title, msg, ttl = 4200) {
  const node = document.createElement('div');
  node.className = `toast toast-${kind}`;
  const titleEl = document.createElement('div');
  titleEl.className = 'toast-title';
  titleEl.textContent = title;
  const msgEl = document.createElement('div');
  msgEl.className = 'toast-msg';
  msgEl.textContent = msg || '';
  node.append(titleEl, msgEl);
  el.toastContainer.appendChild(node);
  setTimeout(() => {
    node.style.transition = 'opacity 200ms';
    node.style.opacity = '0';
    setTimeout(() => node.remove(), 210);
  }, ttl);
}

function emptyState(root, text) {
  const e = document.createElement('div');
  e.className = 'intel-empty';
  e.textContent = text;
  root.appendChild(e);
}

// ── Message rendering (XSS-safe) ───────────────────────────────────────
function addUserMessage(text) {
  const msg = document.createElement('div');
  msg.className = 'msg msg-user';
  const bubble = document.createElement('div');
  bubble.className = 'msg-bubble';
  bubble.textContent = text;
  msg.appendChild(bubble);
  el.messages.appendChild(msg);
  scrollMessages();
}

function addAriaMessage(payload) {
  const msg = document.createElement('div');
  msg.className = 'msg msg-ai';

  const header = document.createElement('div');
  header.className = 'msg-header';
  if (payload.phase) {
    const badge = document.createElement('span');
    badge.className = 'badge badge-phase';
    badge.textContent = payload.phase;
    header.appendChild(badge);
  }
  if (payload.risk) {
    const rb = document.createElement('span');
    rb.className = `badge badge-risk-${payload.risk}`;
    rb.textContent = payload.risk.toUpperCase();
    header.appendChild(rb);
  }
  msg.appendChild(header);

  const bubble = document.createElement('div');
  bubble.className = 'msg-bubble';
  const bodyEl = document.createElement('div');
  bodyEl.textContent = payload.text || '';
  bubble.appendChild(bodyEl);

  // Reasoning chain (collapsible)
  if (payload.reasoning && payload.reasoning.length) {
    const det = document.createElement('details');
    det.className = 'collapse';
    const summ = document.createElement('summary');
    summ.textContent = `Reasoning chain (${payload.reasoning.length} steps)`;
    det.appendChild(summ);
    const body = document.createElement('div');
    body.className = 'body';
    payload.reasoning.forEach((r, i) => {
      const step = document.createElement('div');
      step.className = 'reasoning-step';
      const t = document.createElement('div');
      t.className = 'thought';
      t.textContent = `Step ${i+1}: ${r.thought || ''}`;
      step.appendChild(t);
      if (r.action) {
        const a = document.createElement('div');
        a.className = 'action';
        a.textContent = `→ ${r.action.command || JSON.stringify(r.action)}`;
        step.appendChild(a);
      }
      if (r.observation) {
        const o = document.createElement('div');
        o.className = 'observation';
        o.textContent = r.observation;
        step.appendChild(o);
      }
      body.appendChild(step);
    });
    det.appendChild(body);
    bubble.appendChild(det);
  }

  // Commands
  if (payload.commands && payload.commands.length) {
    const det = document.createElement('details');
    det.className = 'collapse';
    det.open = true;
    const summ = document.createElement('summary');
    summ.textContent = `Commands (${payload.commands.length})`;
    det.appendChild(summ);
    const body = document.createElement('div');
    body.className = 'body';
    payload.commands.forEach(cmd => body.appendChild(renderCmdCard(cmd)));
    det.appendChild(body);
    bubble.appendChild(det);
  }

  // Findings
  if (payload.findings && payload.findings.length) {
    payload.findings.forEach(f => bubble.appendChild(renderFinding(f)));
  }

  msg.appendChild(bubble);
  el.messages.appendChild(msg);
  scrollMessages();
}

function renderCmdCard(cmd) {
  const card = document.createElement('div');
  card.className = 'cmd-card';
  card.dataset.risk = cmd.risk_color || 'orange';

  const row = document.createElement('div');
  row.className = 'cmd-row';
  const cmdEl = document.createElement('code');
  cmdEl.className = 'cmd-command';
  cmdEl.textContent = cmd.command || '';
  cmdEl.title = cmd.command || '';

  const actions = document.createElement('div');
  actions.className = 'cmd-actions';

  const copyBtn = document.createElement('button');
  copyBtn.className = 'cmd-btn';
  copyBtn.textContent = 'copy';
  copyBtn.onclick = () => {
    navigator.clipboard.writeText(cmd.command || '').then(
      () => toast('success', 'Copied', ''),
      () => toast('danger', 'Copy failed', ''),
    );
  };
  const runBtn = document.createElement('button');
  runBtn.className = 'cmd-btn cmd-btn-run';
  runBtn.textContent = '▶ Run';
  runBtn.onclick = () => runCommand(cmd);

  actions.append(copyBtn, runBtn);
  row.append(cmdEl, actions);
  card.appendChild(row);

  if (cmd.purpose) {
    const p = document.createElement('div');
    p.className = 'cmd-purpose';
    p.textContent = cmd.purpose;
    card.appendChild(p);
  }
  return card;
}

function renderFinding(f) {
  const card = document.createElement('div');
  card.className = 'finding';
  const title = document.createElement('div');
  title.className = 'finding-title';

  (f.cve_ids || []).slice(0, 3).forEach(cve => {
    const chip = document.createElement('span');
    chip.className = 'cve-chip';
    chip.textContent = cve;
    title.appendChild(chip);
  });
  if (typeof f.cvss_score === 'number' && f.cvss_score > 0) {
    const sev = f.cvss_score >= 9 ? 'crit'
              : f.cvss_score >= 7 ? 'high'
              : f.cvss_score >= 4 ? 'med' : 'low';
    const chip = document.createElement('span');
    chip.className = `cvss-chip ${sev}`;
    chip.textContent = `CVSS ${f.cvss_score.toFixed(1)}`;
    title.appendChild(chip);
  }
  const ttl = document.createElement('span');
  ttl.textContent = ' ' + (f.title || '');
  title.appendChild(ttl);
  card.appendChild(title);

  if (f.description) {
    const d = document.createElement('div');
    d.className = 'finding-desc';
    d.textContent = f.description;
    card.appendChild(d);
  }
  return card;
}

function scrollMessages() {
  el.messages.scrollTop = el.messages.scrollHeight;
}

// ── Phase stepper ──────────────────────────────────────────────────────
const PHASES = ['scope','recon','scan','vuln','exploit','post','report'];
function renderPhaseStepper() {
  el.phaseStep.textContent = '';
  PHASES.forEach(p => {
    const li = document.createElement('li');
    li.textContent = p.charAt(0).toUpperCase() + p.slice(1);
    if (phaseIndex(p) < phaseIndex(state.phase)) li.classList.add('done');
    else if (p === state.phase) li.classList.add('active');
    el.phaseStep.appendChild(li);
  });
}
function phaseIndex(p) {
  const map = {'scope':0,'recon':1,'reconnaissance':1,'scan':2,'scanning':2,
               'vuln':3,'vulnerability':3,'vulnerability_analysis':3,
               'exploit':4,'exploitation':4,
               'post':5,'post_exploitation':5,'report':6,'reporting':6};
  return map[p] !== undefined ? map[p] : 0;
}
function updatePhaseUI() {
  el.phaseVal.textContent = state.phase;
  renderPhaseStepper();
}

// ── Tools pills ────────────────────────────────────────────────────────
const toolsRun = new Set();
function addToolPill(tool) {
  if (!tool || toolsRun.has(tool)) return;
  toolsRun.add(tool);
  const pill = document.createElement('span');
  pill.className = 'tool-pill';
  pill.textContent = tool;
  el.toolPills.appendChild(pill);
}

// ── Target management ─────────────────────────────────────────────────
function setTarget(target) {
  state.target = (target || '').trim();
  el.targetVal.textContent = state.target || '—';
  if (state.target) {
    el.inputTarget.hidden = false;
    el.inputTargetLabel.textContent = `target: ${state.target}`;
  } else {
    el.inputTarget.hidden = true;
  }
}

// ── Send message ───────────────────────────────────────────────────────
async function sendMessage() {
  const text = el.input.value.trim();
  if (!text) return;
  if (!state.sessionId) {
    toast('warn', 'No session', 'Create a session first.');
    return;
  }
  // Auto-detect IP in message if no target set yet
  if (!state.target) {
    const ipm = text.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
    if (ipm) setTarget(ipm[1]);
  }
  addUserMessage(text);
  el.input.value = '';
  el.input.style.height = 'auto';
  el.thinking.classList.remove('hidden');

  try {
    const resp = await api('/api/pentest/v8/input', {
      method: 'POST',
      body: {
        user_input: text,
        session_id: state.sessionId,
        current_target: state.target,
        context_type: 'internal_corporate',
        chat_history: [],
        tools_run: Array.from(toolsRun),
      },
    });
    el.thinking.classList.add('hidden');

    if (resp && resp.plan) {
      const plan = resp.plan;
      state.phase = plan.current_phase || state.phase;
      updatePhaseUI();
      const risk = (plan.commands || []).some(c => c.risk_color === 'red')  ? 'red'
                 : (plan.commands || []).some(c => c.risk_color === 'orange') ? 'orange'
                 : 'green';
      addAriaMessage({
        text: plan.suggested_reply || '',
        phase: state.phase,
        risk,
        commands: plan.commands,
        reasoning: plan.react_trace || [],
      });
    } else if (resp) {
      addAriaMessage({ text: resp.suggested_reply || JSON.stringify(resp) });
    }
    refreshKB();
  } catch (exc) {
    el.thinking.classList.add('hidden');
    toast('danger', 'Request failed', exc.message);
  }
}

// ── Run a single command ───────────────────────────────────────────────
async function runCommand(cmd) {
  if (cmd.risk_color === 'red') {
    if (!confirm(`This is a RED-risk command. Run anyway?\n\n${cmd.command}`)) return;
  }
  addToolPill(cmd.tool);
  toast('info', 'Dispatching', cmd.tool || 'command');
  try {
    const res = await api('/api/pentest/kali/execute', {
      method: 'POST',
      body: {
        session_id: state.sessionId,
        command:    cmd.command,
        tool:       cmd.tool,
        target:     state.target,
      },
    });
    if (res && (res.stdout || res.stderr)) {
      await api('/api/pentest/tool-results', {
        method: 'POST',
        body: {
          session_id: state.sessionId,
          agent_type: cmd.agent || 'scan',
          command: cmd.command,
          stdout: res.stdout || '',
          stderr: res.stderr || '',
          exit_code: res.exit_code || 0,
          target: state.target,
        },
      });
      toast('success', 'Done', `${cmd.tool} completed`);
      refreshKB();
    }
  } catch (exc) {
    toast('danger', 'Exec failed', exc.message);
  }
}

// ── AUTO mode ──────────────────────────────────────────────────────────
async function toggleAuto() {
  if (state.autoActive) await stopAuto();
  else await startAuto();
}

async function startAuto() {
  if (!state.target) {
    toast('warn', 'Target required',
          'Set a target (e.g. 192.168.57.10) before starting auto mode.');
    return;
  }
  if (!state.sessionId) {
    toast('warn', 'No session', 'Create a session first.');
    return;
  }
  try {
    const res = await api(`/api/pentest/${state.sessionId}/autonomous/start`, {
      method: 'POST',
      body: { goal: state.goalSelect || 'initial_access', target: state.target },
    });
    if (res && (res.status === 'started' || res.status === 'already_running')) {
      state.autoActive = true;
      updateAutoUI();
      connectAutoWS();
      toast('success', 'AUTO mode active',
            `Goal: ${state.goalSelect || 'initial_access'}`);
    } else {
      toast('warn', 'Auto', res?.status || 'unknown');
    }
  } catch (exc) {
    toast('danger', 'Auto start failed', exc.message);
  }
}

async function stopAuto() {
  try {
    await api(`/api/pentest/${state.sessionId}/autonomous/stop`, { method: 'POST' });
    state.autoActive = false;
    updateAutoUI();
    if (state.ws) { state.ws.close(); state.ws = null; }
    toast('info', 'AUTO stopped', 'Autonomous cycle ended');
  } catch (exc) {
    toast('danger', 'Auto stop failed', exc.message);
  }
}

function updateAutoUI() {
  if (state.autoActive) {
    el.autoBtn.dataset.state = 'on';
    el.autoLabel.textContent = 'AUTONOMOUS — RUNNING';
    el.autoLog.classList.remove('hidden');
    el.autoRun.classList.remove('hidden');
  } else {
    el.autoBtn.dataset.state = 'off';
    el.autoLabel.textContent = 'Auto mode';
    el.autoRun.classList.add('hidden');
  }
}

// ── WebSocket ──────────────────────────────────────────────────────────
function connectAutoWS() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = `${proto}//${location.host}/api/pentest/ws/${state.sessionId}/auto`
              + `?token=${encodeURIComponent(state.token)}`;
  let ws;
  try {
    ws = new WebSocket(url);
  } catch (exc) {
    toast('danger', 'WebSocket', exc.message);
    return;
  }
  state.ws = ws;

  ws.onmessage = (e) => {
    let ev;
    try { ev = JSON.parse(e.data); } catch { return; }
    handleAutoEvent(ev);
  };
  ws.onerror = () => {
    // errors often precede close; handled in onclose
  };
  ws.onclose = () => {
    if (state.autoActive) {
      setTimeout(() => { if (state.autoActive) connectAutoWS(); }, 2000);
    }
  };
}

function handleAutoEvent(ev) {
  switch (ev.type) {
    case 'auto_activity':
      renderAutoLine(ev);
      if (ev.step) {
        state.autoStep = ev.step;
        el.autoCount.textContent = `step ${ev.step} / ${state.autoMaxSteps}`;
      }
      if (ev.tool) addToolPill(ev.tool);
      if (ev.status === 'done') refreshKB();
      break;

    case 'waiting_approval':
      state.pendingApprovals.push(ev);
      showApprovalBanner(ev);
      renderAutoLine(ev);
      break;

    case 'plan_updated':
      toast('info', 'Plan updated',
            `Trigger: ${ev.trigger || 'replan'} on ${ev.host || '?'}`);
      refreshKB();
      break;

    case 'goal_achieved':
      toast('success', '🎯 Goal achieved', ev.action || '');
      renderAutoLine({...ev, type: 'auto_activity', status: 'done',
                       action: `🎯 ${ev.action}`});
      refreshKB();
      break;

    case 'auto_complete':
      renderAutoLine({...ev, type: 'auto_activity', status: 'done',
                       action: ev.action || 'Autonomous cycle complete'});
      state.autoActive = false;
      updateAutoUI();
      break;

    case 'auto_error':
      toast('danger', 'Auto error', ev.action || '');
      renderAutoLine({...ev, type: 'auto_activity', status: 'failed'});
      break;
  }
}

function renderAutoLine(ev) {
  const line = document.createElement('div');
  line.className = 'auto-log-line';
  line.dataset.status = ev.status || 'done';

  const mark = document.createElement('span');
  mark.className = 'mark';
  mark.textContent = {
    running: '⚙',
    done: '✓',
    failed: '✗',
    waiting_approval: '⏸',
  }[ev.status] || '•';
  line.appendChild(mark);

  if (ev.step) {
    const badge = document.createElement('span');
    badge.className = 'step-badge';
    badge.textContent = `${ev.step}/${state.autoMaxSteps}`;
    line.appendChild(badge);
  }

  const body = document.createElement('span');
  body.className = 'body';
  body.textContent = ev.action || '';
  line.appendChild(body);

  if (ev.risk_color) {
    const r = document.createElement('span');
    r.className = `risk ${ev.risk_color}`;
    r.textContent = ev.risk_color;
    line.appendChild(r);
  }

  el.autoLines.appendChild(line);
  el.autoLines.scrollTop = el.autoLines.scrollHeight;

  if (ev.kb_updates && ev.kb_updates.length) {
    ev.kb_updates.slice(0, 3).forEach(u => {
      const sub = document.createElement('div');
      sub.className = 'auto-log-line';
      sub.dataset.status = 'done';
      const m = document.createElement('span');
      m.className = 'mark';
      m.textContent = '↳';
      const b = document.createElement('span');
      b.className = 'body';
      b.textContent = u;
      sub.append(m, b);
      el.autoLines.appendChild(sub);
    });
    el.autoLines.scrollTop = el.autoLines.scrollHeight;
  }
}

// ── Approval banner ────────────────────────────────────────────────────
function showApprovalBanner(req) {
  el.approvalDetail.textContent =
      `Step ${req.step}: ${req.reason || req.purpose || ''}`;
  el.approvalCommand.textContent = req.action || '';
  el.approvalBanner.classList.remove('hidden');
  el.btnApprove.dataset.actionId = req.action_id;
  el.btnReject.dataset.actionId  = req.action_id;
  el.btnModify.dataset.actionId  = req.action_id;
  el.btnApprove.dataset.command  = req.action || '';
}

async function submitApproval(decision) {
  const actionId = el.btnApprove.dataset.actionId;
  if (!actionId) return;
  let modifiedCommand = '';
  if (decision === 'modify') {
    modifiedCommand = prompt('Modified command:',
                              el.btnApprove.dataset.command || '');
    if (!modifiedCommand) return;
  }
  try {
    await api(`/api/pentest/${state.sessionId}/autonomous/approve`, {
      method: 'POST',
      body: {
        action_id: actionId,
        decision,
        modified_command: modifiedCommand,
      },
    });
    el.approvalBanner.classList.add('hidden');
    toast('info', `Decision: ${decision}`, 'Recorded in decision log.');
    const rem = state.pendingApprovals.filter(a => a.action_id !== actionId);
    state.pendingApprovals = rem;
    if (rem.length) showApprovalBanner(rem[0]);
    // Refresh decision log tab if it's currently active
    const active = document.querySelector('.intel-tab.active');
    if (active && active.dataset.tab === 'decisions') loadDecisionLog();
  } catch (exc) {
    toast('danger', 'Approval failed', exc.message);
  }
}

// ── Intel panel refresh ────────────────────────────────────────────────
async function refreshKB() {
  if (!state.sessionId) return;
  try {
    const snap = await api(`/api/pentest/${state.sessionId}/kb-snapshot`);
    if (snap) renderIntel(snap);
  } catch (exc) {
    // silent
  }
}

function renderIntel(snap) {
  renderHosts(snap.hosts || []);
  renderShells(snap.hosts || []);
  renderCreds(snap.hosts || []);
  renderFindingsPanel(snap.hosts || []);
  renderTimeline(snap.timeline || []);
}

function renderHosts(hosts) {
  const root = el.bodies.hosts;
  root.textContent = '';
  if (!hosts.length) { emptyState(root, 'No hosts discovered yet.'); return; }
  hosts.forEach(h => {
    const card = document.createElement('div');
    card.className = 'host-card';

    const head = document.createElement('div');
    head.className = 'host-card-head';
    const ip = document.createElement('div');
    ip.className = 'host-ip';
    ip.textContent = h.ip + (h.hostname ? ` (${h.hostname})` : '');
    head.appendChild(ip);
    if (h.os) {
      const os = document.createElement('span');
      os.className = 'host-os';
      os.textContent = h.os.slice(0, 30);
      head.appendChild(os);
    }
    card.appendChild(head);

    if (h.ports && h.ports.length) {
      const grid = document.createElement('div');
      grid.className = 'host-ports';
      h.ports.forEach(p => {
        const pill = document.createElement('span');
        pill.className = 'port-pill';
        pill.dataset.sev = sevForPort(p.port, p.version);
        pill.textContent = `${p.port}/${p.service || '?'}`;
        pill.title = `${p.service} ${p.version}`;
        pill.onclick = () => togglePortDetail(pill, p);
        grid.appendChild(pill);
      });
      card.appendChild(grid);
    }
    if (h.vulnerabilities && h.vulnerabilities.length) {
      const v = document.createElement('div');
      v.className = 'cmd-purpose';
      v.textContent = `${h.vulnerabilities.length} vulnerability finding(s)`;
      card.appendChild(v);
    }
    root.appendChild(card);
  });
}

function togglePortDetail(pill, p) {
  pill.classList.toggle('expanded');
  if (pill.nextElementSibling && pill.nextElementSibling.classList.contains('port-detail')) {
    pill.nextElementSibling.remove();
    return;
  }
  const d = document.createElement('div');
  d.className = 'port-detail';
  d.textContent = `${p.service} ${p.version}${p.banner ? '  ·  ' + p.banner : ''}`;
  pill.after(d);
}

function sevForPort(port, ver) {
  if (/vsftpd 2\.3\.4/i.test(ver || '')) return 'critical';
  if (/unreal/i.test(ver || '')) return 'critical';
  if ([21, 23, 445, 3306, 5432].includes(port)) return 'high';
  if ([80, 443, 8080, 22].includes(port)) return 'medium';
  return '';
}

function renderShells(hosts) {
  const root = el.bodies.shells;
  root.textContent = '';
  const all = [];
  hosts.forEach(h => (h.shells || []).forEach(s => all.push({...s, host: h.ip})));
  if (!all.length) { emptyState(root, 'No shells obtained.'); return; }
  all.forEach(s => {
    const c = document.createElement('div');
    c.className = 'host-card';
    c.textContent = `${(s.type || 'shell').toUpperCase()} on ${s.host}:${s.port} `
                     + `as ${s.user} [${s.privilege}]`;
    root.appendChild(c);
  });
}

function renderCreds(hosts) {
  const root = el.bodies.creds;
  root.textContent = '';
  const all = [];
  hosts.forEach(h => (h.credentials || []).forEach(c => all.push({...c, host: h.ip})));
  if (!all.length) { emptyState(root, 'No credentials captured.'); return; }
  all.forEach(c => {
    const card = document.createElement('div');
    card.className = 'host-card';
    card.textContent = `${c.user}${c.has_password ? ' (password set)' : ''}`
                        + ` @ ${c.host}:${c.port}/${c.service || '?'}`;
    root.appendChild(card);
  });
}

function renderFindingsPanel(hosts) {
  const root = el.bodies.findings;
  root.textContent = '';
  const all = [];
  hosts.forEach(h => (h.vulnerabilities || []).forEach(v => all.push({...v, host: h.ip})));
  all.sort((a, b) => (b.cvss || 0) - (a.cvss || 0));
  if (!all.length) { emptyState(root, 'No findings yet.'); return; }
  all.forEach(v => root.appendChild(renderFinding({
    title: v.title + (v.host ? `  @ ${v.host}` : ''),
    description: v.description || '',
    cve_ids: v.cve_ids || [],
    cvss_score: v.cvss || 0,
  })));
}

function renderTimeline(events) {
  const root = el.bodies.timeline;
  root.textContent = '';
  if (!events.length) { emptyState(root, 'No events yet.'); return; }
  events.slice().reverse().forEach(e => {
    const ev = document.createElement('div');
    ev.className = 'timeline-event';
    ev.dataset.type = e.event || '';
    const ts = document.createElement('span');
    ts.className = 'ts';
    ts.textContent = (e.ts || '').replace('T', ' ').slice(0, 19);
    ev.appendChild(ts);
    const body = document.createElement('span');
    body.textContent = e.detail || '';
    ev.appendChild(body);
    root.appendChild(ev);
  });
}

// ── Decision log (academic brief: traceability) ────────────────────────
async function loadDecisionLog() {
  const root = el.bodies.decisions;
  root.textContent = '';
  try {
    const res = await api(`/api/pentest/${state.sessionId}/decision-log?limit=100`);
    if (!res || !res.entries || !res.entries.length) {
      emptyState(root, 'No decisions recorded yet.');
      return;
    }
    res.entries.forEach(e => root.appendChild(renderDecisionEntry(e)));
  } catch (exc) {
    emptyState(root, 'Could not load decision log.');
  }
}

function renderDecisionEntry(e) {
  const card = document.createElement('div');
  card.className = 'decision-entry';
  if (e.human_involved) card.classList.add('human-involved');

  const head = document.createElement('div');
  head.className = 'head';
  const type = document.createElement('span');
  type.className = 'type';
  type.textContent = e.type || '';
  head.appendChild(type);
  if (e.human_involved) {
    const b = document.createElement('span');
    b.className = 'badge-human';
    b.textContent = e.human_decision || 'human';
    head.appendChild(b);
  }
  if (e.step) {
    const step = document.createElement('span');
    step.className = 'step';
    step.textContent = `step ${e.step}`;
    head.appendChild(step);
  }
  card.appendChild(head);

  if (e.reasoning) {
    const r = document.createElement('div');
    r.className = 'reasoning';
    r.textContent = e.reasoning;
    card.appendChild(r);
  }
  if (e.action) {
    const a = document.createElement('div');
    a.className = 'action';
    a.textContent = e.action;
    a.title = e.action;
    card.appendChild(a);
  }
  if (e.created_at) {
    const ts = document.createElement('div');
    ts.className = 'step';
    ts.style.fontSize = '10px';
    ts.textContent = (e.created_at || '').replace('T', ' ').slice(0, 19);
    card.appendChild(ts);
  }
  return card;
}

// ── Playbooks tab ──────────────────────────────────────────────────────
async function loadPlaybooks() {
  const root = el.bodies.playbooks;
  root.textContent = '';
  try {
    const res = await api(`/api/pentest/${state.sessionId}/playbooks`);
    if (!res || !res.playbooks || !res.playbooks.length) {
      emptyState(root, 'No playbooks saved yet. They appear after successful engagements.');
      return;
    }
    res.playbooks.forEach(p => root.appendChild(renderPlaybookCard(p)));
  } catch (exc) {
    emptyState(root, 'Could not load playbooks.');
  }
}

function renderPlaybookCard(p) {
  const card = document.createElement('div');
  card.className = 'playbook-card';

  const head = document.createElement('div');
  head.className = 'head';
  const svc = document.createElement('span');
  svc.className = 'svc';
  svc.textContent = `${p.service} → ${p.goal_type}`;
  head.appendChild(svc);
  const rate = document.createElement('span');
  rate.className = 'success-rate';
  rate.textContent = `${Math.round((p.success_rate || 0) * 100)}% (${p.success_count}/${p.success_count + p.failure_count})`;
  head.appendChild(rate);
  card.appendChild(head);

  if (p.steps && p.steps.length) {
    const steps = document.createElement('div');
    steps.className = 'cmd-purpose';
    steps.textContent = `${p.steps.length} steps`;
    card.appendChild(steps);
  }

  if (p.tags && p.tags.length) {
    const tags = document.createElement('div');
    tags.className = 'tags';
    p.tags.forEach(t => {
      const s = document.createElement('span');
      s.textContent = t;
      tags.appendChild(s);
    });
    card.appendChild(tags);
  }
  return card;
}

// ── Session list ───────────────────────────────────────────────────────
async function loadSessions() {
  try {
    const res = await api('/api/sessions/list');
    if (!res) return;
    el.sessionList.textContent = '';
    (res.sessions || []).forEach(s => {
      const item = document.createElement('div');
      item.className = 'session-item';
      if (s.id === state.sessionId) item.classList.add('active');
      item.textContent = s.name || s.target || s.id.slice(0, 8);
      item.onclick = () => switchSession(s);
      el.sessionList.appendChild(item);
    });
  } catch (exc) {
    // silent
  }
}

function switchSession(s) {
  state.sessionId = s.id;
  localStorage.setItem('current_session', s.id);
  el.sessionName.textContent = s.name || s.id.slice(0, 8);
  setTarget(s.target || '');
  state.phase = s.current_phase || 'scope';
  updatePhaseUI();
  el.messages.textContent = '';
  loadSessions();
  refreshKB();
}

async function createNewSession() {
  const target = prompt('Target (IP or URL):');
  if (!target) return;
  try {
    const res = await api('/api/sessions/create', {
      method: 'POST',
      body: { target, name: `Session ${new Date().toLocaleString()}` },
    });
    if (res && res.id) {
      switchSession(res);
      toast('success', 'Session created', target);
    }
  } catch (exc) {
    toast('danger', 'Create failed', exc.message);
  }
}

// ── Settings ───────────────────────────────────────────────────────────
function openSettings() {
  el.settingsPanel.classList.remove('hidden');
  loadLLMKeys();
}
function closeSettings() {
  el.settingsPanel.classList.add('hidden');
}

async function loadLLMKeys() {
  try {
    const res = await api('/api/api-keys/list');
    if (!res) return;
    el.llmKeysList.textContent = '';
    (res.keys || []).forEach(k => {
      const row = document.createElement('div');
      row.className = 'form-row';
      const lbl = document.createElement('span');
      lbl.textContent = `${k.provider}: ${k.label || '(no label)'} · ${k.state}`;
      row.appendChild(lbl);
      const del = document.createElement('button');
      del.className = 'btn btn-ghost';
      del.textContent = 'Delete';
      del.onclick = () => deleteKey(k.key_id);
      row.appendChild(del);
      el.llmKeysList.appendChild(row);
    });
  } catch (exc) {
    // silent
  }
}
async function deleteKey(keyId) {
  if (!confirm('Delete this API key?')) return;
  try {
    await api(`/api/api-keys/${keyId}`, { method: 'DELETE' });
    loadLLMKeys();
    toast('info', 'Key deleted', '');
  } catch (exc) {
    toast('danger', 'Delete failed', exc.message);
  }
}
async function addKey() {
  const provider = el.newKeyProvider.value;
  const apiKey = el.newKeyValue.value.trim();
  const label = el.newKeyLabel.value.trim();
  if (!apiKey) { toast('warn', 'Empty key', ''); return; }
  try {
    await api('/api/api-keys/add', {
      method: 'POST',
      body: { provider, api_key: apiKey, label },
    });
    el.newKeyValue.value = '';
    el.newKeyLabel.value = '';
    loadLLMKeys();
    toast('success', 'Key added', provider);
  } catch (exc) {
    toast('danger', 'Add failed', exc.message);
  }
}

// ── Bindings ───────────────────────────────────────────────────────────
function bindEvents() {
  // Send button & Enter
  el.sendBtn.onclick = sendMessage;
  el.input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  });
  // Auto-growing textarea
  el.input.addEventListener('input', () => {
    el.input.style.height = 'auto';
    el.input.style.height = Math.min(el.input.scrollHeight, 180) + 'px';
  });

  // Auto mode
  el.autoBtn.onclick = toggleAuto;

  // Goal / mode selects
  el.goalSel.onchange = (e) => state.goalSelect = e.target.value;
  el.modeSel.onchange = (e) => {
    state.modeSelect = e.target.value;
    // Optionally push mode to server
  };

  // Target chip clear
  el.inputTargetClear.onclick = () => setTarget('');

  // Intel tabs
  el.tabs.forEach(tab => {
    tab.onclick = () => {
      el.tabs.forEach(t => t.classList.remove('active'));
      Object.values(el.bodies).forEach(b => b.classList.remove('active'));
      tab.classList.add('active');
      const target = el.bodies[tab.dataset.tab];
      if (target) target.classList.add('active');
      // Lazy load tabs
      if (tab.dataset.tab === 'decisions') loadDecisionLog();
      if (tab.dataset.tab === 'playbooks') loadPlaybooks();
    };
  });

  // Approval banner
  el.btnApprove.onclick = () => submitApproval('approve');
  el.btnReject.onclick  = () => submitApproval('reject');
  el.btnModify.onclick  = () => submitApproval('modify');

  // Settings
  el.settingsBtn.onclick   = openSettings;
  el.settingsClose.onclick = closeSettings;
  if (el.maxStepsInput) {
    el.maxStepsInput.oninput = () => {
      el.maxStepsValue.textContent = el.maxStepsInput.value;
      state.autoMaxSteps = parseInt(el.maxStepsInput.value, 10) || 12;
    };
  }
  if (el.newKeyAdd) el.newKeyAdd.onclick = addKey;

  // New session
  el.newSessionBtn.onclick = createNewSession;
}

// ── Boot ───────────────────────────────────────────────────────────────
async function boot() {
  if (!state.token) {
    window.location.href = '/login.html';
    return;
  }
  bindEvents();
  updatePhaseUI();
  await loadSessions();
  if (state.sessionId) {
    try {
      const s = await api(`/api/sessions/${state.sessionId}`);
      if (s) {
        el.sessionName.textContent = s.name || s.id.slice(0, 8);
        setTarget(s.target || '');
        state.phase = s.current_phase || 'scope';
        updatePhaseUI();
      }
    } catch {}
    await refreshKB();
    // Check if auto is already running on this session (page reload case)
    try {
      const status = await api(`/api/pentest/${state.sessionId}/autonomous/status`);
      if (status && status.active) {
        state.autoActive = true;
        state.autoMaxSteps = status.max_steps || 12;
        updateAutoUI();
        connectAutoWS();
      }
    } catch {}
  } else {
    addAriaMessage({
      text: 'Welcome to PentestAI v10. Create a session to begin, then set a '
          + 'target and either chat your goal or click AUTO to run the '
          + 'collaborative loop.\n\nRemember: any red-risk step (exploit, '
          + 'brute-force) will pause the autonomous cycle and ask for your '
          + 'explicit approval.',
      phase: 'scope',
    });
  }

  // Periodic KB refresh every 15s (belt-and-braces alongside WS)
  setInterval(refreshKB, 15000);
}

document.addEventListener('DOMContentLoaded', boot);
})();
