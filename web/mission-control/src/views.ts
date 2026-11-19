import { diagnostics, number, object, records, request, rows, signedReportArchive, strings, text, type Json, type TimelineEvent } from './api'
import { accents, type MissionStore, type Preferences } from './store'
import { badge, button, card, count, date, el, empty, fields, human, labelControl, link, money, recordButton,
  select, status, windowed } from './dom'
import { budgetSummary, eventDetail, recordFields, sourceCard, taskState, taskTitle, type Detail, type Go, type Lazy } from './panels'
import type { Edge, Node as GraphNode } from './graph'

type ReplayWindow = { records: TimelineEvent[]; capturedAt: number; campaignId: string | null; gap: boolean }

export type Filters = { sessionQuery: string; sessionState: string; sessionDate: string; role: string; run: string;
  task: string; taskState: string; eventQuery: string; eventSource: string; replay: ReplayWindow | null; replayIndex: number;
  renderer: string; provider: string; model: string; campaign: string; attemptAgent: string; timeWindow: string }
export const defaultFilters = (): Filters => ({ sessionQuery: '', sessionState: '', sessionDate: '', role: '', run: '',
  task: '', taskState: '', eventQuery: '', eventSource: '', replay: null, replayIndex: 0, renderer: 'canvas',
  provider: '', model: '', campaign: '', attemptAgent: '', timeWindow: '' })

const unique = (values: string[]) => [...new Set(values.filter(Boolean))].sort()
function filterText(label: string, value: string, key: string, update: (value: string) => void) {
  const search = el('input')
  search.type = 'search'
  search.value = value
  search.dataset.focus = key
  search.addEventListener('input', () => update(search.value))
  return labelControl(label, search)
}
function filterSelect(label: string, values: string[], value: string, update: (next: string) => void,
                      format: (value: string) => string = human) {
  const control = select([['', 'All'], ...values.map(item => [item, format(item)] as [string, string])], value, update)
  control.dataset.focus = label
  return labelControl(label, control)
}

export function sessions(store: MissionStore, detail: Detail, filters: Filters, change: () => void) {
  const create = button('New session', () => {
    const form = el('form', 'stack')
    const name = el('input')
    name.required = true
    name.maxLength = 100
    name.autocomplete = 'off'
    const target = el('input')
    target.required = true
    target.maxLength = 253
    target.autocomplete = 'off'
    const feedback = el('p', 'subtle')
    feedback.setAttribute('role', 'status')
    const submit = el('button', 'button primary', 'Create session')
    submit.type = 'submit'
    form.append(labelControl('Session name', name), labelControl('Engagement target', target), submit, feedback)
    form.addEventListener('submit', async event => {
      event.preventDefault()
      if (!name.value.trim() || !target.value.trim()) {
        feedback.textContent = 'Enter a session name and a target.'
        return
      }
      submit.disabled = true
      feedback.textContent = 'Creating session…'
      await store.create(name.value.trim(), target.value.trim())
      feedback.textContent = store.notice
      submit.disabled = false
    })
    detail('New session', [form])
  }, 'button primary', 'plus')
  create.disabled = !!store.action
  const source = store.slot('sessions')
  const records = store.sessions()
  const today = Date.now()
  const filtered = records.filter(record => {
    const match = [record.name, record.target, record.session_id].some(value => text(value).toLowerCase().includes(filters.sessionQuery.toLowerCase()))
    const ms = Date.parse(text(record.updated_at ?? record.created_at))
    return match && (!filters.sessionState || record.status === filters.sessionState) &&
      (!filters.sessionDate || Number.isFinite(ms) && ms <= today && ms >= today - Number(filters.sessionDate) * 86400000)
  })
  return [card('Session index', [
    el('div', 'filter-grid',
      filterText('Search name or target', filters.sessionQuery, 'session-query', value => { filters.sessionQuery = value; change() }),
      filterSelect('Session status', unique(records.map(record => text(record.status))), filters.sessionState,
        value => { filters.sessionState = value; change() }),
      labelControl('Updated', select([['', 'Any date'], ['1', 'Last 24 hours'], ['7', 'Last 7 days'], ['30', 'Last 30 days']],
        filters.sessionDate, value => { filters.sessionDate = value; change() }))),
    ...(status(source) ? [status(source)!] : []),
    source.value ? el('p', 'subtle', count(filtered.length) + ' of ' + count(records.length) + ' sessions') : el('span'),
    ...(filtered.length ? [windowed(filtered, record => recordButton(text(record.name, text(record.target, 'Unnamed session')),
      text(record.target, 'Scope not recorded') + ' · ' + date(record.updated_at ?? record.created_at),
      record.session_id === store.sid ? 'selected' : record.status,
      () => store.navigate('overview', text(record.session_id))), 'Sessions')] : source.value ? [
      empty(records.length ? 'No sessions match these filters.' : 'Create a session to start organizing records.')
    ] : [])
  ], { action: create })]
}

export function agents(store: MissionStore, detail: Detail, go: Go, lazy: Lazy, filters: Filters, change: () => void) {
  const ledger = store.value('team')
  const roster = rows(store.value('roster')?.agents)
  const tasks = rows(ledger?.tasks)
  const evidence = rows(ledger?.evidence)
  const attempts = rows(store.value('budget')?.attempts)
  const advanced = store.preferences.mode === 'advanced'
  const observedState = (agent: Json) => {
    if (agent.registration === 'unavailable') return 'unavailable'
    const assignments = tasks.filter(task => task.owner_role === agent.id)
    return taskState(ledger && (assignments.length || agent.registration === 'team_specialist') ? assignments : null)
  }

  const inspectEvidence = (record: Json) => detail('Evidence record', [recordFields(record, ['id', 'source_kind', 'source_id', 'summary', 'created_at']),
    button('Open investigation', () => go('investigation'))])
  const inspectTask = (record: Json) => {
    const model = attempts.filter(attempt => attempt.task_id === record.id)
    const assignedEvidence = evidence.filter(item => strings(record.evidence_inputs).includes(text(item.id)))
    detail(taskTitle(record), [badge(record.state),
      recordFields(record, ['owner_role', 'objective', 'reason', 'created_at', 'expected_output',
        ...(advanced ? ['id', 'run_id', 'campaign_id', 'dependencies', 'evidence_inputs'] : [])]),
      ...(model.length ? [el('h3', '', 'Recorded model attribution'), el('p', 'subtle', unique(model.map(
        attempt => text(attempt.provider) + ' / ' + text(attempt.model))).join(', '))] : []),
      ...assignedEvidence.map(item => recordButton(text(item.summary, 'Evidence ' + text(item.id)), human(item.source_kind),
        null, () => inspectEvidence(item))),
      ...tasks.filter(item => strings(record.dependencies).includes(text(item.id))).map(item =>
        recordButton(taskTitle(item), 'Recorded dependency', item.state, () => inspectTask(item))),
      button('View related events', () => { filters.eventQuery = text(record.id); go('events') })])
  }
  const inspectAgent = (record: Json) => {
    const assigned = tasks.filter(task => task.owner_role === record.id)
    detail(human(record.id), [el('p', '', text(record.role, 'Recorded role')), badge(observedState(record)),
      el('p', 'subtle', human(record.registration, 'Registration unknown')),
      el('h3', '', 'Assigned tasks'),
      ...(assigned.length ? assigned.map(task => recordButton(taskTitle(task), text(task.reason, date(task.created_at)), task.state,
        () => inspectTask(task))) : [empty(ledger ? 'No assignments recorded for this agent.' : 'Task ledger unavailable.')]),
      button('View agent events', () => { filters.eventQuery = text(record.id); go('events') })])
  }
  const visibleTasks = tasks.filter(task => (!filters.role || task.owner_role === filters.role) &&
    (!filters.run || task.run_id === filters.run) && (!filters.taskState || task.state === filters.taskState) &&
    (taskTitle(task) + ' ' + text(task.id)).toLowerCase().includes(filters.task.toLowerCase()))
  const graph = el('div', 'viz', empty('Preparing the orchestration graph…'))
  const visibleAgents = roster.filter(row => !filters.role || row.id === filters.role)
  const evidenceById = new Map(evidence.map(item => [text(item.id), item]))
  const taskById = new Map(visibleTasks.map(item => [text(item.id), item]))
  const agentById = new Map(visibleAgents.map(item => [text(item.id), item]))
  const linkedEvidence = advanced ? new Set(visibleTasks.flatMap(task => strings(task.evidence_inputs))) : new Set<string>()
  const graphNodes: GraphNode[] = [
    ...visibleAgents.map(record => ({ id: 'a:' + text(record.id), label: human(record.id), column: 0, kind: 'Agent',
      state: observedState(record) })),
    ...visibleTasks.map(task => ({ id: 't:' + text(task.id), label: taskTitle(task), column: 1, kind: 'Task', state: text(task.state, 'unknown') })),
    ...[...linkedEvidence].filter(id => evidenceById.has(id)).map(id => ({
      id: 'e:' + id, label: text(evidenceById.get(id)?.summary, id), column: 2, kind: 'Evidence', state: 'recorded'
    }))
  ]
  const edges: Edge[] = visibleTasks.flatMap(task => [
    { source: 'a:' + text(task.owner_role), target: 't:' + text(task.id), kind: 'Assignment' },
    ...strings(task.dependencies).map(id => ({ source: 't:' + id, target: 't:' + text(task.id), kind: 'Dependency' })),
    ...(advanced ? strings(task.evidence_inputs).map(id => ({ source: 't:' + text(task.id), target: 'e:' + id, kind: 'Evidence reference' })) : [])
  ])
  if (graphNodes.length) lazy(graph, async () => {
    const module = await import('./graph')
    if (!graph.isConnected) return
    return module.mountGraph(graph, { nodes: graphNodes, edges, label: 'Agent assignments and recorded dependencies',
      motion: store.preferences.motion, inspect(id) {
        const type = id.slice(0, 2)
        const key = id.slice(2)
        if (type === 'a:' && agentById.has(key)) inspectAgent(agentById.get(key)!)
        if (type === 't:' && taskById.has(key)) inspectTask(taskById.get(key)!)
        if (type === 'e:' && evidenceById.has(key)) inspectEvidence(evidenceById.get(key)!)
      } })
  })
  return [
    card('Recorded orchestration', [
      el('div', 'filter-grid',
        filterSelect('Agent', unique([...roster.map(row => text(row.id)), ...tasks.map(task => text(task.owner_role))]), filters.role,
          value => { filters.role = value; change() }),
        filterSelect('Task state', unique(tasks.map(task => text(task.state))), filters.taskState,
          value => { filters.taskState = value; change() }),
        filterSelect('Recorded task run', unique(tasks.map(task => text(task.run_id))), filters.run,
          value => { filters.run = value; change() }, value => value),
        filterText('Search tasks', filters.task, 'task-query', value => { filters.task = value; change() })),
      ...(status(store.slot('team')) ? [status(store.slot('team'))!] : []),
      ...(status(store.slot('roster')) ? [status(store.slot('roster'))!] : []),
      graphNodes.length ? graph : empty('No visible assignments or registered roles for this selection.'),
      el('p', 'subtle', 'Solid links show task assignments. Dashed links follow stored dependencies. Dotted links identify recorded evidence references.')
    ]),
    el('div', 'split-grid',
      card('Agent inventory', visibleAgents.length ? visibleAgents.map(record => recordButton(human(record.id),
        text(record.role) + ' · ' + human(record.registration), observedState(record), () => inspectAgent(record))) :
        [empty('No agent records available.')]),
      card('Task records', visibleTasks.length ? [windowed(visibleTasks, record => recordButton(taskTitle(record),
        human(record.owner_role) + ' · ' + text(record.reason, date(record.created_at)), record.state, () => inspectTask(record)), 'Task records')] :
        [empty(ledger ? 'No recorded tasks match these filters.' : 'Task ledger unavailable.')]))
  ]
}

const authorizationStates: Record<string, string | null> = {
  proposal_registered: null, approval_recorded: 'approved', rejection_recorded: 'rejected', authorization_consumed: 'consumed'
}

function authorizationEvents(operations: Json | null, sid: string): TimelineEvent[] {
  return rows(object(operations?.authorizations)?.records).flatMap(row => {
    const id = text(row.id)
    const action = text(row.action_id)
    const timestamp = text(row.timestamp)
    const kind = text(row.event)
    if (!id || !action || !Number.isFinite(Date.parse(timestamp)) || !Object.hasOwn(authorizationStates, kind)) return []
    return [{ id, timestamp, kind, source: 'authorization', sequence: null, session_id: sid, entity_id: action,
      stage: kind === 'proposal_registered' ? 'Execution proposal' : 'Authorization', state: authorizationStates[kind],
      decision: text(row.decision) || null, campaign_id: null, run_id: null, agent: null, task_id: null, job_id: null,
      reason_code: null, correlation_id: null, evidence_ids: [], dependency_ids: [] }]
  })
}

function authorizationCoverage(operations: Json) {
  const history = object(operations.authorizations)
  if (!history) return empty('Authorization journal unavailable.')
  const truncated = history.truncated === true ? 'Showing the newest ' + count(history.limit) + ' journal records.' : ''
  const omitted = number(history.omitted)
  const invalid = omitted ? count(omitted) + ' records had incomplete metadata and were omitted.' : ''
  return truncated || invalid ? el('p', 'subtle', [truncated, invalid].filter(Boolean).join(' ')) : null
}

export function operations(store: MissionStore, detail: Detail) {
  const campaign = store.value('campaign')
  const run = store.value('run')
  const operationData = store.value('operations')
  const advanced = store.preferences.mode === 'advanced'
  const campaignState = text(campaign?.state)
  const receipt = (row: Json) => detail('Worker receipt', [badge(row.state),
    fields([['Job ID', text(row.id, 'Unknown')], ['Recorded', date(row.created_at)],
      ['Cancellation requested', row.cancel_requested === true ? 'Yes' : 'No'],
      ['Exit code', typeof row.exit_code === 'number' ? String(row.exit_code) : 'Not recorded'],
      ...(advanced ? [['Output SHA-256', text(row.output_sha256, 'Not recorded')] as [string, string]] : [])])])
  const command = (row: Json) => detail('Recorded command', [recordFields(row,
    ['tool', 'state', 'duration_ms', 'agent', ...(advanced ? ['id'] : [])]),
    fields([['Recorded', date(row.timestamp)], ['Sanitized output', row.http_status ? 'HTTP status ' + String(row.http_status) : 'No public output recorded']])])
  const action = (method: 'pause' | 'resume' | 'cancel' | 'stop' | 'reject', id?: string) => {
    const sid = store.sid
    const title = { pause: 'Pause campaign', resume: 'Resume campaign', cancel: 'Cancel campaign', stop: 'Stop bounded run', reject: 'Reject proposal' }[method]
    detail(title, [el('p', '', method === 'reject' ? 'Reject this pending proposal for the selected session?' :
      method === 'resume' ? 'Resume this existing campaign? The server may schedule execution under the existing scope, approval and budget limits.' :
        'Send this containment request for the selected session? Server records will show the resulting state.'),
      button(title, () => {
        document.querySelector<HTMLDialogElement>('#inspector')?.close()
        if (store.sid !== sid) return
        void store.control(method, id)
      }, 'button danger')], true)
  }
  const controls = el('div', 'toolbar')
  if (store.slot('campaign').state === 'available' && campaignState === 'paused') {
    controls.append(button('Resume campaign', () => action('resume')))
  }
  if (store.slot('campaign').state === 'available' && ['scheduled', 'starting', 'running'].includes(campaignState)) {
    controls.append(button('Pause campaign', () => action('pause')))
  }
  if (store.slot('campaign').state === 'available' && ['scheduled', 'starting', 'running', 'pausing', 'paused'].includes(campaignState)) {
    controls.append(button('Cancel campaign', () => action('cancel'), 'button danger'))
  }
  if (store.slot('run').state === 'available' && store.slot('campaign').state === 'not_started' && run?.active === true) {
    controls.append(button('Stop bounded run', () => action('stop'), 'button danger'))
  }
  for (const child of controls.querySelectorAll('button')) child.disabled = !!store.action
  const pending = rows(operationData?.pending)
  const now = Date.now()
  const receipts = rows(operationData?.receipts)
  const commands = rows(operationData?.commands)
  return [
    card('Execution state and containment', [
      el('div', 'status-pair', badge(campaign?.state ?? store.slot('campaign').state, 'Campaign · ' +
        human(campaign?.state ?? store.slot('campaign').state)), badge(object(run?.mission)?.state, 'Bounded run · ' + human(object(run?.mission)?.state))),
      ...(status(store.slot('campaign')) ? [status(store.slot('campaign'))!] : []),
      ...(status(store.slot('run')) ? [status(store.slot('run'))!] : []),
      ...(text(object(run?.mission)?.reason) ? [el('p', '', text(object(run?.mission)?.reason))] : []),
      ...(store.containment?.action === 'stop' ? [el('p', 'callout',
        store.containment.state === 'cancellation_pending' || (store.containment.pending ?? 0) > 0 ?
          'Stop acknowledged. ' + (store.containment.pending === null ? 'Cancellation remains unconfirmed.' :
            count(store.containment.pending) + ' cancellation(s) remain unconfirmed.') +
            ' Worker and web replay termination must be confirmed before further execution.' :
          'Stop acknowledged by the server. Review the current run and retained receipts below.')] : []),
      ...(controls.children.length ? [controls] : [empty('No containment action is available for the current state.')])
    ]),
    sourceCard(store, 'operations', 'Stored web replay state', value => {
      const replay = object(value.web_replays)
      if (!replay) return [empty('Stored web replay state is unavailable. Termination cannot be confirmed from this source.')]
      return [fields([['Stored records', count(replay.records)], ['Pending cancellations', count(replay.pending_cancellations)],
        ['Unknown outcomes', count(replay.unknown_outcomes)]]),
        el('p', 'subtle', 'Durable state only. This view does not contact the desktop connector.'),
        ...((number(replay.pending_cancellations) ?? 0) > 0 || (number(replay.unknown_outcomes) ?? 0) > 0 ?
          [el('p', 'callout', 'Web replay termination remains unconfirmed. Review the connector before further execution.')] : [])]
    }),
    sourceCard(store, 'operations', 'Pending proposals', () => pending.length ? pending.map(row => {
      const expires = Date.parse(text(row.expires_at))
      const open = Number.isFinite(expires) && expires > now
      const reject = button('Reject proposal', () => action('reject', text(row.action_id)), 'button small danger')
      reject.disabled = !!store.action || store.slot('operations').state !== 'available'
      return el('div', 'proposal', el('div', '', el('strong', '', human(row.tool, 'Review required')),
        el('small', '', (open ? 'Expires ' : 'Expiry · ') + date(row.expires_at))),
        advanced ? el('small', 'mono', text(row.action_id)) : null, open ? reject : badge('blocked', Number.isFinite(expires) ? 'Expired' : 'Expiry unknown'))
    }) : [empty('No pending approvals were recorded in this session.')]),
    sourceCard(store, 'operations', 'Authorization history', value => {
      const history = authorizationEvents(value, store.sid)
      const coverage = authorizationCoverage(value)
      return [el('p', 'subtle', 'Recorded lifecycle from the durable journal. The review queue shows current pending proposals.'),
        ...(coverage ? [coverage] : []),
        ...(history.length ? [windowed(history, event => recordButton(human(event.kind), date(event.timestamp), event.state,
          () => eventDetail(event, detail, advanced)), 'Authorization history')] : value.authorizations ? [empty('No authorization events recorded.')] : [])]
    }),
    el('div', 'split-grid',
      sourceCard(store, 'operations', 'Worker receipts', () => operationData?.receipts === null ? [
        badge('unavailable', 'Receipt store unavailable')
      ] : receipts.length ? [windowed(receipts, row => recordButton(text(row.id), date(row.created_at), row.state, () => receipt(row)),
        'Worker receipts')] : [empty('No retained worker receipts.')]),
      sourceCard(store, 'operations', 'Command history', () => commands.length ? [
        el('p', 'subtle', 'Process-local command history'),
        windowed(commands, row => recordButton(human(row.tool, 'Recorded command'), date(row.timestamp) +
          (row.http_status ? ' · HTTP ' + row.http_status : ''), row.state, () => command(row)), 'Command history')
      ] : [empty('No commands retained by this API process.')]))
  ]
}

const stages = ['Objective', 'Planning', 'Agent task', 'Execution proposal', 'Authorization', 'Worker execution',
  'Observation', 'Evidence', 'Verification', 'Review', 'Outcome']

function eventGraph(events: TimelineEvent[], root: HTMLElement, store: MissionStore, detail: Detail, lazy: Lazy) {
  const recent = events.slice(0, 70)
  const byEntity = new Map<string, TimelineEvent>()
  const authorizationNext = new Map<string, TimelineEvent>()
  const correlations = new Map<string, TimelineEvent>()
  const edges: Edge[] = []
  const ids = (event: TimelineEvent) => event.source + ':' + (event.campaign_id ?? event.session_id) + ':' + event.id
  for (const event of recent) if (event.entity_id && !byEntity.has(event.entity_id)) byEntity.set(event.entity_id, event)
  for (const event of recent) {
    const id = ids(event)
    if (event.source === 'authorization' && event.entity_id) {
      const next = authorizationNext.get(event.entity_id)
      if (next) edges.push({ source: id, target: ids(next), kind: 'Recorded authorization' })
      authorizationNext.set(event.entity_id, event)
    }
    for (const ref of [...event.dependency_ids, ...event.evidence_ids]) {
      const record = byEntity.get(ref)
      if (record && ids(record) !== id) edges.push({ source: ids(record), target: id, kind: 'Recorded reference' })
    }
    const scope = event.correlation_id && event.campaign_id ? event.campaign_id + ':' + event.correlation_id : null
    const receipt = event.source === 'team' && event.job_id ? byEntity.get(event.job_id) : undefined
    if (receipt?.source === 'worker') edges.push({ source: ids(receipt), target: id, kind: 'Recorded reference' })
    const prior = scope ? correlations.get(scope) : undefined
    if (prior) edges.push({ source: id, target: ids(prior), kind: 'Shared correlation' })
    if (scope) correlations.set(scope, event)
  }
  const stageIndex = (stage: string) => stages.includes(stage) ? stages.indexOf(stage) : stages.length
  const activeStages = [...new Set(recent.map(event => event.stage))].sort((a, b) => stageIndex(a) - stageIndex(b))
  lazy(root, async () => {
    const module = await import('./graph')
    if (!root.isConnected) return
    return module.mountGraph(root, { nodes: recent.map(event => ({ id: ids(event), label: human(event.kind),
      state: text(event.state, 'recorded'), column: activeStages.indexOf(event.stage), kind: event.stage })),
      edges, label: 'Retained event relationships', motion: store.preferences.motion, inspect(id) {
        const event = recent.find(event => ids(event) === id)
        if (event) eventDetail(event, detail, true)
      } })
  })
}

export function events(store: MissionStore, detail: Detail, lazy: Lazy, filters: Filters, change: () => void) {
  const advanced = store.preferences.mode === 'advanced'
  const archived = store.campaignSnapshot
  const operations = store.value('operations')
  const authorizations = authorizationEvents(operations, store.sid)
  const registered = new Set(authorizations.filter(event => event.kind === 'proposal_registered').map(event => event.entity_id))
  const snapshot = (row: Json, source: 'worker' | 'approval'): TimelineEvent | null => {
    const id = text(source === 'worker' ? row.id : row.action_id)
    const timestamp = text(row.created_at)
    if (!id || !Number.isFinite(Date.parse(timestamp))) return null
    return { id, timestamp, source, sequence: null, session_id: store.sid, entity_id: id,
      kind: source === 'worker' ? 'worker_receipt_created' : 'proposal_registered',
      stage: source === 'worker' ? 'Worker execution' : 'Execution proposal', job_id: source === 'worker' ? id : null,
      campaign_id: null, run_id: null, task_id: null, agent: null, state: null, reason_code: null,
      correlation_id: null, evidence_ids: [], dependency_ids: [] }
  }
  const referenced = [...rows(operations?.receipts).map(row => snapshot(row, 'worker')),
    ...rows(operations?.pending).filter(row => !registered.has(text(row.action_id))).map(row => snapshot(row, 'approval'))].filter(item => item !== null)
  const current = store.eventsDenied ? [] : archived ? (archived.page?.events ?? []).slice().reverse() :
    [...store.events(), ...referenced, ...authorizations].sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp))
  const replay = filters.replay
  const all = replay?.records ?? current
  const filtered = all.filter(event => (!filters.eventSource || filters.eventSource === event.source) &&
    [event.kind, event.stage, event.agent, event.state, event.task_id, event.run_id, event.job_id, event.id, event.entity_id, event.correlation_id,
      ...event.evidence_ids].some(field => text(field).toLowerCase().includes(filters.eventQuery.toLowerCase())))
  const oldestFirst = replay ? filtered.slice().reverse() : []
  const index = Math.min(filters.replayIndex, oldestFirst.length - 1)
  const display = replay ? oldestFirst.slice(0, index + 1).reverse() : filtered
  const toggleReplay = button(replay ? 'Exit replay' : 'Replay retained events', () => {
    filters.replay = replay ? null : { records: current, capturedAt: Date.now(), campaignId: archived?.id ?? null,
      gap: archived ? !!archived.page?.gap : !!(store.feed.team?.gap || store.feed.campaign?.gap) }
    filters.replayIndex = 0
    change()
  }, 'button small')
  toggleReplay.disabled = !replay && !filtered.length
  const heading = el('div', 'timeline-controls',
    filterText('Search events', filters.eventQuery, 'event-query', value => { filters.eventQuery = value; filters.replayIndex = 0; change() }),
    filterSelect('Event source', archived ? ['campaign'] : ['team', 'campaign', 'worker', 'approval', 'authorization'], filters.eventSource,
      value => { filters.eventSource = value; filters.replayIndex = 0; change() }),
    toggleReplay)
  const coverage = el('div', 'coverage-line', ...(['team', 'campaign'] as const).map(source => {
    const page = store.feed[source]
    const state = page?.state ?? (store.eventError ? 'unavailable' : 'loading')
    return badge(state, human(source) + ' · ' + human(state) +
      (page?.has_more ? ' · newer records pending' : '') +
      (page?.gap ? ' · retention gap' : ''))
  }), badge(store.stream === 'Run stream connected' ? 'running' : 'unknown', store.stream),
    store.streamGap ? badge('stale', 'Run stream reported an event gap') : null)
  const options: Node[] = []
  if (!replay) {
    const entries = store.campaigns()
    const picker = select([['', 'Live session events'], ...entries.map(row => [text(row.id),
      human(row.state) + ' · ' + date(row.created_at) + ' · ' + text(row.id)] as [string, string])], archived?.id ?? '', value => {
      filters.eventSource = ''
      filters.eventQuery = ''
      filters.replayIndex = 0
      void store.selectCampaign(value)
    })
    picker.dataset.focus = 'campaign-timeline'
    picker.disabled = store.eventsDenied || (!entries.length && !archived)
    const toolbar = el('div', 'timeline-archive', labelControl('Campaign timeline', picker))
    if (store.campaignBefore) {
      const more = button(store.olderCampaignLoading ? 'Loading earlier campaigns…' : 'Load earlier campaigns',
        () => void store.loadOlderCampaigns(), 'button small')
      more.disabled = store.eventsDenied || store.olderCampaignLoading
      toolbar.append(more)
    }
    options.push(toolbar)
    const archiveIndexStatus = status(store.slot('campaignHistory'))
    if (archiveIndexStatus) options.push(archiveIndexStatus)
    if (store.olderCampaignError) options.push(el('p', 'subtle', store.olderCampaignError))
  }
  options.push(heading)
  if (replay) {
    options.push(el('div', 'coverage-line', badge('recorded', 'Replay snapshot'),
      replay.gap ? badge('stale', 'Retention gap in captured records') : null),
      el('p', 'subtle', (replay.campaignId ? 'Campaign ' + replay.campaignId : 'Session events') + ' · Captured ' + date(replay.capturedAt)))
    if (oldestFirst.length) {
      const range = el('input')
      range.type = 'range'
      range.max = String(oldestFirst.length - 1)
      range.value = String(index)
      range.dataset.focus = 'replay'
      range.addEventListener('input', () => { filters.replayIndex = Number(range.value); change() })
      options.push(labelControl('Historical replay position', range), el('p', 'subtle',
        'Retained record ' + (index + 1) + ' / ' + oldestFirst.length + ' · ' + date(oldestFirst[index]?.timestamp)))
    }
  } else if (archived) {
    const archiveStatus = status({ state: archived.state, value: null, issue: archived.issue })
    if (archiveStatus) options.push(archiveStatus)
    if (archived.state === 'unavailable') options.push(button('Retry campaign snapshot', () => void store.selectCampaign(archived.id), 'button small'))
    if (archived.at) options.push(el('div', 'coverage-line', badge('recorded', 'Campaign snapshot'),
      archived.page?.gap ? badge('stale', 'Earlier campaign events are outside retention') : null),
      el('p', 'subtle', 'Campaign ' + archived.id + ' · Retrieved ' + date(archived.at)))
  } else {
    options.push(coverage)
    const snapshotStatus = status(store.slot('operations'))
    if (snapshotStatus) options.push(snapshotStatus)
    const journalStatus = operations ? authorizationCoverage(operations) : null
    if (journalStatus) options.push(journalStatus)
    if (store.eventError) options.push(el('p', 'subtle', (all.length ? 'Stale events · ' : '') + store.eventError))
  }
  const knownWindow = !!replay || (archived ? archived.state === 'available' : !store.eventsDenied &&
    (store.feed.team?.state === 'available' || store.feed.campaign?.state === 'available' || !!operations))
  if (knownWindow) options.push(el('p', 'subtle', count(display.length) + ' retained ' +
    (display.length === 1 ? 'record' : 'records') + '. Each campaign ring holds up to 50 events.'))
  if (display.length) {
    const list = windowed(display, event => recordButton(human(event.kind), event.stage + ' · ' + date(event.timestamp) +
      ' · ' + human(event.source), event.state, () => eventDetail(event, detail, advanced)), 'Event timeline')
    list.dataset.scroll = 'timeline'
    options.push(list)
  } else if (knownWindow) options.push(empty(all.length ? 'No events match the current filters.' : 'No events recorded in the current response.'))
  if (!replay && !archived && store.canLoadOlder) {
    const history = button(store.historyLoading ? 'Loading older events…' : 'Load older team events', () => void store.loadOlder(), 'button small')
    history.disabled = store.historyLoading
    options.push(history)
  }
  if (!replay && !archived && store.historyError) options.push(el('p', 'subtle', store.historyError))
  const result = [card('Event timeline', options)]
  if (advanced) {
    const stageCounts = new Map<string, number>()
    for (const event of display) stageCounts.set(event.stage, (stageCounts.get(event.stage) ?? 0) + 1)
    result.push(card('Operational stages', [el('div', 'pipeline', ...stages.map(stage => el('div', 'stage',
      el('strong', '', stage), stageCounts.has(stage) ? badge('recorded', count(stageCounts.get(stage)) + ' retained') : badge('unknown', 'Not recorded'))))]))
    if (display.length) {
      const plot = el('div', 'density', empty('Preparing activity density…'))
      const picker = select([['canvas', 'Canvas 2D'], ['gpu', 'PixiJS WebGL']], filters.renderer,
        value => { filters.renderer = value; change() })
      lazy(plot, async () => {
        const module = await import('./density')
        if (plot.isConnected) return module.mountDensity(plot, display, filters.renderer === 'gpu',
          index => eventDetail(display[index], detail, advanced))
      })
      result.push(card('Activity density', [plot], { action: labelControl('Renderer', picker) }))
      const graph = el('div', 'viz', empty('Preparing event relationships…'))
      eventGraph(display, graph, store, detail, lazy)
      result.push(card('Event relationships', [el('p', 'subtle', 'Latest 70 matching records with stored evidence, dependencies, or campaign correlation.'), graph]))
    }
  }
  return result
}

export function investigation(store: MissionStore, detail: Detail, lazy: Lazy) {
  const team = store.value('team')
  const evidence = rows(team?.evidence)
  const advanced = store.preferences.mode === 'advanced'
  function inspectEvidence(row: Json) {
    detail('Evidence record', [
      recordFields(row, ['summary', 'description', 'source_kind', 'source_id', 'created_at', ...(advanced ? ['id', 'digest', 'scope_digest'] : [])])
    ])
  }
  function inspectFinding(row: Json) {
    const references = strings(row.evidence_references)
    detail(text(row.title, 'Finding'), [badge(row.state ?? row.severity),
      recordFields(row, ['severity', 'summary', 'description', 'state', 'verification_current',
        'ready_for_external_submission', 'smallest_missing_validation']),
      ...evidence.filter(record => references.includes(text(record.id))).map(record =>
        recordButton(text(record.summary, text(record.id)), 'Referenced evidence', undefined, () => inspectEvidence(record)))])
  }
  async function inspectReport(row: Json) {
    const id = text(row.id)
    if (!id) return
    const signal = store.signal
    const body = el('div', 'stack', empty('Loading report preview…'))
    detail(text(row.title, 'Report preview'), [body])
    try {
      const path = '/api/report/' + encodeURIComponent(store.sid) + '/drafts/' + encodeURIComponent(id)
      const result = await request(path + '/preview', { signal })
      if (!body.isConnected) return
      const files = Object.entries(object(result?.files) ?? {}).filter((entry): entry is [string, string] => typeof entry[1] === 'string')
      const sections: Node[] = files.length ? files.map(([filename, contents]) => {
        const panel = el('details', 'report-file', el('summary', '', filename), el('pre', '', contents.slice(0, 100000)))
        panel.open = filename === 'report.md'
        return panel
      }) : [empty('No text preview recorded for this report.')]
      const report = object(result?.report)
      const signoff = object(result?.signoff)
      const digest = text(report?.package_sha256)
      if (result?.signed === true) {
        if (/^[a-f0-9]{64}$/.test(digest) && signoff?.package_sha256 === digest
            && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(id)) {
          const message = el('p', 'subtle')
          message.setAttribute('role', 'status')
          const download = button('Download signed ZIP', async () => {
            download.disabled = true
            message.textContent = 'Preparing archive…'
            try {
              const archive = await signedReportArchive(path + '/export', digest, signal)
              if (!archive || !body.isConnected || signal.aborted) return
              const url = URL.createObjectURL(archive)
              const anchor = link('', url)
              anchor.download = 'aria-report-' + id + '.zip'
              anchor.hidden = true
              document.body.append(anchor)
              anchor.click()
              anchor.remove()
              window.setTimeout(() => URL.revokeObjectURL(url), 1000)
              message.textContent = 'Download requested.'
            } catch (error) {
              if (!signal.aborted) message.textContent = error instanceof Error ? error.message : 'The report could not be downloaded.'
            } finally {
              download.disabled = false
            }
          }, 'button primary')
          sections.unshift(fields([['Signed package digest', digest]]), download, message)
        } else {
          sections.unshift(empty('The signed package digest is unavailable.'))
        }
      } else if (result?.signed === false) {
        sections.unshift(badge('draft', 'Awaiting report sign-off'))
      }
      body.replaceChildren(...sections)
    } catch (error) {
      if (!signal.aborted) body.replaceChildren(empty(error instanceof Error ? error.message : 'Report preview unavailable.'))
    }
  }
  const hosts = rows(store.value('hosts')?.hosts)
  const graph = el('div', 'viz', empty('Preparing host and service graph…'))
  if (advanced && hosts.length) {
    const nodes: GraphNode[] = []
    const links: Edge[] = []
    const inspect = new Map<string, Json>()
    for (const host of hosts.slice(0, 24)) {
      const address = text(host.ip)
      const key = 'host:' + address
      nodes.push({ id: key, label: text(host.hostname, address), column: 0, state: 'recorded', kind: 'Host' })
      inspect.set(key, host)
      for (const service of rows(host.ports).slice(0, 16)) {
        const serviceId = key + ':' + service.port
        nodes.push({ id: serviceId, label: String(service.port) + ' · ' + text(service.service, 'Service'),
          column: 1, state: 'recorded', kind: 'Service' })
        links.push({ source: key, target: serviceId, kind: 'Recorded service' })
        inspect.set(serviceId, service)
      }
    }
    lazy(graph, async () => {
      const module = await import('./graph')
      if (graph.isConnected) return module.mountGraph(graph, {
        label: 'Recorded host topology', nodes, edges: links, motion: store.preferences.motion, inspect(id) {
          const entry = inspect.get(id)
          if (entry) detail('Recorded topology', [recordFields(entry, ['ip', 'hostname', 'port', 'service', 'version'])])
        }
      })
    })
  }
  const previewReports = (value: Json) => {
    const reports = rows(value.report_drafts)
    const signed = new Set(rows(value.report_signoffs).map(row => text(row.report_id, text(row.id))))
    return reports.length ? reports.map(row => recordButton(text(row.title, 'Report draft'), 'Revision ' + count(row.revision),
      signed.has(text(row.id)) ? 'signed' : 'draft', () => void inspectReport(row))) : [empty('No saved professional reports.')]
  }
  const appMap = store.value('appMap')
  const mapRecords = [['objects', 'Object'], ['workflows', 'Workflow'], ['captures', 'Capture']] as const
  const mapGraph = el('div', 'viz', empty('Preparing saved application relationships…'))
  const mapped = mapRecords.flatMap(([key, kind]) => records(appMap?.[key]).slice(0, 50).flatMap(row => {
    const id = text(row.id)
    if (!id) return []
    return [{ row, node: { id: key + ':' + id, label: text(row.label, text(row.method, kind)), kind,
      state: row.expired === true ? 'stale' : 'recorded', column: key === 'captures' ? 1 : 0 } }]
  }))
  if (advanced && mapped.length) {
    const graphEdges: Edge[] = []
    const captures = mapped.filter(entry => entry.node.kind === 'Capture')
    for (const item of mapped) for (const capture of captures) {
      if (strings(item.row.evidence_ids).includes(text(capture.row.evidence_id))) {
        graphEdges.push({ source: item.node.id, target: capture.node.id, kind: 'Evidence reference' })
      }
    }
    lazy(mapGraph, async () => {
      const module = await import('./graph')
      if (mapGraph.isConnected) return module.mountGraph(mapGraph, { nodes: mapped.map(entry => entry.node), edges: graphEdges,
        label: 'Recorded application map evidence', motion: store.preferences.motion, inspect(id) {
          const entry = mapped.find(item => item.node.id === id)
          if (entry) detail(entry.node.kind, [recordFields(entry.row, ['label', 'id', 'method', 'evidence_id', 'evidence_ids', 'expired'])])
        } })
    })
  }
  return [
    el('div', 'split-grid',
      sourceCard(store, 'verification', 'Verification and review', value => rows(value.findings).length ?
        rows(value.findings).map(row => recordButton(text(row.title, 'Candidate finding'), human(row.severity),
          row.state, () => inspectFinding(row))) : [empty('No durable verification records.')]),
      sourceCard(store, 'findings', 'Recorded findings', value => rows(value.findings).length ?
        rows(value.findings).map(row => recordButton(text(row.title, text(row.name, 'Finding')), human(row.severity),
          row.status, () => inspectFinding(row))) : [empty('No findings recorded by the finding store.')])),
    el('div', 'split-grid',
      sourceCard(store, 'team', 'Evidence catalog', () => evidence.length ?
        [windowed(evidence, row => recordButton(text(row.summary, 'Evidence ' + text(row.id)), human(row.source_kind),
          'recorded', () => inspectEvidence(row)), 'Evidence catalog')] : [empty('No saved evidence.')]),
      sourceCard(store, 'research', 'Research hypotheses', value => rows(value.hypotheses).length ? rows(value.hypotheses).map(row =>
        recordButton(text(row.title, text(row.statement, 'Research hypothesis')), row.requires_revalidation ? 'Requires revalidation' :
          human(row.state), row.state, () => detail('Research hypothesis', [recordFields(row,
            ['title', 'statement', 'state', 'requires_revalidation', 'confirmed', 'confidence', 'evidence_references'])]))) :
        [empty('No recorded hypotheses.')])),

    el('div', 'split-grid',
      sourceCard(store, 'hosts', 'Hosts and services', value => hosts.length ? [
        ...(value.truncated === true ? [el('p', 'subtle', 'Snapshot limited to 100 hosts and 100 services per host.')] : []),
        ...hosts.map(row => recordButton(text(row.hostname, text(row.ip, 'Host')), count(rows(row.ports).length) + ' recorded services', null,
          () => detail(text(row.ip, 'Host'), [recordFields(row, ['hostname', 'os']),
            ...rows(row.ports).map(service => fields([['Port', String(service.port)], ['Service', human(service.service)],
              ['Version', text(service.version, 'Not recorded')]]))])))
      ] : [empty('No host observations in the current knowledge snapshot.')]),
      sourceCard(store, 'appMap', 'Application map', value => {
        const groups = ['objects', 'workflows', 'captures'] as const
        const descriptions: Record<typeof groups[number], string> = { objects: 'Object', workflows: 'Workflow', captures: 'Saved capture' }
        return [fields(groups.map(key => [human(key), count(records(value[key]).length)])),
          ...groups.flatMap(key => records(value[key]).slice(0, 12).map(row => recordButton(
            text(row.label, text(row.name, text(row.title, descriptions[key]))), descriptions[key], row.state,
            () => detail(descriptions[key], [recordFields(row, ['label', 'name', 'title', 'method', 'state', 'id'])]))))]
      })),
    ...(advanced && hosts.length ? [card('Recorded topology', [graph, el('p', 'subtle', 'Up to 24 hosts and 16 services per host in this graph.')])] : []),
    ...(advanced && mapped.length ? [card('Application topology', [mapGraph,
      el('p', 'subtle', 'Links follow evidence IDs stored with application objects and workflows. Up to 50 records per category.')])] : []),
    sourceCard(store, 'reports', 'Professional reports', previewReports)
  ]
}

export function analytics(store: MissionStore, detail: Detail, lazy: Lazy, filters: Filters, change: () => void) {
  const data = store.value('budget')
  const attempts = rows(data?.attempts)
  const tasks = rows(store.value('team')?.tasks)
  const role = new Map(tasks.map(task => [task.id, task.owner_role]))
  const since = Date.now() - Number(filters.timeWindow || 0) * 86400000
  const filtered = attempts.filter(row => (!filters.provider || row.provider === filters.provider) &&
    (!filters.model || row.model === filters.model) && (!filters.campaign || row.campaign_id === filters.campaign) &&
    (!filters.attemptAgent || role.get(row.task_id) === filters.attemptAgent) &&
    (!filters.timeWindow || Date.parse(text(row.timestamp)) >= since))
  const timeouts = ['timeout', 'client_timeout', 'provider_timeout', 'request_timeout', 'read_timeout']
  const settled = filtered.filter(row => ['succeeded', 'failed'].includes(text(row.state)))
  const failed = settled.filter(row => row.state === 'failed')
  const measureRate = (count: number) => settled.length ? (100 * count / settled.length).toFixed(1) + '%' : 'Not recorded'
  const chartCards = []
  const invalidTimestamps = filtered.filter(row => !Number.isFinite(Date.parse(text(row.timestamp)))).length
  const omitted = number(data?.omitted_attempts)
  for (const [kind, title, unit] of [['tokens', 'Token usage', 'Tokens by reservation timestamp'],
    ['cost', 'Cost accounting', 'USD by reservation timestamp'], ['latency', 'Response timing', 'Milliseconds by reservation timestamp'],
    ['volume', 'Attempt outcomes', 'Cumulative counts in the selected records'], ['distribution', 'Latency distribution', 'Measured pool attempts by time band']] as const) {
    const chart = el('div', 'chart', empty('Loading chart…'))
    chart.setAttribute('aria-label', title)
    if (filtered.length) lazy(chart, async () => {
      const module = await import('./analytics')
      if (!chart.isConnected) return
      if (!module.seriesFor(kind, filtered).length) {
        chart.replaceChildren(empty('No measurements recorded for these filters.'))
        return
      }
      return module.mountChart(chart, kind, filtered)
    })
    chartCards.push(card(title, [el('p', 'subtle', unit),
      filtered.length ? chart : empty(data ? 'No recorded measurements match these filters.' : 'Accounting source unavailable or loading.')]))
  }
  const cmd = rows(store.value('operations')?.commands)
  const timings = cmd.map(row => number(row.duration_ms)).filter((value): value is number => value !== null)
  const taskCounts = new Map<string, number>()
  for (const task of tasks) taskCounts.set(text(task.state, 'unknown'), (taskCounts.get(text(task.state, 'unknown')) ?? 0) + 1)
  const campaignCounts = new Map<string, number>()
  for (const record of store.events()) if (record.source === 'campaign') {
    const day = new Date(record.timestamp).toISOString().slice(0, 10)
    campaignCounts.set(day, (campaignCounts.get(day) ?? 0) + 1)
  }
  const countChart = (label: string, bins: [string, number][]) => {
    const node = el('div', 'chart', empty('Loading chart…'))
    node.setAttribute('aria-label', label)
    lazy(node, async () => {
      const module = await import('./analytics')
      if (node.isConnected) return module.mountCountChart(node, label, bins)
    })
    return node
  }
  const providerGroups = unique(filtered.map(row => text(row.provider)))
  return [
    sourceCard(store, 'budget', 'Engagement limits and admission', value => budgetSummary(value, true)),
    card('Provider attempts', [
      el('div', 'filter-grid',
        filterSelect('Provider', unique(attempts.map(row => text(row.provider))), filters.provider, value => { filters.provider = value; change() }),
        filterSelect('Model', unique(attempts.map(row => text(row.model))), filters.model, value => { filters.model = value; change() }, value => value),
        filterSelect('Campaign', unique(attempts.map(row => text(row.campaign_id))), filters.campaign,
          value => { filters.campaign = value; change() }, value => value),
        filterSelect('Agent', unique(attempts.map(row => text(role.get(row.task_id)))), filters.attemptAgent,
          value => { filters.attemptAgent = value; change() }),
        labelControl('Time range', select([['', 'All retained'], ['1', 'Last 24 hours'], ['7', 'Last 7 days'], ['30', 'Last 30 days']],
          filters.timeWindow, value => { filters.timeWindow = value; change() }))),
      el('p', 'subtle', data ? count(filtered.length) + ' matching reservations · ' + count(attempts.length) + ' retained attempt records · maximum ' +
        count(data.attempts_limit) + (omitted ? ' · ' + count(omitted) + (omitted === 1 ? ' record' : ' records') + ' could not be attributed' : '') +
        (invalidTimestamps ? ' · ' + invalidTimestamps + ' have unavailable timestamps' : '') : 'Waiting for the accounting source.'),
      ...(data ? [fields([['Settled attempts', count(settled.length)], ['Failed', count(failed.length) + ' · ' + measureRate(failed.length)],
        ['Recorded timeouts', count(failed.filter(row => timeouts.includes(text(row.error_code))).length) + ' · ' +
          measureRate(failed.filter(row => timeouts.includes(text(row.error_code))).length)]])] : []),
      ...providerGroups.map(group => {
        const cohort = filtered.filter(row => row.provider === group)
        return el('p', 'comparison', human(group) + ' · ' + cohort.length + ' reservations · ' +
          cohort.filter(row => row.state === 'succeeded').length + ' succeeded')
      })
    ]),
    el('div', 'split-grid charts', ...chartCards),
    el('div', 'split-grid',
      sourceCard(store, 'team', 'Recorded task activity', () => taskCounts.size ? [fields([...taskCounts].map(([state, total]) =>
        [human(state), count(total)])), countChart('Tasks by recorded state', [...taskCounts].map(([state, total]) => [human(state), total]))] :
        [empty('No task records.')]),
      sourceCard(store, 'operations', 'Recorded command timing', () => timings.length ?
        [fields([['Measured commands', count(timings.length)], ['Shortest', count(Math.min(...timings)) + ' ms'],
          ['Longest', count(Math.max(...timings)) + ' ms']])] : [empty('Command durations were not retained in this window.')]),
      sourceCard(store, 'campaign', 'Campaign measurements', value => {
        const progress = object(value.progress)
        const runtime = object(value.runtime)
        return [fields([['State', human(value.state)], ['Steps taken', count(progress?.steps_taken)],
          ['Successful steps', count(progress?.successful_steps)], ['Runtime seconds', count(runtime?.total_seconds)],
          ['Events retained in campaign ring', count(object(value.operations)?.retained)]]),
          ...(campaignCounts.size ? [el('p', 'subtle', 'Retained campaign events grouped by UTC day'),
            countChart('Campaign events per observed day', [...campaignCounts].sort(([a], [b]) => a.localeCompare(b)))] :
            [empty('No campaign events available in the current window.')])]
      })),
    card('Attempt records', filtered.length ? [windowed([...filtered].reverse(), row => recordButton(
      text(row.model, 'Model attempt'), human(row.provider) + ' · ' + date(row.timestamp), row.state,
      () => detail('Physical model attempt', [recordFields(row, ['id', 'provider', 'model', 'state', 'session_id', 'campaign_id', 'task_id',
        'run_id', 'timestamp', 'finished_at', 'reserved_tokens', 'reported_tokens', 'input_tokens', 'output_tokens', 'logical_request_id',
        'attempt_index']), fields([['Reserved cost', money(row.reserved_cost_microusd)],
        ['Reported cost estimate', money(row.reported_cost_microusd)],
        ['Pool attempt time', number(object(row.timings)?.pool_attempt_ms) !== null ? count(object(row.timings)?.pool_attempt_ms) + ' ms' : 'Unknown'],
        ['Outcome', timeouts.includes(text(row.error_code)) ? 'Timeout' : human(row.state)],
        ['Failure reason', row.state === 'failed' ? human(row.error_code, 'Not recorded') : 'Not applicable']])])), 'Model attempts')] :
      [empty('No retained attempts match these filters.')])
  ]
}

export function infrastructure(store: MissionStore, detail: Detail, lazy: Lazy) {
  const ready = store.value('ready')
  const service = store.value('health')
  const capability = store.value('capabilities')
  const worker = object(capability?.worker)
  const providerList = rows(store.value('providers')?.keys)
  const components = [
    ['FastAPI', service?.status === 'ok' ? 'operational' : 'unknown', text(service?.version, 'Version unknown')],
    ['PostgreSQL', ready?.database === true ? 'operational' : ready?.database === false ? 'unavailable' : 'unknown', 'Readiness database probe'],
    ['Redis', ready?.cache === true ? 'operational' : ready?.cache === false ? 'unavailable' : 'unknown', 'Optional session cache'],
    ['Kali worker', text(worker?.status, 'unknown'), worker?.status === 'online' ?
      strings(worker.available_tools).join(', ') || 'No tools advertised' : 'Capability probe']
  ]
  const graph = el('div', 'viz', empty('Preparing infrastructure topology…'))
  const advanced = store.preferences.mode === 'advanced'
  if (advanced) lazy(graph, async () => {
    const module = await import('./graph')
    if (!graph.isConnected) return
    return module.mountGraph(graph, { nodes: components.map(([name, state], index) => ({ id: name, label: name,
      state, kind: 'Service', column: index === 0 ? 0 : 1 })), edges: [
      ...(typeof ready?.database === 'boolean' ? [{ source: 'FastAPI', target: 'PostgreSQL', kind: 'Readiness probe' }] : []),
      ...(typeof ready?.cache === 'boolean' ? [{ source: 'FastAPI', target: 'Redis', kind: 'Cache readiness' }] : []),
      ...(worker?.status === 'online' || worker?.status === 'unreachable' ?
        [{ source: 'FastAPI', target: 'Kali worker', kind: 'Capability probe' }] : [])
    ], label: 'Reported infrastructure connections', motion: store.preferences.motion, inspect(id) {
      const service = components.find(([name]) => name === id)
      if (service) detail(id, [fields([['State', human(service[1])], ['Source', service[2]]])])
    } })
  })
  return [
    el('div', 'split-grid', card('Service health', [
      ...(['health', 'ready', 'capabilities'] as const).flatMap(key => status(store.slot(key)) ? [status(store.slot(key))!] : []),
      ...components.map(([name, state, explanation]) => el('div', 'infra-row', el('div', '', el('strong', '', name),
        el('small', '', explanation)), badge(state)))]),
    sourceCard(store, 'capabilities', 'Worker capabilities', value => [
      fields([['Operationally advertised', worker?.status === 'online' ? strings(worker.available_tools).join(', ') || 'None' : 'Unknown'],
        ['Integrated profiles', strings(value.supported_profiles).join(' · ') || 'Not recorded'],
        ['Installed inventory', 'Not measured by this endpoint'], ['Isolation', 'Worker policy enforced server-side'],
        ['CPU, memory and GPU telemetry', 'Not measured by this endpoint']]),
      el('p', 'subtle', strings(value.unavailable).length ? 'Unavailable capabilities · ' + strings(value.unavailable).join(' · ') : '')
    ])),
    sourceCard(store, 'providers', 'Model provider pool', () => providerList.length ?
      providerList.map(row => el('div', 'infra-row', el('div', '', el('strong', '', human(row.provider, 'Provider')),
        el('small', '', text(row.model, 'Configured pool entry'))), badge(row.status ?? (row.is_active === true ? 'available' : 'unknown')))) :
      [empty('No provider pool records returned.')]),
    ...(advanced ? [card('Reported infrastructure connections', [graph, el('p', 'subtle', 'Links indicate probes with a recorded result.')]),
      card('API diagnostics', [windowed([...diagnostics].reverse(), row =>
      el('div', 'diagnostic record', el('span', 'record-copy', el('strong', '', row.path),
        el('small', '', (row.requestId ?? 'No request ID') + ' · ' + (row.handler !== undefined ? count(row.handler) + ' ms handler' : 'Handler time unknown'))),
      badge(row.status < 400 && row.status > 0 ? 'completed' : 'failed', row.status ? String(row.status) : 'Transport'),
      el('span', 'mono', count(Math.round(row.duration)) + ' ms')), 'API diagnostics')])] : [])
  ]
}

export function settings(store: MissionStore) {
  const preferences = store.preferences
  function set<K extends keyof Preferences>(key: K, value: Preferences[K]) {
    store.updatePreferences({ [key]: value })
  }
  const theme = select([['dark', 'Dark'], ['light', 'Light'], ['system', 'System']], preferences.theme,
    value => set('theme', value as Preferences['theme']))
  const accent = select(accents.map(value => [value, human(value)]), preferences.accent, value => set('accent', value as Preferences['accent']))
  const density = select([['standard', 'Standard'], ['compact', 'Compact']], preferences.density,
    value => set('density', value as Preferences['density']))
  const mode = select([['simple', 'Simple'], ['advanced', 'Advanced']], preferences.mode, value => set('mode', value as Preferences['mode']))
  const motion = el('input')
  motion.type = 'checkbox'
  motion.checked = preferences.motion
  motion.addEventListener('change', () => set('motion', motion.checked))
  const width = el('input')
  width.type = 'range'
  width.min = '340'
  width.max = '700'
  width.value = String(preferences.inspectorWidth)
  width.dataset.focus = 'inspector-width'
  width.addEventListener('input', () => set('inspectorWidth', Number(width.value)))
  return [
    card('Interface preferences', [el('div', 'preferences-grid', labelControl('Theme', theme), labelControl('Accent colour', accent),
      labelControl('Layout density', density), labelControl('Detail mode', mode),
      labelControl('Inspector width', width), labelControl('Animate observed changes', motion))]),
    sourceCard(store, 'profile', 'Operator profile', value => [recordFields(value, ['username', 'skill_level'])]),
    ...(store.sid ? [sourceCard(store, 'budget', 'Configured model and accounting limits', value => {
      const selection = object(value.configured_selection)
      return [recordFields(selection ?? {}, ['provider', 'model']), ...budgetSummary(value, true)]
    })] : []),
    card('Workspace access', [link('Research chat', store.sid ? '/chat/' + encodeURIComponent(store.sid) : '/'),
      link('Legacy Operations Overview', '/dashboard/legacy')])
  ]
}
