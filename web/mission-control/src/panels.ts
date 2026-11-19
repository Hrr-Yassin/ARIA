import { number, object, rows, strings, text, type Json, type SourceKey, type TimelineEvent } from './api'
import { type MissionStore, type View } from './store'
import { badge, button, card, count, date, el, empty, fields, human, icon, meter, money, recordButton, status } from './dom'

export type Detail = (title: string, contents: Node[], backdrop?: boolean) => void
export type Go = (view: View) => void
export type Lazy = (node: HTMLElement, mount: () => Promise<(() => void) | undefined>) => void
export const labels: Record<View, string> = {
  overview: 'Mission Control', workspace: 'Workspace', sessions: 'Sessions', agents: 'Agents', operations: 'Operations', events: 'Events',
  investigation: 'Investigation', analytics: 'Analytics', infrastructure: 'Infrastructure', settings: 'Settings'
}

export function sourceCard(store: MissionStore, key: SourceKey, title: string, body: (value: Json) => Node[], action?: Node) {
  const slot = store.slot(key)
  const banner = status(slot)
  const children = [...(banner ? [banner] : []), ...(slot.value ? body(slot.value) : [])]
  return card(title, children, { action })
}
export const recordFields = (record: Json, names: string[]) => fields(names.map(key => [human(key),
  Array.isArray(record[key]) ? strings(record[key]).join(', ') || 'None recorded' : typeof record[key] === 'boolean' ? (record[key] ? 'Yes' : 'No') :
    typeof record[key] === 'number' ? String(record[key]) : text(record[key], 'Not recorded')]))
export function taskTitle(task: Json): string { return text(task.title, text(task.objective, 'Task ' + text(task.id))) }
export function taskState(tasks: Json[] | null): string {
  if (!tasks) return 'unknown'
  if (!tasks.length) return 'inactive'
  const priority = ['running', 'blocked', 'awaiting_review', 'queued', 'failed', 'completed', 'cancelled']
  return priority.find(state => tasks.some(task => task.state === state)) ?? 'unknown'
}

export function eventDetail(event: TimelineEvent, detail: Detail, advanced: boolean) {
  const data: [string, string][] = [
    ['Stage', event.stage], ['Source', { team: 'Durable team ledger', campaign: 'Campaign event ring',
      worker: 'Worker receipt store', approval: 'Current approval queue', authorization: 'Durable authorization journal' }[event.source]],
    ['Timestamp', date(event.timestamp)], ['State', human(event.state, 'Not recorded')],
    ['Reason code', text(event.reason_code, 'Not recorded')],
    ['Agent', human(event.agent, 'Not recorded')], ['Evidence references', event.evidence_ids.join(', ') || 'None recorded']
  ]
  if (advanced) data.push(['Event ID', event.id], ['Sequence', event.sequence === null ? 'Not recorded' : String(event.sequence)], ['Session ID', event.session_id],
    ['Campaign ID', text(event.campaign_id, 'Not recorded')], ['Task ID', text(event.task_id, 'Not recorded')],
    ['Run ID', text(event.run_id, 'Not recorded')], ['Job ID', text(event.job_id, 'Not recorded')],
    ['Correlation ID', text(event.correlation_id, 'Not recorded')], ['Dependency references', event.dependency_ids.join(', ') || 'None recorded'])
  if (event.source === 'approval' || event.source === 'authorization') data.push(['Action ID', text(event.entity_id, 'Not recorded')])
  if (event.decision) data.push(['Recorded decision', human(event.decision)])
  detail(human(event.kind), [fields(data), ...(event.kind === 'authorization_consumed' ?
    [el('p', 'subtle', 'This record confirms an authorization claim. Worker outcomes are shown in the receipt history.')] : [])])
}

export const admissionReasons: Record<string, string> = {
  call_limit: 'The call reservation limit is exhausted.',
  token_reservation_floor: 'Token headroom is below the minimum reservation.',
  cost_reservation_floor: 'Cost headroom is below the minimum reservation for the configured model.',
  provider_overrun: 'Reported use exceeded a reservation. Accounting stopped.',
  unknown_usage: 'A provider attempt had unknown usage. Accounting stopped.',
  accounting_inconsistent: 'Accounting records are inconsistent. Admission is denied.',
  accounting_stopped: 'Accounting has stopped.',
  model_tariff_missing: 'The configured model requires an approved tariff.',
  model_tariff_invalid: 'The configured OpenRouter quote requires review.'
}

export function admissionBox(value: Json, expanded = false) {
  const admission = object(value.admission)
  const remaining = object(admission?.remaining)
  const reasons = strings(admission?.reasons)
  const prerequisites = strings(admission?.configured_provider_prerequisites)
  const blocked = admission?.state === 'blocked'
  const tone = blocked ? 'blocked' : 'unknown'
  const label = blocked ? 'Admission blocked' : 'Admission undetermined'
  const message = admission ? (reasons.length ? reasons.map(code => admissionReasons[code] ?? human(code)).join(' ') :
    'Admission depends on the request size, provider, and current campaign and task constraints.') : 'This response did not include an admission snapshot.'
  return el('div', 'callout ' + tone, icon(blocked ? 'warning' : 'shield'), el('div', 'callout-copy',
    el('strong', '', label), el('p', '', message),
    reasons.includes('token_reservation_floor') || expanded && admission ? el('p', 'mono',
      count(remaining?.tokens) + ' tokens available · ' + count(admission?.minimum_tokens) + ' minimum reservation') : null,
    ...prerequisites.map(code => el('p', '', admissionReasons[code] ?? human(code)))))
}

export function budgetSummary(value: Json, expanded = false) {
  const limits = object(value.limits)
  const usage = object(value.usage)
  const remaining = object(object(value.admission)?.remaining)
  const children: Node[] = [
    meter('Call reservations', usage?.calls, limits?.max_calls),
    meter('Reserved tokens', usage?.reserved_tokens, limits?.max_tokens),
    meter('Reserved cost', usage?.reserved_cost_microusd, limits?.max_cost_microusd, money),
    admissionBox(value, expanded)
  ]
  if (expanded) {
    children.splice(3, 0, fields([
      ['Calls remaining', count(remaining?.calls)], ['Token headroom', count(remaining?.tokens)], ['Cost headroom', money(remaining?.cost_microusd)],
      ['Reported tokens', count(usage?.reported_tokens)], ['Reported cost estimate', money(usage?.reported_cost_microusd)],
      ['Unknown token usage', count(usage?.unknown_usage_calls)], ['Unknown cost', count(usage?.unknown_cost_calls)]
    ]))
  }
  return children
}

export function overview(store: MissionStore, go: Go, detail: Detail) {
  const advanced = store.preferences.mode === 'advanced'
  const run = store.value('run') ?? {}
  const mission = object(run.mission)
  const campaign = store.value('campaign')
  const currentSession = store.value('session')
  const scope = object(currentSession?.scope)
  const worker = object(store.value('capabilities')?.worker)
  const progress = object(campaign?.progress)
  const blockers = rows(campaign?.alerts)
  const objective = text(mission?.objective, text(campaign?.goal, 'No recorded mission objective'))
  const campaignFresh = store.slot('campaign').state === 'available'
  const runFresh = store.slot('run').state === 'available'
  const workerFresh = store.slot('capabilities').state === 'available'
  const overallState = text(campaignFresh ? campaign?.state : null, text(runFresh ? mission?.state : null, 'unknown'))
  const missionBlocker = object(mission?.blocker)
  const activity = store.events().slice(0, 6)
  const budget = store.value('budget')
  const primary = el('section', 'hero card',
    el('div', 'hero-top', el('div', 'hero-emblem', icon('shield')), el('div', 'hero-label',
      el('p', 'eyebrow', 'CURRENT MISSION'), el('h2', '', text(currentSession?.name, text(store.session()?.name, 'Session overview')))),
      badge(overallState)),
    el('p', 'objective', objective),
    el('div', 'hero-rule'),
    el('div', 'hero-metadata',
      el('div', '', el('small', '', 'Engagement scope'), el('strong', 'mono', text(currentSession?.target, 'Unknown'))),
      el('div', '', el('small', '', 'Operational phase'), el('strong', '', human(mission?.current_phase ?? progress?.current_phase ?? currentSession?.phase))),
      el('div', '', el('small', '', 'Campaign state'), el('strong', '', human(campaign?.state,
        store.slot('campaign').state === 'not_started' ? 'Not started' : 'Unknown'))),
      button('Inspect scope', () => detail('Engagement scope', [fields([
        ['Session', text(currentSession?.name, 'Unknown')], ['Targets', strings(scope?.targets).join(', ') || 'Not recorded'],
        ['Ports', Array.isArray(scope?.ports) ? scope.ports.filter(port => typeof port === 'number').join(', ') || 'None recorded' : 'Not recorded'],
        ['Exclusions', Array.isArray(scope?.exclusions) ? strings(scope?.exclusions).join(', ') || 'None recorded' : 'Not recorded'],
        ['Session status', human(currentSession?.status)], ['Created', date(currentSession?.created_at)]] )]), 'button small')),
    status(store.slot('session')), status(store.slot('run')), campaign ? status(store.slot('campaign')) : null)
  const pending = mission?.pending_tasks
  const completed = mission?.completed_task_ids
  const stats = el('div', 'metrics-grid',
    stat('Bounded run', human(runFresh ? mission?.state : store.slot('run').state),
      runFresh && text(mission?.bounded_run_state) ? 'Run · ' + human(mission?.bounded_run_state) : 'Awaiting a current run record', 'operations', () => go('operations')),
    stat('Assigned work', Array.isArray(pending) ? count(pending.length) : 'Unknown',
      Array.isArray(completed) ? count(completed.length) + ' completed tasks' : 'Durable team ledger', 'agents', () => go('agents')),
    stat('Review queue', runFresh && run.waiting_approval === true ? 'Waiting' : runFresh && run.waiting_approval === false ? 'Clear' : 'Unknown',
      'Autonomous run checkpoint', 'clock', () => go('operations')),
    stat('Execution worker', human(workerFresh ? worker?.status : store.slot('capabilities').state), workerFresh && worker?.status === 'online' ?
      count(strings(worker.available_tools).length) + ' advertised tools' : 'Reported by capabilities', 'infrastructure', () => go('infrastructure')))
  const alerts = [] as Node[]
  if (missionBlocker) alerts.push(el('p', '', text(missionBlocker.summary, text(missionBlocker.message, text(mission?.reason, human(mission?.reason_code))))))
  for (const row of blockers.slice(0, 4)) alerts.push(el('p', '', text(row.detail, human(row.code))))
  const stale = store.slot('budget').state === 'stale'
  if (object(budget?.admission)?.state === 'blocked' && !stale) alerts.push(el('p', '', 'The engagement cannot reserve the minimum resources for a model attempt.'))
  const hasUnavailable = ['run', 'campaign', 'budget'].some(key => ['unavailable', 'denied', 'stale', 'loading'].includes(store.slot(key as SourceKey).state))
  const blockerPanel = card('Current blockers', alerts.length ? alerts : [
    empty(hasUnavailable ? 'One or more blocker sources are unavailable or still loading.' : 'No blockers recorded by the loaded sources.')
  ], { action: button('Operations', () => go('operations'), 'text-button', 'chevron') })
  const events = card('Recent events', [
    ...(store.eventError ? [el('p', 'subtle', store.eventError)] : []),
    ...(activity.length ? activity.map(event => recordButton(human(event.kind), date(event.timestamp) + ' · ' + human(event.source),
      event.state, () => eventDetail(event, detail, advanced))) :
      [empty(!store.feed.team && !store.feed.campaign ? 'Loading event sources…' : 'No events in the retained window.')])
  ], { action: button('View timeline', () => go('events'), 'text-button', 'chevron') })
  return [primary, stats, el('div', 'overview-grid',
    el('div', 'stack', sourceCard(store, 'budget', 'Model budget', value => budgetSummary(value, advanced),
      button('Analytics', () => go('analytics'), 'text-button', 'chevron')), blockerPanel),
    el('div', 'stack', events, card('Investigation summary', [fields([
      ['Catalogued evidence', count(runFresh ? mission?.recorded_evidence_count : null)],
      ['Verification ledger entries', count(runFresh ? mission?.recorded_review_count : null)]
    ])], { action: button('Investigation', () => go('investigation'), 'text-button', 'chevron') })))]
}

function stat(label: string, value: string, detail: string, glyph: string, run: () => void) {
  const node = el('button', 'card stat', el('span', 'stat-top', el('span', 'tile-icon', icon(glyph)), label),
    el('strong', '', value), el('span', 'stat-note', detail), el('span', 'stat-arrow', icon('chevron')))
  node.type = 'button'
  node.addEventListener('click', run)
  return node
}
