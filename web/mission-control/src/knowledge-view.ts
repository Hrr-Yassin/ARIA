import { object, rows, text, type SourceKey } from './api'
import { badge, card, date, el, empty, fields, human, labelControl, link, select, status, button } from './dom'
import { projectKnowledge, type KnowledgeView } from './knowledge'
import { labels, recordFields, type Detail, type Lazy } from './panels'
import type { MissionStore } from './store'
import { findingHistory } from './evidence-review'

const pageSize = 80
type GraphFilters = { search: string; kind: string; state: string; page: number; hidden: Set<string> }
const defaults = (): GraphFilters => ({ search: '', kind: '', state: '', page: 0, hidden: new Set() })
const memories = new WeakMap<MissionStore, { sid: string; views: Record<KnowledgeView, GraphFilters> }>()

export function knowledgeView(view: KnowledgeView, store: MissionStore, detail: Detail, lazy: Lazy) {
  const keys: SourceKey[] = ['team', 'research', 'verification']
  if (view === 'asset-graph') keys.push('session', 'hosts', 'appMap', 'reports', 'traffic')
  else keys.push('run', 'operations')
  const checkpoint = view === 'exploration-graph' ? store.teamCheckpoint : null
  const records = object(checkpoint?.value?.records)
  const events = store.eventsDenied ? [] : store.events()
  const teamEvents = events.filter(event => event.source === 'team' && event.sequence !== null)
  const sources = checkpoint ? { team: records, research: { hypotheses: records?.research_hypotheses },
    verification: { findings: records?.verification_findings } } : Object.fromEntries(keys.map(key => [key, store.value(key)]))
  const graphEvents = checkpoint ? (records ? teamEvents.filter(event => event.sequence! <= checkpoint.sequence) : []) : events
  const { nodes, edges, incoming } = projectKnowledge(view, sources, graphEvents, !!checkpoint)
  let memory = memories.get(store)
  if (!memory || memory.sid !== store.sid) {
    memory = { sid: store.sid, views: { 'asset-graph': defaults(), 'exploration-graph': defaults() } }
    memories.set(store, memory)
  }
  const filters = memory.views[view]
  const kindNames = [...new Set([...nodes.values()].map(node => node.kind))].sort()
  const states = [...new Set([...nodes.values()].map(node => node.state))].sort()
  const search = el('input')
  search.type = 'search'
  search.dataset.focus = 'graph-search'
  search.value = filters.search
  search.placeholder = 'Name or record ID'
  const plot = el('div', 'viz')
  const list = el('div', 'stack')
  const summary = el('p', 'subtle')
  summary.setAttribute('role', 'status')
  let revision = 0
  let dispose: (() => void) | undefined

  function inspect(id: string) {
    const node = nodes.get(id)
    if (!node) return
    const traffic = node.kind === 'Traffic record' ? rows(sources.traffic?.captures).find(record => record.id === node.sourceId) : undefined
    const signal = store.signal
    const openTraffic = traffic ? button('Open saved HTTP inspection', () => {
      void import('./traffic').then(module => {
        if (!signal.aborted && openTraffic?.isConnected && store.view === view && store.slot('traffic').state !== 'denied') {
          return module.inspectTrafficCapture(store, detail, traffic)
        }
      }).catch(() => {
        if (openTraffic?.isConnected) openTraffic.replaceWith(el('p', 'subtle', 'The HTTP inspector is unavailable.'))
      })
    }) : null
    const related = (entries: typeof node.references, direction: string) => entries.map(ref => {
      const record = nodes.get(ref.id)
      return record
        ? button(direction + ' · ' + ref.relation + ' · ' + record.label, () => inspect(ref.id), 'button')
        : el('p', 'subtle', ref.relation + ' · ' + ref.id + ' · unavailable in this snapshot')
    })
    detail(node.label, [
      badge(node.state), fields([['Record', node.id], ['Source', node.source], ['Source ID', node.sourceId],
        ['Engagement', store.sid], ['Access', 'Engagement owner'], ['First recorded', date(node.firstSeen)],
        ['Last recorded', date(node.lastSeen)]]),
      recordFields(node.metadata, Object.keys(node.metadata)),
      ...(openTraffic ? [openTraffic] : []),
      ...(node.kind === 'Finding' && !checkpoint ? [findingHistory(store, node.sourceId, rows(store.value('team')?.evidence),
        record => inspect('Evidence:' + record.id))] : []),
      el('h3', '', 'Record relationships'),
      ...related(node.references, 'References'), ...related(incoming.get(id) ?? [], 'Referenced by'),
      ...(!node.references.length && !incoming.has(id) ? [empty('No explicit relationships in this snapshot.')] : []),
    ])
  }

  function render() {
    const current = ++revision
    dispose?.()
    dispose = undefined
    const query = filters.search.trim().toLowerCase()
    const matched = [...nodes.values()].filter(node =>
      (!filters.kind || node.kind === filters.kind) && (!filters.state || node.state === filters.state)
      && !filters.hidden.has(node.kind) &&
      (!query || [node.label, node.id, node.state, node.source].some(value => value.toLowerCase().includes(query))))
      .sort((a, b) => b.firstSeen.localeCompare(a.firstSeen) || a.id.localeCompare(b.id))
    filters.page = Math.min(filters.page, Math.max(0, Math.ceil(matched.length / pageSize) - 1))
    const page = filters.page
    const visible = matched.slice(page * pageSize, (page + 1) * pageSize)
    const ids = new Set(visible.map(node => node.id))
    summary.textContent = visible.length
      ? (page * pageSize + 1) + '–' + (page * pageSize + visible.length) + ' of ' + matched.length + ' records'
      : 'No records match these filters.'
    previous.disabled = page === 0
    next.disabled = (page + 1) * pageSize >= matched.length
    plot.replaceChildren(empty(visible.length ? 'Preparing graph…' : 'No graph records in this view.'))
    list.replaceChildren(...visible.map(node => button(node.kind + ' · ' + node.label + ' · ' + human(node.state),
      () => inspect(node.id), 'button graph-record')))
    if (visible.length) void import('./graph').then(module => {
      if (current !== revision || !plot.isConnected) return
      dispose = module.mountGraph(plot, { label: labels[view], nodes: visible, directed: true,
        edges: edges.filter(edge => ids.has(edge.source) && ids.has(edge.target)), motion: store.preferences.motion, inspect })
    }).catch(() => {
      if (current === revision && plot.isConnected) plot.replaceChildren(empty('Graph unavailable. Use the record list to inspect the sources.'))
    })
  }

  const apply = () => { filters.page = 0; render() }
  search.addEventListener('input', () => { filters.search = search.value; apply() })
  const previous = button('Previous records', () => { filters.page -= 1; render() }, 'button small')
  const next = button('Next records', () => { filters.page += 1; render() }, 'button small')
  const choices = new Map(teamEvents.map(event => [String(event.sequence),
    '#' + event.sequence + ' · ' + human(event.kind) + ' · ' + date(event.timestamp)]))
  const selected = checkpoint ? String(checkpoint.sequence) : ''
  if (selected && !choices.has(selected)) choices.set(selected, '#' + selected + ' · Saved checkpoint')
  const picker = select([['', 'Current records'], ...choices], selected, value => {
    filters.kind = filters.state = ''
    filters.page = 0
    void store.selectTeamCheckpoint(value ? Number(value) : null)
  })
  picker.dataset.focus = 'team-checkpoint'
  picker.disabled = !choices.size
  const checkpointStatus = el('p', 'subtle', checkpoint?.state === 'available' ?
    'Saved checkpoint #' + checkpoint.sequence + ' · ' + date(checkpoint.value?.timestamp) + ' · Retained team records' :
    checkpoint?.state === 'loading' ? 'Loading saved checkpoint…' : checkpoint ? 'Saved checkpoint unavailable.' : '')
  checkpointStatus.setAttribute('role', 'status')
  const earlier = button(store.historyLoading ? 'Loading earlier checkpoints…' : 'Load earlier checkpoints', () => void store.loadOlder(), 'button small')
  earlier.disabled = store.historyLoading
  const groups = el('div', 'filter-bar', ...kindNames.map(kind => {
    const toggle = el('input')
    toggle.type = 'checkbox'
    toggle.checked = !filters.hidden.has(kind)
    toggle.addEventListener('change', () => {
      if (toggle.checked) filters.hidden.delete(kind)
      else filters.hidden.add(kind)
      apply()
    })
    return el('label', 'graph-group', toggle, kind)
  }))
  lazy(plot, async () => {
    if (!plot.isConnected) return
    render()
    return () => { revision += 1; dispose?.() }
  })
  return [card(labels[view], [
    ...(!checkpoint ? keys : []).flatMap(key => {
      const message = status(store.slot(key))
      return message ? [el('div', 'split-grid', el('small', '', human(key)), message)] : []
    }),
    ...(text(sources.traffic?.next_before) ? [el('p', 'subtle',
      'The graph includes the latest saved HTTP captures. ', link('Browse earlier captures in Traffic', store.href('traffic')))] : []),
    el('div', 'filter-bar', labelControl('Search graph', search),
      labelControl('Record type', select([['', 'All types'], ...kindNames.map((kind): [string, string] => [kind, kind])],
        filters.kind, value => { filters.kind = value; apply() })),
      labelControl('Record state', select([['', 'All states'], ...states.map((state): [string, string] => [state, human(state)])],
        filters.state, value => { filters.state = value; apply() }))),
    ...(view === 'exploration-graph' ? [el('div', 'filter-bar', labelControl('Team checkpoint', picker),
      store.canLoadOlder ? earlier : null), ...(checkpoint ? [checkpointStatus] : []),
      ...(store.historyError ? [el('p', 'subtle', store.historyError)] : []),
      ...(checkpoint?.value?.event_gap === true ? [el('p', 'callout', 'There are missing or ambiguous ledger sequences in this history.')] : []),
      ...(checkpoint?.value?.truncated === true ? [el('p', 'callout', 'Showing the latest 2,000 retained record revisions at this checkpoint.')] : []),
      ...(Number(checkpoint?.value?.rejected_records) > 0 ? [el('p', 'callout', checkpoint?.value?.rejected_records + ' unreadable graph records.')] : []),
    ] : []),
    el('details', 'graph-records', el('summary', '', 'Visible node groups'), groups),
    summary, plot, el('div', 'filter-bar', previous, next),
    el('details', 'graph-records', el('summary', '', 'Record list'), list),
  ])]
}
