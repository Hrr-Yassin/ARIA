import { object, records, rows, strings, text, type Json } from './api'
import type { TimelineEvent } from './api'
import type { Edge, Node } from './graph'

export type KnowledgeView = 'asset-graph' | 'exploration-graph'
type Reference = { id: string; relation: string }
export type RecordNode = Node & {
  source: string; sourceId: string; firstSeen: string; lastSeen: string
  references: Reference[]; metadata: Json
}

function recordedOrigin(value: unknown): URL | null {
  if (typeof value !== 'string' || !/^https?:\/\/(?:[a-z0-9.-]+|\[[a-f0-9:]+\])(?::[0-9]+)?$/i.test(value)) return null
  try { return new URL(value) } catch { return null }
}

export function projectKnowledge(view: KnowledgeView, sources: Record<string, Json | null>, events: TimelineEvent[] = [], historical = false) {
  const nodes = new Map<string, RecordNode>()
  const references = (value: unknown, kind: string, relation: string): Reference[] =>
    Array.isArray(value) ? value.flatMap(id => typeof id === 'string' && id ? [{ id: kind + ':' + id, relation }] : []) : []
  function add(kind: string, id: string, label: string, state: string, column: number,
               source: string, record: Json, fields: string[], links: Reference[] = []) {
    if (!id) return
    const key = kind + ':' + id
    if (nodes.has(key)) return
    const distinct = new Map(links.map(link => [JSON.stringify([link.id, link.relation]), link]))
    nodes.set(key, {
      id: key, label, kind, state, column, source, sourceId: id, references: [...distinct.values()],
      firstSeen: text(record.first_recorded_at, text(record.source_timestamp, text(record.created_at, text(record.captured_at)))),
      lastSeen: text(record.recorded_at, text(record.updated_at, text(record.cataloged_at, text(record.finished_at,
        text(record.source_timestamp, text(record.created_at, text(record.captured_at))))))),
      metadata: Object.fromEntries(fields.filter(field => record[field] != null).map(field => [field, record[field]])),
    })
  }

  const evidence = rows(sources.team?.evidence)
  const byCapture = new Map<string, string[]>()
  for (const record of evidence) {
    const id = text(record.id)
    const sourceId = text(record.source_id)
    if (record.source_kind === 'chat' && sourceId && id) {
      const refs = byCapture.get(sourceId) ?? []
      refs.push(id)
      byCapture.set(sourceId, refs)
    }
    add('Evidence', id, 'Evidence ' + id.slice(0, 12), 'observed', 3, 'Team evidence catalog', record,
      ['source_kind', 'source_id', 'provenance', 'trust', 'digest'])
  }
  for (const record of rows(sources.verification?.findings)) {
    const lifecycle = text(record.state, 'unknown')
    const links = references(record.evidence_references, 'Evidence', 'Candidate evidence')
    for (const [key, stage] of [['test', 'Test'], ['reproduction', 'Independent reproduction']]) {
      const validation = object(record[key])
      for (const [field, purpose] of [['evidence_references', 'evidence'], ['negative_control_references', 'negative control'],
        ['ownership_references', 'ownership evidence'], ['permission_references', 'permission evidence']]) {
        links.push(...references(validation?.[field], 'Evidence', stage + ' · ' + purpose))
      }
    }
    if (view === 'exploration-graph') links.push(...references([record.specialist_task_id], 'Task', 'Specialist task'))
    const state = !historical && (lifecycle === 'reviewed' || lifecycle === 'reportable')
      ? record.verification_current === true ? 'reviewed' : 'stale' : lifecycle
    const findingId = text(record.id)
    for (const [field, label] of [['human_review', 'Human review'], ['human_signoff', 'Human sign-off']]) {
      const review = object(record[field])
      if (!review || !findingId || !Number.isSafeInteger(review.revision)) continue
      add('Review', findingId + '/' + field + '/' + String(review.revision), label, 'recorded', 4,
        'Finding verification ledger', review, ['reason', 'revision'], references([findingId], 'Finding', label + ' for finding'))
    }
    add('Finding', findingId, text(record.title, 'Candidate finding'), state, 4, 'Finding verification ledger', record,
      ['state', 'revision', 'verification_current', 'ready_for_external_submission', 'smallest_missing_validation'], links)
  }
  const knowledgeById = new Map(rows(sources.team?.knowledge).map(item => [item.id, item.kind]))
  for (const record of rows(sources.team?.knowledge)) {
    const kind = record.kind === 'hypothesis' ? 'Hypothesis' : 'Observation'
    const state = text(record.disposition, 'open')
    const contradictions = Array.isArray(record.contradicts) ? record.contradicts : []
    const links = contradictions.flatMap(id => references([id],
      knowledgeById.get(id) === 'hypothesis' ? 'Hypothesis' : knowledgeById.has(id) ? 'Observation' : 'Knowledge', 'Contradicts'))
    add(kind, text(record.id), text(record.text, kind).slice(0, 160),
      state === 'open' ? kind === 'Observation' ? 'observed' : 'inferred' : state, 2, 'Team knowledge ledger', record,
      ['actor', 'uncertainty', 'disposition'], [...links, ...references(record.evidence_references, 'Evidence', 'Recorded evidence')])
  }

  if (view === 'exploration-graph') {
    const run = sources.run
    const mission = object(run?.mission)
    const objective = text(mission?.objective)
    const runId = text(run?.run_id)
    if (objective && runId && mission) add('Objective', runId, objective.slice(0, 160),
      text(mission.state, 'recorded'), 0, 'Current mission run', mission, ['reason_code'])
    for (const event of events) {
      const links = [
        ...references([event.task_id], 'Task', 'Recorded task revision'),
        ...references(event.evidence_ids, 'Evidence', 'Event references evidence'),
        ...references(event.dependency_ids, 'Task', 'Recorded dependency'),
      ]
      if (event.run_id === runId && runId && objective) links.push(...references([runId], 'Objective', 'Recorded run identifier'))
      add('Event', event.source + '/' + (event.campaign_id ?? event.session_id) + '/' + event.id, event.kind.replaceAll('_', ' '),
        text(event.state, 'recorded'), 1, 'Mission ' + event.source + ' history', { ...event, created_at: event.timestamp },
        ['sequence', 'agent', 'campaign_id', 'run_id', 'reason_code'], links)
    }
    const journal = object(sources.operations?.authorizations)
    for (const record of rows(journal?.records)) {
      const id = text(record.id)
      const proposal = text(record.action_id)
      if (!id || !proposal) continue
      add('Authorization', id, text(record.event, 'Authorization').replaceAll('_', ' '),
        text(record.decision, 'recorded'), 2, 'Authorization journal', { ...record, created_at: record.timestamp },
        ['event', 'action_id', 'decision', 'tool'],
        id === proposal ? [] : references([proposal], 'Authorization', 'Stored proposal identifier'))
    }
    for (const record of rows(sources.team?.tasks)) {
      const role = text(record.owner_role)
      if (role) add('Agent', role, role, 'recorded', 0, 'Recorded task assignment role', {}, [])
      add('Task', text(record.id), text(record.title, text(record.objective, 'Task')).slice(0, 160), text(record.state, 'unknown'), 0, 'Team task ledger', record,
        ['owner_role', 'revision', 'reason', 'finished_at'], [
          ...references([role], 'Agent', 'Assigned role'),
          ...references(record.dependencies, 'Task', 'Depends on'),
          ...references(record.evidence_inputs, 'Evidence', 'Assigned evidence'),
          ...references(object(record.result)?.evidence_references, 'Evidence', 'Result cites evidence'),
        ])
    }
    for (const record of rows(sources.research?.hypotheses)) {
      const lifecycle = text(record.state, 'unknown').toLowerCase()
      add('Research hypothesis', text(record.id), text(record.title, 'Research hypothesis'),
        historical ? lifecycle : lifecycle === 'rejected' ? 'rejected' : record.confirmed === true ? 'reviewed' : 'inferred', 1, 'Research ledger', record,
        ['state', 'revision', 'uncertainty', 'requires_revalidation', 'confirmed'], [
          ...references(record.supporting_evidence, 'Evidence', 'Supporting evidence'),
          ...references(record.evidence_references, 'Evidence', 'Recorded evidence'),
          ...references([record.finding_id], 'Finding', 'Linked finding'),
        ])
    }
  } else {
    const map = sources.appMap
    const session = sources.session
    const engagementId = text(session?.session_id)
    function groupOrigin(url: URL, at: unknown) {
      const origin = url.origin
      const domain = /^[a-z0-9.-]+$/i.test(url.hostname) && /[a-z]/i.test(url.hostname) ? url.hostname : ''
      add('Application', origin, origin, 'observed', 1, 'Retained HTTP origins', {}, [],
        [...references([engagementId], 'Engagement', 'Origin recorded in engagement'),
          ...references([domain], 'Domain', 'Hostname recorded in application origin')])
      if (domain) add('Domain', domain, domain, 'observed', 0, 'Retained HTTP hostname', {}, [])
      markRecorded(['Application:' + origin, 'Domain:' + domain], at)
    }
    function markRecorded(keys: string[], at: unknown) {
      const time = Date.parse(text(at))
      if (!Number.isFinite(time)) return
      const observed = new Date(time).toISOString()
      for (const key of keys) {
        const node = nodes.get(key)
        if (!node) continue
        if (!node.firstSeen || node.firstSeen > observed) node.firstSeen = observed
        if (!node.lastSeen || node.lastSeen < observed) node.lastSeen = observed
      }
    }
    if (session && engagementId) add('Engagement', engagementId, text(session.name, 'Engagement'),
      'recorded', 0, 'Session record', session, ['phase', 'status'])
    const policy = object(object(session?.scope)?.program_policy)
    if (policy) add('Program', text(policy.program_id), 'Research program', text(policy.state, 'recorded'),
      0, 'Engagement program policy', policy, ['snapshot_id', 'state'], references([engagementId], 'Engagement', 'Program assigned to engagement'))
    for (const record of rows(sources.reports?.report_drafts)) {
      add('Document', text(record.id), text(record.title, 'Report draft'), 'recorded', 4, 'Report drafts', record,
        ['revision'], references(Object.keys(object(record.evidence_snapshot) ?? {}), 'Evidence', 'Report evidence snapshot'))
    }
    for (const record of rows(sources.hosts?.hosts)) {
      const id = text(record.ip)
      if (!id) continue
      add('Host', id, text(record.hostname, id), 'observed', 0, 'Process-local topology', record, ['ip', 'os'])
      for (const service of rows(record.ports)) {
        if (!Number.isInteger(service.port)) continue
        add('Service', id + '/' + String(service.port), text(service.service, 'Service') + ' ' + service.port,
          'observed', 1, 'Process-local topology', service, ['port', 'version'], references([id], 'Host', 'Observed on host'))
      }
    }
    for (const record of rows(sources.traffic?.captures)) {
      const id = text(record.id)
      if (!id) continue
      const url = recordedOrigin(record.destination)
      const origin = url?.origin ?? ''
      if (url) groupOrigin(url, record.imported_at)
      add('Traffic record', id, [text(record.method, 'HTTP capture'), origin].filter(Boolean).join(' '), 'observed', 3,
        'Mission Traffic', { ...record, destination: origin || null, capture_source: record.source,
          first_recorded_at: record.imported_at, recorded_at: record.imported_at },
        ['capture_source', 'destination', 'method', 'captured_at', 'imported_at', 'response_status', 'response_content_type'], [
          ...references([origin], 'Application', 'Origin recorded in saved capture'),
          ...references(byCapture.get(id), 'Evidence', 'Cataloged capture source'),
        ])
    }
    const captureIdsBySource = new Map<string, string[]>()
    for (const record of records(map?.captures)) {
      const id = text(record.id)
      if (!id) continue
      const sourceId = text(record.evidence_id)
      if (sourceId) {
        const ids = captureIdsBySource.get(sourceId) ?? []
        ids.push(id)
        captureIdsBySource.set(sourceId, ids)
      }
      const url = recordedOrigin(record.origin)
      const origin = url?.origin ?? ''
      const route = text(record.route)
      const method = text(record.method)
      const endpoint = origin && method && /^\/(?!\/)[^?#]*$/.test(route) ? origin + ' ' + method + ' ' + route : ''
      if (url) groupOrigin(url, record.created_at)
      if (endpoint) {
        add('Endpoint', endpoint, method + ' ' + route, 'observed', 2, 'Application map capture route', {}, [],
          references([origin], 'Application', 'Route recorded on origin'))
        markRecorded(['Endpoint:' + endpoint], record.created_at)
      }
      add('HTTP capture', id, method || 'HTTP capture', record.expired === true ? 'expired' : 'observed', 3,
        'Application map', record, ['method', 'expired'], [
          ...references([endpoint], 'Endpoint', 'Request recorded for endpoint'),
          ...references(endpoint ? [] : [origin], 'Application', 'Capture records origin'),
          ...references([sourceId], 'Traffic record', 'Mapped from saved capture'),
          ...references(byCapture.get(sourceId), 'Evidence', 'Cataloged capture source'),
        ])
    }
    for (const [collection, kind] of [['objects', 'Object'], ['workflows', 'Workflow']]) {
      for (const record of records(map?.[collection])) {
        add(kind, text(record.id), text(record.label, text(record.name, kind)), 'recorded', 1, 'Application map', record,
          ['created_at'], strings(record.evidence_ids).flatMap(sourceId => captureIdsBySource.has(sourceId)
            ? references(captureIdsBySource.get(sourceId), 'HTTP capture', 'Mapped capture reference')
            : references([sourceId], 'Capture source', 'Mapped capture reference')))
      }
    }
    const model = object(sources.research?.application_model)
    const modelRelations = new Map<string, Reference[]>()
    for (const edge of rows(model?.edges)) {
      const source = text(edge.source)
      const related = modelRelations.get(source) ?? []
      related.push(...references([edge.target], 'Model asset', 'Model assertion · ' + text(edge.relation, 'relationship')))
      modelRelations.set(source, related)
    }
    for (const record of rows(model?.nodes)) {
      const id = text(record.id)
      add('Model asset', id, text(record.label, 'Model asset'), sources.research?.application_model_current === true ? 'inferred' : 'stale',
        1, 'Research application model', record, ['kind'], [
          ...(modelRelations.get(id) ?? []), ...references(record.evidence_references, 'Evidence', 'Model citation'),
        ])
    }
  }
  const edges: Edge[] = []
  const incoming = new Map<string, Reference[]>()
  for (const node of nodes.values()) for (const ref of node.references) {
    if (!nodes.has(ref.id)) continue
    edges.push({ source: node.id, target: ref.id, kind: ref.relation })
    const reverse = incoming.get(ref.id) ?? []
    reverse.push({ id: node.id, relation: ref.relation })
    incoming.set(ref.id, reverse)
  }
  return { nodes, edges, incoming }
}
