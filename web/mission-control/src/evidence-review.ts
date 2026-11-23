import { ApiError, object, request, rows, strings, text, type Json } from './api'
import { badge, button, card, count, date, el, empty, fields, human, labelControl, select } from './dom'
import { recordFields } from './panels'
import type { MissionStore } from './store'

const openStates = new Set(['observation', 'hypothesis', 'tested', 'reproduced', 'reviewed', 'reportable'])

export function dispositionForm(store: MissionStore, finding: Json) {
  const id = text(finding.id)
  const revision = finding.revision
  if (!id || !Number.isSafeInteger(revision) || Number(revision) < 1 || !openStates.has(text(finding.state)) ||
      store.slot('verification').state !== 'available') return null
  const sid = store.sid
  const state = select([['rejected', 'Reject'], ['inconclusive', 'Mark inconclusive'], ['blocked', 'Mark blocked']],
    'rejected', update)
  const reason = el('textarea')
  reason.maxLength = 2000
  reason.required = true
  const missing = el('textarea')
  missing.maxLength = 2000
  const missingField = labelControl('Smallest missing validation', missing)
  const message = el('p', 'subtle')
  message.setAttribute('role', 'status')
  const save = button('Record review disposition', () => { void submit() }, 'button primary')
  const result = el('div', 'stack',
    el('h3', '', 'Record a review disposition'),
    labelControl('Review decision', state), labelControl('Review reason', reason), missingField, save, message)
  let submitted: { key: string; requestId: string } | undefined
  let saving = false
  let locked = false

  function update() {
    const needsMissing = state.value !== 'rejected'
    missingField.hidden = !needsMissing
    save.disabled = saving || locked || !reason.value.trim() || (needsMissing && !missing.value.trim())
  }

  async function submit() {
    if (save.disabled || !result.isConnected || store.sid !== sid) return
    const payload = { expected_revision: revision, state: state.value, reason: reason.value.trim(),
      smallest_missing_validation: state.value === 'rejected' ? '' : missing.value.trim() }
    const key = JSON.stringify(payload)
    if (submitted?.key !== key) submitted = { key, requestId: crypto.randomUUID() }
    saving = true
    update()
    message.textContent = 'Saving review…'
    const signal = store.signal
    try {
      const response = await request('/api/team/' + encodeURIComponent(sid) + '/findings/' + encodeURIComponent(id) + '/review',
        { method: 'POST', signal, data: { ...payload, request_id: submitted.requestId } })
      if (signal.aborted) return
      const data = object(response?.data)
      if (response?.collection !== 'verification_findings' || response.entity_id !== id || data?.state !== payload.state) {
        throw new Error('Review acknowledgement did not match the submitted disposition.')
      }
      if (result.isConnected) result.replaceChildren(badge(data.state), el('p', 'subtle', 'Review recorded at revision ' +
        String(data.revision) + '.'))
      locked = true
      await store.refresh(true)
    } catch (error) {
      if (!result.isConnected || signal.aborted) return
      locked = error instanceof ApiError && [401, 403, 404, 409].includes(error.status)
      message.textContent = locked ? 'The finding is stale or unavailable. Refresh and reopen it before reviewing.' :
        'The review could not be confirmed. An identical retry uses the same request ID.'
      if (locked) await store.refresh(true)
    } finally {
      saving = false
      if (result.isConnected && !signal.aborted) update()
    }
  }
  reason.addEventListener('input', update)
  missing.addEventListener('input', update)
  update()
  return result
}

export function filterFindings(records: Json[], state: string, query: string): Json[] {
  const needle = query.trim().toLowerCase()
  return records.filter(row => (!state || row.state === state) &&
    [row.id, row.title, row.state, human(row.state)].some(value => text(value).toLowerCase().includes(needle)))
}

export function findingHistory(store: MissionStore, id: string, evidence: Json[], inspectEvidence?: (evidence: Json) => void) {
  const sid = store.sid
  const signal = store.signal
  const catalog = new Map(evidence.map(row => [text(row.id), row]))
  const history = el('details', 'card stack', el('summary', '', 'Finding revision history'))
  const content = el('div', 'stack')
  const message = el('p', 'subtle')
  message.setAttribute('role', 'status')
  const latest = button('Latest revisions', () => { void load() }, 'button small')
  const older = button('Older revisions', () => { if (cursor !== null) void load(cursor) }, 'button small')
  let cursor: number | null = null
  let loading = false
  let attempted = false
  older.hidden = true
  history.append(message, el('div', 'filter-bar', latest, older), content)

  function renderRevision(row: Json) {
    const references = Object.entries(object(row.references) ?? {}).flatMap(([kind, values]) => strings(values).map(ref => {
      const record = catalog.get(ref)
      const label = human(kind) + ' · ' + ref
      return record && inspectEvidence ? button(label, () => inspectEvidence(record), 'button small') :
        el('p', 'subtle', label + (record ? '' : ' · unavailable in the loaded catalog'))
    }))
    const digests = Object.entries(object(row.evidence_snapshot) ?? {}).map(([id, hash]): [string, string] => [id, text(hash)])
    return card('Revision ' + count(row.revision), [badge(row.state), fields([
      ['Recorded', date(row.timestamp)], ['Event', text(row.event_id)], ['Actor', human(row.actor, 'Unknown')],
    ]), recordFields(row, ['reason', 'smallest_missing_validation', 'specialist_task_id']), ...references,
    ...(digests.length ? [el('details', '', el('summary', '', 'Saved evidence digests'), fields(digests))] : [])])
  }

  async function load(before?: number) {
    if (loading || signal.aborted || !history.isConnected) return
    attempted = loading = true
    latest.disabled = older.disabled = true
    message.textContent = 'Loading saved revisions…'
    try {
      const path = '/api/team/' + encodeURIComponent(sid) + '/findings/' + encodeURIComponent(id) + '/history'
      const page = await request(path + (before ? '?before_sequence=' + before : ''), { signal })
      if (!history.isConnected || signal.aborted) return
      const next = page?.next_before_sequence
      if (page?.schema_version !== 'aria.mission.finding-history.v1' || page.session_id !== sid || page.finding_id !== id ||
          !Array.isArray(page.revisions) || (next !== null && (!Number.isSafeInteger(next) || Number(next) <= 0 ||
          (before !== undefined && Number(next) >= before)))) throw new Error('Invalid revision window')
      const revisions = rows(page.revisions)
      cursor = next === null ? null : Number(next)
      const rejected = Number(page.rejected_records)
      message.textContent = revisions.length + ' saved revisions on this page' +
        (rejected ? ' · ' + rejected + ' unreadable records' : '')
      content.replaceChildren(...(revisions.length ? revisions.map(renderRevision) : [empty('No readable revisions on this page.')]))
    } catch (error) {
      if (!history.isConnected || signal.aborted) return
      if (error instanceof ApiError && [401, 403, 404].includes(error.status)) {
        cursor = null
        content.replaceChildren()
      }
      message.textContent = 'Finding history is unavailable.'
    } finally {
      loading = false
      latest.disabled = older.disabled = false
      older.hidden = cursor === null
    }
  }
  history.addEventListener('toggle', () => { if (history.open && !attempted) void load() })
  return history
}
