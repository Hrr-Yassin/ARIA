import { ApiError, number, object, request, rows, strings, text, type Json } from './api'
import { button, date, el, empty, fields, labelControl, link, recordButton, select } from './dom'
import { recordFields, sourceCard, type Detail } from './panels'
import type { MissionStore } from './store'

const sources = new Map<string, string>([
  ['burp_community_selected_history', 'Selected Burp history import'],
  ['authenticated_worker_receipt', 'Retained application capture'],
  ['sanitized_har_import', 'Sanitized HAR import'],
])

const previewStates = new Map<string, string>([
  ['missing', 'No body text in the archive.'], ['not_selected', 'Body preview was excluded at import.'],
  ['historical_metadata', 'This source retained metadata for Traffic.'], ['encoded', 'Encoded body preview unavailable.'],
  ['invalid_json', 'Malformed JSON preview unavailable.'], ['unsupported_media', 'Body type unavailable for text preview.'],
  ['oversized', 'Body exceeded the preview processing limit.'], ['redaction_unavailable', 'Body preview could not be redacted.'],
  ['inspection_unavailable', 'The saved inspection could not be verified.'],
])

function messagePanel(label: string, meta: Node, message: Json | null = null) {
  const nodes = [el('h3', '', label), meta]
  if (message) {
    const headers = rows(message.headers).map((header): [string, string] => [text(header.name), text(header.value)])
    const omitted = number(message.omitted_headers)
    const body = object(message.preview)
    const bodyText = body?.text
    nodes.push(el('h4', '', 'Headers'), headers.length ? fields(headers) : empty('No displayable headers recorded.'))
    if (omitted) nodes.push(el('p', 'subtle', omitted + ' additional header fields omitted.'))
    nodes.push(el('h4', '', body?.format === 'json' ? 'JSON body preview' : 'Body preview'))
    if (body?.state === 'available' && typeof bodyText === 'string') {
      const snippet = el('pre', 'traffic-preview', bodyText || '(Empty body)')
      snippet.setAttribute('aria-label', label + ' body preview')
      snippet.tabIndex = 0
      nodes.push(snippet)
    } else nodes.push(empty(previewStates.get(text(body?.state)) ?? 'Body preview unavailable.'))
    if (body?.truncated === true) nodes.push(el('p', 'subtle', 'Preview truncated.'))
  }
  return el('section', 'stack traffic-message', ...nodes)
}

function harImport(store: MissionStore, detail: Detail) {
  const sid = store.sid
  const signal = store.signal
  const input = el('input')
  input.type = 'file'
  input.accept = '.har,.json,application/har+json,application/json'
  const bodies = el('input')
  bodies.type = 'checkbox'
  const option = el('label', 'traffic-check', bodies, 'Include reviewed body previews')
  const message = el('p', 'subtle')
  message.setAttribute('role', 'status')
  const submit = button('Save archive', () => { void save() }, 'button primary')
  submit.disabled = true
  const form = el('div', 'stack', el('p', 'subtle', 'HAR 1.2, up to 1 MiB and 100 exchanges. Select a sanitized archive. Body previews require reviewed text.'),
    labelControl('HAR file', input), option, submit, message)
  input.addEventListener('change', () => { submit.disabled = !input.files?.length })
  detail('Import sanitized HAR', [form])

  async function save() {
    const archive = input.files?.[0]
    if (!archive || submit.disabled || signal.aborted || !form.isConnected) return
    if (archive.size > 1024 * 1024) {
      message.textContent = 'Choose an archive of 1 MiB or less.'
      return
    }
    submit.disabled = input.disabled = bodies.disabled = true
    message.textContent = 'Importing archive…'
    try {
      const path = '/api/mission/' + encodeURIComponent(sid) + '/traffic/import-har' + (bodies.checked ? '?include_bodies=true' : '')
      const result = await request(path, { method: 'POST', archive, signal })
      if (signal.aborted) return
      const counts = ['imported', 'duplicates', 'skipped'].map(key => number(result?.[key]))
      if (result?.schema_version !== 'aria.mission.har-import.v1' || result.session_id !== sid ||
          counts.some(count => count === null || !Number.isSafeInteger(count))) throw new Error('Invalid import acknowledgement')
      const [imported, duplicates, skipped] = counts
      message.textContent = imported + ' imported · ' + duplicates + ' already saved · ' + skipped + ' skipped'
      await store.load('traffic')
      if (!signal.aborted) await store.load('traffic', true)
    } catch (error) {
      if (form.isConnected && !signal.aborted) message.textContent = error instanceof ApiError ? error.message : 'The archive import could not be confirmed.'
    } finally {
      submit.disabled = input.disabled = bodies.disabled = false
    }
  }
}

export async function inspectTrafficCapture(store: MissionStore, detail: Detail, row: Json) {
  const sid = store.sid
  const signal = store.signal
  const id = text(row.id)
  if (!sid || !id || signal.aborted) return
  const evidence = rows(store.value('team')?.evidence)
  const tasks = rows(store.value('team')?.tasks)
  const matches = evidence.filter(item => item.source_kind === 'chat' && item.source_id === id)
  const ids = new Set(matches.map(item => text(item.id)))
  const related = tasks.filter(task => [...strings(task.evidence_inputs), ...strings(object(task.result)?.evidence_references)]
    .some(key => ids.has(key)))
  const inspection = el('div', 'traffic-inspector stack')
  function renderMessages(capture: Json, messages?: Json) {
    const duration = number(capture.latency_ms)
    inspection.replaceChildren(fields([['Record', id], ['Source', sources.get(text(capture.source)) ?? 'Unknown'],
      ['Imported', date(capture.imported_at)], ['Captured', date(capture.captured_at)],
      ['Recorded elapsed time', duration === null ? 'Not recorded' : duration + ' ms']]),
    el('div', 'traffic-pair',
      messagePanel('Request', recordFields(capture, ['method', 'destination', 'request_content_type', 'request_body_bytes']), object(messages?.request)),
      messagePanel('Response', recordFields(capture, ['response_status', 'protocol', 'response_content_type',
        'response_body_bytes', 'response_content_bytes', 'framing']), object(messages?.response))))
  }
  renderMessages(row)
  const status = el('p', 'subtle', 'Loading saved inspection…')
  status.setAttribute('role', 'status')
  const relationships = fields([['Catalog evidence', matches.map(item => text(item.id)).join(', ') || 'No link in the loaded catalog'],
    ['Tasks referencing catalog evidence', related.map(task => text(task.id)).join(', ') || 'No link in the loaded ledger']])
  const catalog = el('div', 'stack')
  detail('HTTP capture', [inspection, status, relationships, catalog])
  try {
    const saved = await request('/api/mission/' + encodeURIComponent(sid) + '/traffic/captures/' + encodeURIComponent(id), { signal })
    if (signal.aborted || !inspection.isConnected) return
    const summary = object(saved?.capture)
    if (saved?.schema_version !== 'aria.mission.traffic.capture.v1' || saved.session_id !== sid || summary?.id !== id ||
        !object(saved.request) || !object(saved.response)) throw new Error('Invalid capture envelope')
    renderMessages(summary, saved)
    status.remove()
    if (matches.length) {
      catalog.append(link('Open Investigation', store.href('investigation')))
    } else if (summary.source === 'sanitized_har_import') {
      const feedback = el('div')
      feedback.setAttribute('role', 'status')
      const requestId = crypto.randomUUID()
      const save = button('Add capture metadata to evidence', () => {
        if (signal.aborted || save.disabled) return
        save.disabled = true
        feedback.textContent = 'Cataloging capture metadata…'
        void store.catalogEvidence('chat', id, requestId).then(evidenceId => {
          if (signal.aborted || !feedback.isConnected) return
          feedback.replaceChildren(el('p', '', 'Capture metadata cataloged · ' + evidenceId),
            link('Open Investigation', store.href('investigation')))
        }).catch(error => {
          if (signal.aborted || !feedback.isConnected) return
          feedback.textContent = error instanceof Error ? error.message : 'Cataloging could not be confirmed.'
          save.disabled = false
        })
      })
      catalog.append(el('p', 'subtle', 'Saved reviews use the retained metadata. Body previews stay in Traffic.'), save, feedback)
    }
  } catch (error) {
    if (signal.aborted || !inspection.isConnected) return
    if (error instanceof ApiError && [401, 403, 404].includes(error.status)) {
      inspection.replaceChildren()
      relationships.remove()
    }
    status.textContent = 'Saved inspection is unavailable.'
  }
}

export function traffic(store: MissionStore, detail: Detail) {
  const sid = store.sid
  return [sourceCard(store, 'traffic', 'Retained HTTP captures', first => {
    const search = el('input')
    search.type = 'search'
    const output = el('div', 'stack')
    const message = el('p', 'subtle')
    message.setAttribute('role', 'status')
    const pages = [first]
    let index = 0
    let denied = false
    const previous = button('Newer captures', () => { index -= 1; render() }, 'button small')
    const next = button('Older captures', () => { void loadOlder() }, 'button small')
    const source = select([['', 'All sources'], ...sources.entries()], '', render)
    function render() {
      if (denied) return
      const query = search.value.trim().toLowerCase()
      const records = rows(pages[index].captures)
      const filtered = records.filter(row => (!source.value || row.source === source.value) &&
        (!query || [row.method, row.destination, row.response_status, row.id, row.response_content_type, sources.get(text(row.source))]
          .some(value => value != null && String(value).toLowerCase().includes(query))))
      previous.disabled = index === 0
      next.disabled = !text(pages[index].next_before)
      message.textContent = filtered.length + ' of ' + records.length + ' captures on page ' + (index + 1)
      output.replaceChildren(...(filtered.length ? filtered.map(row => recordButton(
        [text(row.method, 'Unknown method'), text(row.destination, 'Unknown destination')].join(' '),
        [date(row.captured_at ?? row.imported_at), String(row.response_status ?? 'No recorded status'), sources.get(text(row.source))]
          .filter(Boolean).join(' · '), null, () => { void inspectTrafficCapture(store, detail, row) })) :
        [empty('No retained captures match the current page filters.')]))
    }
    async function loadOlder() {
      if (pages[index + 1]) { index += 1; render(); return }
      const cursor = text(pages[index].next_before)
      if (!cursor) return
      const signal = store.signal
      next.disabled = true
      previous.disabled = true
      try {
        const page = await request('/api/mission/' + encodeURIComponent(sid) + '/traffic?before=' + encodeURIComponent(cursor), { signal })
        if (!output.isConnected || signal.aborted) return
        if (!page || page.session_id !== sid || page.schema_version !== 'aria.mission.traffic.v1' ||
            !Array.isArray(page.captures) || page.next_before === cursor) throw new Error('Capture history unavailable')
        pages.push(page)
        index += 1
        render()
      } catch (error) {
        if (!output.isConnected || signal.aborted) return
        if (error instanceof ApiError && [403, 404].includes(error.status)) {
          denied = true
          pages.length = 0
          search.disabled = true
          source.disabled = true
          output.replaceChildren()
          message.textContent = 'Capture history is no longer accessible. Refresh to reconcile.'
          return
        }
        render()
        message.textContent = 'Older captures are temporarily unavailable.'
      }
    }
    search.addEventListener('input', render)
    render()
    return [el('div', 'filter-bar', labelControl('Search capture page', search), labelControl('Capture source', source)), message, output,
      el('div', 'filter-bar', previous, next)]
  }, store.slot('traffic').state === 'available' ? button('Import HAR', () => harImport(store, detail), 'button small') : undefined)]
}
