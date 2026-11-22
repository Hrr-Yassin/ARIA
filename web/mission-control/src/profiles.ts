import { request } from './api'
import { badge, button, card, el, empty, fields, human, select } from './dom'
import type { MissionStore } from './store'

type Json = Record<string, unknown>
const KINDS: [string, string][] = [
  ['private_lab', 'Private Lab'], ['ctf', 'CTF'], ['authorized_pentest', 'Authorized Pentest'], ['bug_bounty', 'Bug Bounty']]

const now = new Date()
const iso = (days: number) => new Date(now.getTime() + days * 86400000).toISOString()
// Starting templates only; the backend validates every field and states what is missing.
const TEMPLATES: Record<string, Json> = {
  private_lab: { kind: 'private_lab', targets: [], ports: [], inventory: [], permitted_capabilities: ['httpx.http.probe.v1'],
    prohibited_capabilities: [], approval: 'sensitive', ownership_statement: '',
    isolation: { network_isolated: true, description: '' }, retention_days: 30, model_sharing: 'deny' },
  ctf: { kind: 'ctf', targets: [], permitted_capabilities: ['httpx.http.probe.v1'], approval: 'sensitive', challenge_name: '',
    challenge_scope: '', rules_text: '', rules_source: '', valid_until: iso(2), retention_days: 30, model_sharing: 'deny' },
  authorized_pentest: { kind: 'authorized_pentest', targets: [], exclusions: [], permitted_capabilities: ['httpx.http.probe.v1'],
    approval: 'sensitive', authorization_reference: '', authorized_by: '', authorization_document_sha256: '',
    rules_of_engagement: '', valid_from: iso(0), valid_until: iso(14), retention_days: 90, model_sharing: 'deny' },
  bug_bounty: { kind: 'bug_bounty', targets: [], exclusions: [], permitted_capabilities: ['httpx.http.probe.v1'],
    approval: 'sensitive', program_snapshot_id: '', testing_restrictions: '', retention_days: 90, model_sharing: 'deny' }
}
const EDITABLE_OMIT = new Set(['revision', 'integrity', 'changed_by', 'changed_at', 'reason', 'rules_provenance'])

function editable(profile: Json): Json {
  return Object.fromEntries(Object.entries(profile).filter(([key]) => !EDITABLE_OMIT.has(key)))
}

function list(items: unknown[], render: (item: Json) => HTMLElement[], none: string): HTMLElement {
  if (!items.length) return empty(none)
  const table = el('table', 'table')
  for (const item of items) table.append(el('tr', '', ...render(item as Json).map(cell => el('td', '', cell))))
  return table
}

function describeError(error: unknown): string {
  if (error instanceof Error) return error.message
  return 'The profile could not be saved.'
}

export function profilePanel(store: MissionStore, rerender: () => void): HTMLElement {
  const body = el('div', 'stack', empty('Loading authorization profile…'))
  const panel = card('Authorization profile', [body], { id: 'authorization-profile' })
  const sid = store.sid
  if (!sid) {
    body.replaceChildren(empty('Select an engagement to view or configure its authorization profile.'))
    return panel
  }
  void (async () => {
    try {
      const [view, kinds] = await Promise.all([
        request(`/api/engagements/${encodeURIComponent(sid)}/profile`),
        request('/api/engagements/profile-kinds')])
      if (!panel.isConnected || !view) return
      body.replaceChildren(...render(sid, view, (kinds?.kinds ?? {}) as Json, rerender))
    } catch (error) {
      body.replaceChildren(empty(describeError(error)))
    }
  })()
  return panel
}

function render(sid: string, view: Json, kinds: Json, rerender: () => void): HTMLElement[] {
  const profile = (view.profile ?? null) as Json | null
  const restrictions = (view.restrictions ?? {}) as Json
  const enforced = (restrictions.enforced ?? {}) as Json
  const revision = Number(profile?.revision ?? 0)
  let kind = String(profile?.kind ?? 'private_lab')
  const summary = profile
    ? fields([['Profile', human(profile.kind)], ['Revision', String(revision)], ['Changed by', String(profile.changed_by ?? '')],
              ['Reason', String(profile.reason ?? '')]])
    : el('p', 'notice', String(restrictions.warning ?? 'No authorization profile is configured.'))
  const restrictionList = profile
    ? fields(Object.entries(enforced).map(([key, value]) => [human(key), Array.isArray(value) ? value.join(', ') || 'None' : String(value ?? 'None')]))
    : empty('Only the legacy engagement scope applies.')

  const requirement = el('p', 'muted')
  const editor = el('textarea', 'code-editor')
  editor.rows = 18
  editor.spellcheck = false
  editor.setAttribute('aria-label', 'Profile definition (JSON)')
  const reason = el('input', 'input')
  reason.placeholder = 'Reason for this change (recorded in the audit log)'
  reason.setAttribute('aria-label', 'Reason for change')
  const status = el('p', 'muted', '')
  status.setAttribute('role', 'status')
  const load = (selected: string) => {
    kind = selected
    const spec = (kinds[selected] ?? {}) as Json
    requirement.textContent = 'Required: ' + ((spec.required as string[] | undefined) ?? []).join(', ')
    const base = profile && profile.kind === selected ? editable(profile) : TEMPLATES[selected]
    editor.value = JSON.stringify(base, null, 2)
  }
  load(kind)
  const kindSelect = select(KINDS, kind, load)
  kindSelect.setAttribute('aria-label', 'Profile type')
  const save = button('Save profile', async () => {
    let definition: Json
    try { definition = JSON.parse(editor.value) as Json }
    catch { status.textContent = 'The profile definition is not valid JSON.'; return }
    if (definition.kind !== kind) { status.textContent = 'The definition kind must match the selected profile type.'; return }
    if (!reason.value.trim()) { status.textContent = 'A reason is required.'; return }
    save.disabled = true
    status.textContent = 'Saving…'
    try {
      await request(`/api/engagements/${encodeURIComponent(sid)}/profile`, {
        method: 'POST', data: { expected_revision: revision, reason: reason.value.trim(), profile: definition } })
      status.textContent = 'Saved. Approvals bound to the previous policy are no longer valid.'
      rerender()
    } catch (error) {
      status.textContent = describeError(error)
    } finally { save.disabled = false }
  }, 'button primary')

  const denied = list((view.denied_operations as unknown[]) ?? [], item => [
    el('span', '', String(item.at ?? '')), badge('denied', human(item.reason ?? item.code ?? 'denied')),
    el('span', '', String(item.stage ?? '')), el('span', '', String(item.message ?? ''))], 'No denied operations recorded.')
  const history = list((view.history as unknown[]) ?? [], item => [
    el('span', '', String(item.at ?? '')), el('span', '', 'Revision ' + String(item.revision ?? '')),
    el('span', '', human(item.previous_kind ?? 'none') + ' → ' + human(item.kind)),
    el('span', '', String(item.reason ?? '')), el('span', '', String(item.actor ?? ''))], 'No profile changes recorded.')

  return [
    el('h3', '', 'Current policy'), summary,
    el('h3', '', 'Enforced restrictions'), restrictionList,
    el('h3', '', 'Configure'), el('div', 'row', kindSelect), requirement, editor, reason, el('div', 'row', save), status,
    el('p', 'muted', 'Sensitive operations wait for approval in Operations → Pending proposals. Chat cannot change this profile.'),
    el('h3', '', 'Denied operations'), denied,
    el('h3', '', 'Policy changes'), history]
}
