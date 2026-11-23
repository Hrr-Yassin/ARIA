export type Json = Record<string, unknown>
export type SourceKey = 'sessions' | 'profile' | 'session' | 'run' | 'campaign' | 'campaignHistory' | 'budget' |
  'capabilities' | 'roster' | 'team' | 'operations' | 'research' | 'verification' | 'findings' |
  'hosts' | 'appMap' | 'reports' | 'health' | 'ready' | 'providers' | 'toolRegistry' | 'toolRestrictions' | 'traffic'
export type DataState = 'loading' | 'available' | 'not_started' | 'stale' | 'unavailable' | 'denied'
export type Slot = { state: DataState; value: Json | null; at?: number; issue?: string }

export const object = (value: unknown): Json | null =>
  value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Json : null
export const text = (value: unknown, fallback = ''): string =>
  typeof value === 'string' && value.trim() ? value : fallback
export const number = (value: unknown): number | null =>
  typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null
export const rows = (value: unknown): Json[] => Array.isArray(value) ? value.filter(item => object(item)) : []
export const strings = (value: unknown): string[] => Array.isArray(value) ? value.filter(item => typeof item === 'string') : []
export const records = (value: unknown): Json[] => object(value) ? rows(Object.values(value as Json)) : rows(value)

type Valid = (record: Json) => boolean
const list = (name: string): Valid => record => Array.isArray(record[name]) && (record[name] as unknown[]).every(item => object(item))
const map = (name: string): Valid => record => !!object(record[name])
const field = (name: string): Valid => record => text(record[name]).length > 0

type Definition = { url: (sid: string) => string; valid: Valid; global?: true; absence?: true; degraded?: true }
export const sources: Record<SourceKey, Definition> = {
  sessions: { url: () => '/api/session/list', valid: value => list('sessions')(value) && rows(value.sessions).every(field('session_id')), global: true },
  profile: { url: () => '/api/profile', valid: field('username'), global: true },
  session: { url: id => '/api/session/' + id, valid: field('session_id') },
  run: { url: id => '/api/pentest/' + id + '/autonomous/status', valid: value => map('mission')(value) && typeof value.active === 'boolean' },
  campaign: { url: id => '/api/pentest/' + id + '/campaign/health?include_absence=true', valid: value =>
    value.schema === 'aria.campaign.health.v1' && field('state')(value) &&
    (value.state !== 'not_started' || field('session_id')(value)) },
  campaignHistory: { url: id => '/api/mission/' + id + '/campaigns', valid: value =>
    field('session_id')(value) && list('campaigns')(value) && (value.next_before === null || typeof value.next_before === 'string') &&
    rows(value.campaigns).every(item => Boolean(text(item.id) && text(item.state)) && Number.isFinite(Date.parse(text(item.created_at)))) },
  budget: { url: id => '/api/mission/' + id + '/accounting', valid: value =>
    value.schema_version === 'aria.mission.accounting.v1' && field('session_id')(value) &&
    map('limits')(value) && map('usage')(value) && map('admission')(value) && list('attempts')(value) },
  capabilities: { url: () => '/api/capabilities', valid: value => field('status')(object(value.worker) ?? {}), global: true },
  toolRegistry: { url: () => '/api/tool-registry', global: true, valid: value => {
    const worker = object(value.worker)
    return value.schema === 'aria.tool.registry.v1' && !!worker && field('status')(worker) &&
      (worker.typed_contract_status === undefined ||
        ['matched', 'mismatch', 'not_reported', 'unavailable', 'invalid'].includes(text(worker.typed_contract_status))) &&
      (worker.typed_registry_sha256 == null || /^[a-f0-9]{64}$/.test(text(worker.typed_registry_sha256))) &&
      list('typed_adapters')(value) && rows(value.typed_adapters).every(row =>
        field('tool')(row) && field('capability')(row) && typeof row.worker_available === 'boolean')
  } },
  toolRestrictions: { url: id => '/api/sessions/' + id + '/tool-restrictions', valid: value =>
    field('session_id')(value) && Array.isArray(value.blocked) && value.blocked.every(item => typeof item === 'string') &&
    (value.engagement_state === undefined || field('engagement_state')(value)) &&
    (value.engagement_blockers === undefined || Array.isArray(value.engagement_blockers) &&
      value.engagement_blockers.every(item => typeof item === 'string')) },
  roster: { url: () => '/api/mission/agents', valid: list('agents'), global: true },
  team: { url: id => '/api/team/' + id, valid: value => list('tasks')(value) && list('evidence')(value) },
  operations: { url: id => '/api/mission/' + id + '/operations', valid: value => {
    const authorization = object(value.authorizations)
    const replays = object(value.web_replays)
    return list('commands')(value) && list('pending')(value) && (value.receipts === null || list('receipts')(value)) &&
      (value.web_replays === null || !!replays && ['records', 'pending_cancellations', 'unknown_outcomes'].every(key =>
        Number.isSafeInteger(replays[key]) && Number(replays[key]) >= 0)) &&
      (value.authorizations == null || !!authorization && list('records')(authorization) && typeof authorization.truncated === 'boolean')
  } },
  research: { url: id => '/api/team/' + id + '/research', valid: list('hypotheses') },
  verification: { url: id => '/api/team/' + id + '/findings', valid: list('findings') },
  findings: { url: id => '/api/findings/' + id, valid: list('findings') },
  hosts: { url: id => '/api/mission/' + id + '/topology', valid: list('hosts') },
  traffic: { url: id => '/api/mission/' + id + '/traffic', valid: value =>
    value.schema_version === 'aria.mission.traffic.v1' && field('session_id')(value) && list('captures')(value)
    && (value.next_before === null || typeof value.next_before === 'string') },
  appMap: { url: id => '/api/application-map/' + id, valid: value => ['objects', 'workflows', 'captures'].every(key => !!object(value[key]) || list(key)(value)) },
  reports: { url: id => '/api/report/' + id + '/drafts', valid: list('report_drafts') },
  health: { url: () => '/api/health', valid: field('status'), global: true },
  ready: { url: () => '/api/ready', valid: value => typeof value.database === 'boolean', global: true, degraded: true },
  providers: { url: () => '/api/v8/llm-status', valid: list('keys'), global: true }
}

export class ApiError extends Error {
  constructor(readonly status: number, message: string, readonly requestId?: string) {
    super(message)
  }
}
const errorLabels: Record<number, string> = {
  400: 'The server rejected the request.', 401: 'Sign-in expired.', 403: 'Access was denied.',
  404: 'The record was not found.', 409: 'The server declined the operation in its current state.',
  413: 'The upload is too large.', 415: 'The archive format is unsupported.',
  422: 'The server rejected the submitted fields.', 429: 'An enforced limit was reached.'
}
export type Diagnostic = { path: string; status: number; duration: number; requestId?: string; handler?: number }
export const diagnostics: Diagnostic[] = []
let diagnosticScope = 0
export function clearDiagnostics() {
  diagnosticScope += 1
  diagnostics.length = 0
}
let redirected = false

export const token = () => localStorage.getItem('pentestai_token')
export function signIn() {
  if (redirected) return
  redirected = true
  for (const key of ['pentestai_token', 'pentestai_user', 'current_session']) localStorage.removeItem(key)
  location.replace('/login?next=mission')
}

type Options = { signal?: AbortSignal; data?: Json; archive?: File; method?: 'GET' | 'POST'; absent?: boolean; degraded?: boolean; timeoutMs?: number }
async function receive<T>(path: string, opts: Options, accept: string,
                          decode: (response: Response, requestId?: string) => Promise<T>): Promise<T | null> {
  const started = performance.now()
  const scope = diagnosticScope
  const credentials = token()
  const headers = new Headers({ 'Accept': accept })
  if (credentials) headers.set('Authorization', 'Bearer ' + credentials)
  if (opts.data || opts.archive) headers.set('Content-Type', opts.archive ? 'application/har+json' : 'application/json')
  const controller = new AbortController()
  const stop = () => controller.abort()
  const timeout = window.setTimeout(stop, opts.timeoutMs ?? 12000)
  if (opts.signal?.aborted) stop()
  opts.signal?.addEventListener('abort', stop, { once: true })
  let response: Response | undefined
  let requestId: string | undefined
  try {
    response = await fetch(path, { method: opts.method ?? 'GET', headers, body: opts.archive ?? (opts.data ? JSON.stringify(opts.data) : undefined),
      signal: controller.signal, cache: 'no-store', credentials: 'same-origin' })
    const id = response.headers.get('x-request-id')
    requestId = id && /^[a-f0-9]{32}$/.test(id) ? id : undefined
    if (response.status === 401) signIn()
    if (opts.absent && response.status === 404) return null
    if (!response.ok && !(opts.degraded && response.status === 503)) {
      const detail = [403, 409].includes(response.status) ?
        object(object(await response.json().catch(() => null))?.detail) : null
      const message = response.status === 403 && detail?.code === 'capability_blocked' ? 'The owner blocked this capability for the engagement.' :
        response.status === 409 && detail?.code === 'har_integrity_invalid' ? 'Saved HAR capture failed integrity validation.' :
        errorLabels[response.status] ?? 'The API is temporarily unavailable.'
      throw new ApiError(response.status, message, requestId)
    }
    return await decode(response, requestId)
  } catch (error) {
    if (error instanceof ApiError || opts.signal?.aborted) throw error
    if (controller.signal.aborted) throw new ApiError(0, 'The API request timed out.')
    throw new ApiError(0, 'The API could not be reached.')
  } finally {
    window.clearTimeout(timeout)
    opts.signal?.removeEventListener('abort', stop)
    if (scope === diagnosticScope && !opts.signal?.aborted) {
      const handler = response?.headers.get('x-aria-handler-ms')
      diagnostics.push({ path: path.split('?')[0], status: response?.status ?? 0,
        duration: performance.now() - started, requestId, handler: handler && /^\d+(\.\d+)?$/.test(handler) ? Number(handler) : undefined })
      if (diagnostics.length > 40) diagnostics.shift()
    }
  }
}

export function request(path: string, opts: Options = {}): Promise<Json | null> {
  return receive(path, opts, 'application/json', async (response, requestId) => {
    const value = object(await response.json().catch(() => null))
    if (!value) throw new ApiError(502, 'The API returned an invalid response.', requestId)
    return value
  })
}

export function signedReportArchive(path: string, manifestDigest: string, signal: AbortSignal): Promise<Blob | null> {
  return receive(path, { signal }, 'application/zip', async (response, requestId) => {
    const type = response.headers.get('content-type')?.split(';')[0].trim().toLowerCase()
    if (type !== 'application/zip' || response.headers.get('x-report-sha256') !== manifestDigest) {
      throw new ApiError(502, 'The exported package did not match the signed preview.', requestId)
    }
    const blob = await response.blob()
    const signature = new Uint8Array(await blob.slice(0, 4).arrayBuffer())
    if (signature.join(',') !== '80,75,3,4') throw new ApiError(502, 'The API returned an invalid report archive.', requestId)
    return blob
  })
}

export async function read(key: SourceKey, sid: string, signal?: AbortSignal): Promise<Json | null> {
  const definition = sources[key]
  const value = await request(definition.url(encodeURIComponent(sid)), { signal, absent: definition.absence, degraded: definition.degraded })
  if (value && (!definition.valid(value) || !definition.global && typeof value.session_id === 'string' && value.session_id !== sid ||
      key === 'budget' && rows(value.attempts).some(attempt => typeof attempt.session_id === 'string' && attempt.session_id !== sid))) {
    throw new ApiError(502, 'The API record did not match its expected schema.')
  }
  return key === 'campaign' && value?.state === 'not_started' ? null : value
}

type LedgerSource = 'team' | 'campaign'
export type TimelineEvent = {
  id: string; source: LedgerSource | 'worker' | 'approval' | 'authorization' | 'model'; sequence: number | null; timestamp: string; kind: string; stage: string;
  session_id: string; entity_id: string | null; state: string | null; agent: string | null;
  campaign_id: string | null; run_id: string | null; task_id: string | null; job_id: string | null;
  reason_code: string | null; correlation_id: string | null; evidence_ids: string[]; dependency_ids: string[]; decision?: string | null; model?: string | null; provider?: string | null; previous_state?: string | null
}
export type Page = { state: 'available' | 'unavailable' | 'not_started'; cursor: number | null; oldest: number | null;
  has_more: boolean; has_older: boolean; gap: boolean; rejected_records: number; campaign_id: string | null; events: TimelineEvent[] }
export function eventPage(value: unknown, sid: string, source: LedgerSource): Page {
  const page = object(value)
  const validCursor = (cursor: unknown) => cursor === null || Number.isSafeInteger(cursor) && Number(cursor) >= 0
  if (!page || !['available', 'unavailable', 'not_started'].includes(text(page.state)) || !Array.isArray(page.events)
      || !validCursor(page.cursor) || !validCursor(page.oldest) || typeof page.gap !== 'boolean'
      || typeof page.has_more !== 'boolean' || typeof page.has_older !== 'boolean'
      || (page.campaign_id !== null && typeof page.campaign_id !== 'string')
      || !page.events.every(item => object(item) && item.session_id === sid && item.source === source &&
        Number.isSafeInteger(item.sequence) && item.sequence > 0 && typeof item.id === 'string' &&
        typeof item.kind === 'string' && typeof item.stage === 'string' && typeof item.timestamp === 'string' &&
        Number.isFinite(Date.parse(item.timestamp)) && Array.isArray(item.evidence_ids) && Array.isArray(item.dependency_ids))) {
    throw new ApiError(502, 'An event source returned an invalid page.')
  }
  return page as Page
}
