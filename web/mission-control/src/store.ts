import { ApiError, type Json, type Page, type Slot, type SourceKey, type TimelineEvent, clearDiagnostics, eventPage, object, read,
  request, rows, signIn, sources, strings, text, token } from './api'

export const views = ['overview', 'workspace', 'sessions', 'agents', 'tasks', 'communication', 'operations', 'events', 'asset-graph', 'exploration-graph', 'traffic', 'investigation', 'analytics',
  'infrastructure', 'settings'] as const
export type View = typeof views[number]
const viewReads: Record<View, SourceKey[]> = {
  overview: ['session', 'run', 'campaign', 'budget', 'capabilities'],
  workspace: ['session'],
  sessions: ['sessions'], agents: ['team', 'roster', 'budget', 'toolRegistry'], operations: ['operations', 'run', 'campaign'],
  tasks: ['team', 'roster', 'budget'], communication: ['team'],
  events: ['run', 'operations', 'campaignHistory', 'budget'], investigation: ['team', 'research', 'verification', 'findings', 'hosts', 'appMap', 'reports'],
  'asset-graph': ['team', 'research', 'verification', 'session', 'hosts', 'appMap', 'reports', 'traffic'],
  'exploration-graph': ['team', 'research', 'verification', 'run', 'operations'],
  traffic: ['traffic', 'team'],
  analytics: ['budget', 'operations', 'team', 'campaign'], infrastructure: ['health', 'ready', 'capabilities', 'toolRegistry', 'toolRestrictions', 'providers', 'operations'],
  settings: ['budget', 'profile']
}
const freshFor = 20000
const maxEvents = 1000
const maxForwardPages = 4
export const maxSavedReviews = 8
export const maxReviewEvidence = 100
const eventViews = new Set<View>(['overview', 'events', 'exploration-graph'])
const hasEventData = (view: View) => eventViews.has(view) || view === 'analytics'

export function queuedSavedReview(task: Json, sid: string): boolean {
  return task.session_id === sid && task.state === 'queued' && task.owner_role === 'correlation' &&
    !task.campaign_id && (task.internal_review === 'analyze' || task.internal_review === 'challenge')
}

export const accents = ['violet', 'blue', 'teal', 'amber'] as const
export type Preferences = { theme: 'dark' | 'light' | 'system'; accent: typeof accents[number];
  mode: 'simple' | 'advanced'; density: 'standard' | 'compact'; motion: boolean; inspectorWidth: number; collapsedPanels: string[] }

function readPreferences(): Preferences {
  const defaults: Preferences = { theme: 'dark', accent: 'violet', mode: 'simple', density: 'standard', motion: true, inspectorWidth: 470, collapsedPanels: [] }
  try {
    const saved = object(JSON.parse(localStorage.getItem('aria.mission.preferences') ?? '{}')) ?? {}
    return {
      theme: saved.theme === 'light' || saved.theme === 'system' ? saved.theme : defaults.theme,
      accent: accents.find(item => item === saved.accent) ?? defaults.accent,
      mode: saved.mode === 'advanced' ? 'advanced' : 'simple',
      density: saved.density === 'compact' ? 'compact' : 'standard',
      motion: saved.motion !== false,
      inspectorWidth: Math.min(700, Math.max(340, typeof saved.inspectorWidth === 'number' && Number.isFinite(saved.inspectorWidth) ? saved.inspectorWidth : defaults.inspectorWidth)),
      collapsedPanels: Array.isArray(saved.collapsedPanels) ? saved.collapsedPanels.filter((key): key is string =>
        typeof key === 'string' && key.length <= 160).slice(0, 100) : []
    }
  } catch {
    return defaults
  }
}

function groupEvents(page: Page, previous: Page | null): Page {
  return { ...page, oldest: previous?.oldest ?? page.oldest, has_older: !!previous?.has_older || page.has_older,
    gap: !!previous?.gap || page.gap }
}

type CampaignSnapshot = { id: string; state: 'loading' | 'available' | 'unavailable' | 'denied';
  page?: Page; at?: number; issue?: string }
type TeamCheckpoint = { sequence: number; state: 'loading' | 'available' | 'unavailable' | 'denied'; value?: Json }

export class MissionStore {
  sid = ''
  view: View
  preferences = readPreferences()
  slots = new Map<SourceKey, Slot>()
  sessionController = new AbortController()
  eventMap = new Map<string, TimelineEvent>()
  feed = { team: null as Page | null, campaign: null as Page | null }
  eventError = ''
  eventsDenied = false
  historyError = ''
  historyLoading = false
  campaignSnapshot: CampaignSnapshot | null = null
  teamCheckpoint: TeamCheckpoint | null = null
  olderCampaigns: Json[] = []
  olderCampaignError = ''
  olderCampaignLoading = false
  private campaignCursor?: string | null
  private campaignRequest?: AbortController
  private checkpointRequest?: AbortController
  stream = 'Polling retained sources'
  streamGap = false
  action = ''
  containment: { action: string; pending: number | null; state: string } | null = null
  notice = ''
  syncing = false
  private inFlight = new Map<string, Promise<void>>()
  private eventFlight?: Promise<void>
  private socket?: WebSocket
  private recheck?: number
  private reconnect?: number
  private attempt = 0
  private activeRefresh?: Promise<void>
  private suspended = false
  private eventFetchedAt = 0

  constructor(private onChange: () => void) {
    this.view = this.routeView()
  }

  slot(key: SourceKey): Slot { return this.slots.get(key) ?? { state: 'loading', value: null } }
  value(key: SourceKey): Json | null { return this.slot(key).value }
  sessions() { return rows(this.value('sessions')?.sessions) }
  session() { return this.sessions().find(item => item.session_id === this.sid) }
  campaigns() {
    const seen = new Set<unknown>()
    return [...rows(this.value('campaignHistory')?.campaigns), ...this.olderCampaigns].filter(item => {
      if (seen.has(item.id)) return false
      seen.add(item.id)
      return true
    })
  }
  get campaignBefore() {
    return this.campaignCursor === undefined ? text(this.value('campaignHistory')?.next_before) : this.campaignCursor
  }
  events(): TimelineEvent[] {
    return [...this.eventMap.values()].sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp) ||
      (a.source === b.source ? (b.sequence ?? 0) - (a.sequence ?? 0) : a.source.localeCompare(b.source)) || a.id.localeCompare(b.id))
  }
  get signal() { return this.sessionController.signal }

  routeView(): View {
    const view = new URLSearchParams(location.search).get('view')
    return views.find(key => key === view) ?? 'overview'
  }
  routeSession(): string { return new URLSearchParams(location.search).get('sid') || localStorage.getItem('current_session') || '' }
  href(view: View, sid = this.sid) {
    const params = new URLSearchParams()
    if (view !== 'overview') params.set('view', view)
    if (sid) params.set('sid', sid)
    return '/dashboard' + (params.size ? '?' + params.toString() : '')
  }

  async boot() {
    if (!token()) return signIn()
    await Promise.all([this.load('sessions'), this.load('profile')])
    this.selectFromList()
    this.navigate(this.routeView(), this.sid, 'replace')
    window.addEventListener('popstate', () => {
      const sid = this.routeSession()
      this.navigate(this.routeView(), this.sessions().some(row => row.session_id === sid) ? sid : this.sid, 'none')
    })
    window.addEventListener('storage', event => {
      if (event.key === 'pentestai_token' && !event.newValue) return signIn()
      if (event.key === 'current_session' && event.newValue !== this.sid &&
          this.sessions().some(row => row.session_id === event.newValue)) this.navigate(this.view, event.newValue ?? '', 'replace')
    })
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) this.stopSocket()
      else void this.refresh(false)
    })
    window.addEventListener('pagehide', () => { this.suspended = true; this.stopSocket() })
    window.addEventListener('pageshow', event => {
      if (event.persisted) { this.suspended = false; void this.refresh(false) }
    })
    window.addEventListener('online', () => { void this.refresh(true) })
    window.setInterval(() => {
      if (!document.hidden && !this.suspended) void this.refresh(false)
    }, freshFor)
  }

  selectFromList() {
    const wanted = this.routeSession()
    const list = this.sessions()
    if (!list.length) return
    const allowed = list.some(item => item.session_id === wanted)
    this.setSession(allowed ? wanted : text(list[0]?.session_id))
    if (wanted && !allowed) this.notice = 'The requested session is unavailable in your session list.'
  }

  navigate(view: View, sid = this.sid, historyMode: 'push' | 'replace' | 'none' = 'push') {
    const leavingWorkspace = this.view === 'workspace' && view !== 'workspace'
    const changed = this.view !== view || this.sid !== sid
    if (this.sid !== sid) this.setSession(sid)
    if (this.view !== view && !eventViews.has(view)) this.stopSocket()
    if (this.view === 'events' && view !== 'events') this.clearCampaignSnapshot()
    if (this.view === 'exploration-graph' && view !== 'exploration-graph') this.clearTeamCheckpoint()
    this.view = view
    const href = this.href(view)
    if (historyMode === 'push' && changed) history.pushState(null, '', href)
    if (historyMode === 'replace') history.replaceState(null, '', href)
    this.onChange()
    void this.refresh(leavingWorkspace)
  }

  private setSession(sid: string) {
    this.stopSocket()
    this.sessionController.abort()
    clearDiagnostics()
    this.sessionController = new AbortController()
    for (const key of this.inFlight.keys()) if (key.split(':')[1]) this.inFlight.delete(key)
    this.activeRefresh = undefined
    this.eventFlight = undefined
    this.eventFetchedAt = 0
    this.eventMap.clear()
    this.feed = { team: null, campaign: null }
    this.eventError = ''
    this.eventsDenied = false
    this.historyError = ''
    this.historyLoading = false
    this.clearCampaignSnapshot()
    this.clearTeamCheckpoint()
    this.olderCampaigns = []
    this.campaignCursor = undefined
    this.olderCampaignError = ''
    this.olderCampaignLoading = false
    this.streamGap = false
    this.attempt = 0
    this.action = ''
    this.containment = null
    this.notice = ''
    for (const key of this.slots.keys()) if (!sources[key].global) this.slots.delete(key)
    this.sid = sid
    if (sid) localStorage.setItem('current_session', sid)
  }

  load(key: SourceKey, force = false): Promise<void> {
    const sid = sources[key].global ? '' : this.sid
    if (!sid && !sources[key].global) return Promise.resolve()
    const signal = sid ? this.signal : undefined
    const flightKey = key + ':' + sid
    const existing = this.inFlight.get(flightKey)
    if (existing) return existing
    const previous = this.slot(key)
    if (!force && previous.at && Date.now() - previous.at < freshFor - 500) return Promise.resolve()
    const operation = read(key, sid, signal).then(value => {
      if (signal?.aborted) return
      this.slots.set(key, { state: value ? 'available' : 'not_started', value, at: Date.now() })
    }).catch(error => {
      if (signal?.aborted) return
      const denied = error instanceof ApiError && [401, 403, 404, 409].includes(error.status)
      if (denied && key === 'campaignHistory') {
        this.clearCampaignSnapshot()
        this.olderCampaigns = []
        this.campaignCursor = undefined
      }
      if (denied && key === 'team') this.clearTeamCheckpoint()
      this.slots.set(key, { state: denied ? 'denied' : previous.value ? 'stale' : 'unavailable',
        value: denied ? null : previous.value, at: previous.at, issue: error instanceof ApiError ? error.message : 'The data is unavailable.' })
    }).finally(() => {
      if (this.inFlight.get(flightKey) === operation) this.inFlight.delete(flightKey)
      if (!signal?.aborted) this.onChange()
    })
    this.inFlight.set(flightKey, operation)
    return operation
  }

  async refresh(force: boolean) {
    if (this.suspended) return
    if (this.activeRefresh && !force && !this.sid) return this.activeRefresh
    this.syncing = true
    this.onChange()
    const keys = viewReads[this.view]
    const operation = (async () => {
      if (force && !this.sid) { await this.load('sessions', true); this.selectFromList() }
      const selection = this.signal
      await Promise.all([...keys.map(key => this.load(key, force)),
        ...(this.sid && hasEventData(this.view) ? [this.loadEvents(force)] : [])])
      if (!selection.aborted) this.updateSocket()
    })()
    this.activeRefresh = operation
    try { await operation } finally {
      if (this.activeRefresh === operation) {
        this.activeRefresh = undefined
        this.syncing = false
        this.onChange()
      }
    }
  }

  loadEvents(force = false) {
    if (!this.sid) return Promise.resolve()
    if (this.eventFlight) return this.eventFlight
    if (!force && Date.now() - this.eventFetchedAt < 15000) return Promise.resolve()
    const sid = this.sid
    const signal = this.signal
    const path = '/api/mission/' + encodeURIComponent(sid) + '/events?'
    const operation = (async () => {
      for (let index = 0; index < maxForwardPages; index++) {
        const params = new URLSearchParams()
        const { team, campaign } = this.feed
        if (team?.cursor != null) params.set('team_after', String(team.cursor))
        if (campaign?.campaign_id && campaign.cursor != null) {
          params.set('campaign_id', campaign.campaign_id)
          params.set('campaign_after', String(campaign.cursor))
        }
        const value = await request(path + params, { signal })
        if (signal.aborted) return
        if (value?.schema_version !== 'aria.mission.events.v1') throw new ApiError(502, 'The event schema was invalid.')
        const pages = { team: eventPage(value.team, sid, 'team'), campaign: eventPage(value.campaign, sid, 'campaign') }
        for (const source of ['team', 'campaign'] as const) {
          const previous = this.feed[source]
          const page = pages[source]
          if (page.state === 'unavailable' && previous) {
            this.feed[source] = { ...previous, state: 'unavailable' }
            continue
          }
          const same = page.campaign_id === previous?.campaign_id
          if (page.state === 'available' && page.has_more &&
              (page.cursor === null || page.cursor <= (same ? previous?.cursor ?? 0 : 0))) {
            throw new ApiError(502, 'An event source did not advance its cursor. Refresh to retry.')
          }
          if (source === 'campaign' && ((!same && previous?.campaign_id) ||
              (page.gap && (page.cursor ?? 0) < (previous?.cursor ?? 0)))) {
            for (const [id, record] of this.eventMap) if (record.source === 'campaign') this.eventMap.delete(id)
          }
          this.feed[source] = groupEvents(page, same || source === 'team' ? previous : null)
          for (const event of page.events) this.eventMap.set(source + ':' + (event.campaign_id ?? sid) + ':' + event.id, event)
        }
        this.eventsDenied = false
        if (!Object.values(pages).some(page => page.state === 'available' && page.has_more)) break
      }
      this.eventError = ''
      this.eventFetchedAt = Date.now()
    })().catch(error => {
      if (signal.aborted) return
      if (error instanceof ApiError && [401, 403, 404].includes(error.status)) {
        this.eventMap.clear()
        this.feed = { team: null, campaign: null }
        this.eventsDenied = true
        this.clearCampaignSnapshot()
        this.clearTeamCheckpoint()
      }
      this.eventError = error instanceof ApiError ? error.message : 'The event feed is unavailable.'
    }).finally(() => {
      if (this.eventFlight === operation) this.eventFlight = undefined
      if (!signal.aborted) {
        if (this.eventMap.size > maxEvents) {
          const retained = new Set(this.events().slice(0, maxEvents))
          for (const [id, record] of this.eventMap) if (!retained.has(record)) this.eventMap.delete(id)
        }
        this.onChange()
      }
    })
    this.eventFlight = operation
    return operation
  }

  private clearCampaignSnapshot() {
    this.campaignRequest?.abort()
    this.campaignRequest = undefined
    this.campaignSnapshot = null
  }

  private clearTeamCheckpoint() {
    this.checkpointRequest?.abort()
    this.checkpointRequest = undefined
    this.teamCheckpoint = null
  }

  async selectTeamCheckpoint(sequence: number | null) {
    this.clearTeamCheckpoint()
    if (sequence === null) { this.onChange(); return }
    const sid = this.sid
    const controller = new AbortController()
    const { signal } = controller
    this.checkpointRequest = controller
    this.teamCheckpoint = { sequence, state: 'loading' }
    this.onChange()
    try {
      const path = '/api/mission/' + encodeURIComponent(sid) + '/exploration/checkpoint?sequence=' + sequence
      const value = await request(path, { signal })
      if (signal.aborted) return
      const records = object(value?.records)
      if (value?.schema_version !== 'aria.mission.exploration-checkpoint.v1' || value.session_id !== sid ||
          value.sequence !== sequence || !records || ['tasks', 'evidence', 'knowledge', 'verification_findings',
            'research_hypotheses'].some(key => !Array.isArray(records[key]))) throw new Error('Invalid checkpoint')
      this.teamCheckpoint = { sequence, state: 'available', value }
    } catch (error) {
      if (signal.aborted) return
      const denied = error instanceof ApiError && [401, 403].includes(error.status)
      this.teamCheckpoint = { sequence, state: denied ? 'denied' : 'unavailable' }
    } finally {
      if (!signal.aborted) { this.checkpointRequest = undefined; this.onChange() }
    }
  }

  async selectCampaign(id: string) {
    this.clearCampaignSnapshot()
    if (!id) { this.onChange(); return }
    const sid = this.sid
    const controller = new AbortController()
    this.campaignRequest = controller
    const signal = controller.signal
    this.campaignSnapshot = { id, state: 'loading' }
    this.onChange()
    try {
      const value = await request(sources.campaignHistory.url(encodeURIComponent(sid)) + '/' + encodeURIComponent(id) + '/events', { signal })
      if (signal.aborted) return
      const page = eventPage(value, sid, 'campaign')
      if (page.state !== 'available' || page.campaign_id !== id || page.events.some(event => event.campaign_id !== id)) {
        throw new ApiError(502, 'The retained events did not match the selected campaign.')
      }
      this.campaignSnapshot = { id, state: 'available', page, at: Date.now() }
    } catch (error) {
      if (signal.aborted) return
      const denied = error instanceof ApiError && [401, 403, 404].includes(error.status)
      this.campaignSnapshot = { id, state: denied ? 'denied' : 'unavailable',
        issue: error instanceof Error ? error.message : 'Campaign records are unavailable.' }
    } finally {
      if (!signal.aborted) {
        this.campaignRequest = undefined
        this.onChange()
      }
    }
  }

  async loadOlderCampaigns() {
    const before = this.campaignBefore
    if (!before || this.olderCampaignLoading) return
    const sid = this.sid
    const signal = this.signal
    this.olderCampaignLoading = true
    this.olderCampaignError = ''
    this.onChange()
    try {
      const value = await request(sources.campaignHistory.url(encodeURIComponent(sid)) + '?before=' + encodeURIComponent(before), { signal })
      if (signal.aborted) return
      if (!value || value.session_id !== sid || !sources.campaignHistory.valid(value) || value.next_before === before) {
        throw new ApiError(502, 'The campaign history did not match the selected session.')
      }
      this.olderCampaigns = [...this.olderCampaigns, ...rows(value.campaigns)]
      this.campaignCursor = text(value.next_before) || null
    } catch (error) {
      if (!signal.aborted) this.olderCampaignError = error instanceof Error ? error.message : 'Campaign history is unavailable.'
    } finally {
      if (!signal.aborted) { this.olderCampaignLoading = false; this.onChange() }
    }
  }

  get canLoadOlder() { return !!this.feed.team?.has_older && !!this.feed.team.oldest && this.eventMap.size < maxEvents }

  async loadOlder() {
    if (!this.canLoadOlder || this.historyLoading) return
    const sid = this.sid
    const signal = this.signal
    const before = this.feed.team!.oldest!
    const params = new URLSearchParams({ team_before: String(before), limit: String(Math.min(100, maxEvents - this.eventMap.size)) })
    this.historyLoading = true
    this.historyError = ''
    this.onChange()
    try {
      const value = await request('/api/mission/' + encodeURIComponent(sid) + '/events?' + params, { signal })
      if (signal.aborted) return
      if (value?.schema_version !== 'aria.mission.events.v1') throw new ApiError(502, 'The event schema was invalid.')
      const page = eventPage(value.team, sid, 'team')
      const current = this.feed.team
      if (page.state !== 'available' || !current) throw new ApiError(503, 'The older team records are unavailable.')
      this.feed.team = { ...current, oldest: page.oldest ?? current.oldest, has_older: page.has_older, gap: current.gap || page.gap }
      for (const item of page.events) {
        if (this.eventMap.size >= maxEvents) break
        this.eventMap.set('team:' + (item.campaign_id ?? sid) + ':' + item.id, item)
      }
    } catch (error) {
      if (!signal.aborted) this.historyError = error instanceof ApiError ? error.message : 'Older records are unavailable.'
    } finally {
      if (!signal.aborted) { this.historyLoading = false; this.onChange() }
    }
  }

  updatePreferences(change: Partial<Preferences>) {
    this.preferences = { ...this.preferences, ...change }
    localStorage.setItem('aria.mission.preferences', JSON.stringify(this.preferences))
    this.onChange()
  }

  async create(name: string, target: string) {
    if (this.action) return
    this.action = 'Creating session'
    this.notice = ''
    this.onChange()
    try {
      const created = await request('/api/session/new', { method: 'POST', data: { name, target } })
      const sid = text(created?.session_id)
      if (!sid) throw new ApiError(502, 'The API did not confirm a session ID.')
      await this.load('sessions', true)
      if (!this.sessions().some(item => item.session_id === sid)) {
        this.notice = 'The server created a session, but the session index could not confirm it. Refresh Sessions before retrying.'
        return
      }
      this.navigate('overview', sid)
      this.notice = 'Session created.'
    } catch (error) {
      this.notice = error instanceof ApiError ? error.message : 'Session creation could not be confirmed.'
    } finally {
      this.action = ''
      this.onChange()
    }
  }

  async control(action: 'pause' | 'resume' | 'cancel' | 'stop' | 'reject', id?: string) {
    if (this.action || !this.sid) return
    const signal = this.signal
    const sid = encodeURIComponent(this.sid)
    const route = action === 'reject' ? 'autonomous/approve' : action === 'stop' ? 'autonomous/stop' : 'campaign/' + action
    this.action = 'Submitting ' + action + ' request'
    this.notice = ''
    this.onChange()
    try {
      const response = await request('/api/pentest/' + sid + '/' + route, { method: 'POST', signal,
        data: action === 'reject' ? { action_id: id, decision: 'reject' } : undefined })
      const received = action === 'reject' ? response?.status === 'recorded' && response.decision === 'reject' :
        action === 'stop' ? ['stopped', 'cancellation_pending'].includes(text(response?.status)) :
          (action === 'resume' ? ['scheduled', 'starting', 'running'] :
            ['pausing', 'paused', 'cancelling', 'cancelled', 'failed', 'completed', 'stopped']).includes(text(response?.state))
      if (!received) throw new ApiError(502, 'The server did not confirm the operator request.')
      if (!signal.aborted) {
        const pending = Number.isSafeInteger(response?.pending) && Number(response?.pending) >= 0 ? Number(response?.pending) : null
        this.containment = { action, pending, state: text(response?.status, text(response?.state)) }
        this.notice = 'Request acknowledged. The records below show the current server state.'
      }
    } catch (error) {
      if (!signal.aborted) this.notice = error instanceof ApiError ? error.message : 'The request could not be confirmed.'
    } finally {
      if (!signal.aborted) {
        this.action = ''
        // A read begun before this mutation may still be in flight. Let it settle
        // before requesting the post-action records instead of deduplicating into it.
        await Promise.all(['run', 'campaign', 'operations'].map(key => this.inFlight.get(key + ':' + this.sid)))
        if (!signal.aborted) await this.refresh(true)
      }
    }
  }

  async catalogEvidence(sourceKind: 'chat' | 'worker', sourceId: string, requestId: string): Promise<string> {
    const sid = this.sid
    if (!sid || !sourceId) throw new ApiError(409, 'Select an engagement and an evidence source.')
    const response = await request('/api/team/' + encodeURIComponent(sid) + '/evidence', {
      method: 'POST', signal: this.signal,
      data: { request_id: requestId, source_kind: sourceKind, source_id: sourceId }
    })
    const entry = object(response?.data)
    const id = text(entry?.id)
    if (!id || entry?.source_kind !== sourceKind || entry.source_id !== sourceId || entry.session_id !== sid) {
      throw new ApiError(502, 'The API did not confirm the evidence record.')
    }
    return id
  }

  async queueSavedReview(evidenceIds: string[], objective: string, requestId: string): Promise<string> {
    const sid = this.sid
    const signal = this.signal
    const ids = [...new Set(evidenceIds)]
    if (!ids.length || ids.length > maxReviewEvidence) throw new ApiError(422, 'Select between one and 100 evidence records.')
    const scoped = new Set(rows(this.value('team')?.evidence)
      .filter(item => item.session_id === sid && text(item.owner_id)).map(item => item.id))
    if (!sid || this.slot('team').state !== 'available' || ids.some(id => !scoped.has(id))) {
      throw new ApiError(409, 'Refresh the evidence catalog before queuing a review.')
    }
    const comparison = ids.length > 1
    const response = await request('/api/team/' + encodeURIComponent(sid) + '/tasks', {
      method: 'POST', signal, data: { request_id: requestId, task: {
        owner_role: 'correlation', internal_review: 'analyze', objective,
        evidence_inputs: ids, expected_output: 'Evidence-linked interpretation',
        ...(comparison ? { require_all_evidence: true } : {}),
        completion_criteria: ['Cite the assigned evidence and explain uncertainty'],
        budget: { max_attempts: 1, max_model_calls: 1 }
      } }
    })
    const id = text(response?.entity_id)
    const task = object(response?.data)
    const confirmed = strings(task?.evidence_inputs)
    if (!id || task?.id !== id || task.session_id !== sid || task.internal_review !== 'analyze' ||
        confirmed.length !== ids.length || ids.some((item, index) => item !== confirmed[index]) ||
        (comparison && task.require_all_evidence !== true)) {
      throw new ApiError(502, 'The API did not confirm the queued task.')
    }
    if (!signal.aborted) {
      await this.inFlight.get('team:' + sid)
      if (!signal.aborted) await this.load('team', true)
    }
    return id
  }

  async transitionSavedReview(id: string, state: 'cancelled' | 'queued', requestId: string): Promise<Json> {
    const sid = this.sid
    const signal = this.signal
    await this.inFlight.get('team:' + sid)
    if (!sid || signal.aborted) throw new ApiError(409, 'The selected engagement changed.')
    await this.load('team', true)
    const task = rows(this.value('team')?.tasks).find(item => item.id === id)
    const revision = task?.revision
    if (signal.aborted || this.slot('team').state !== 'available' || !task?.internal_review ||
        typeof revision !== 'number' || !Number.isSafeInteger(revision) || revision < 1) {
      throw new ApiError(409, 'The current task revision could not be confirmed.')
    }
    if (task.state === state) return task
    const allowed = state === 'queued' ? ['blocked'] : ['queued', 'running', 'blocked']
    if (!allowed.includes(text(task.state))) {
      throw new ApiError(409, 'The task is now ' + text(task.state, 'in an unknown state') + '. Refresh Tasks.')
    }
    const response = await request('/api/team/' + encodeURIComponent(sid) + '/tasks/' + encodeURIComponent(id) + '/transition', {
      method: 'POST', signal, data: {request_id: requestId, expected_revision: revision,
        state, reason: state === 'queued' ? 'Owner requeued this saved-evidence review in Mission Control.' :
          'Owner cancelled this saved-evidence review in Mission Control.'}
    })
    const saved = object(response?.data)
    if (!saved || saved.id !== id || saved.session_id !== sid || saved.state !== state) {
      throw new ApiError(502, 'The API did not confirm the task transition.')
    }
    if (!signal.aborted) {
      await this.inFlight.get('team:' + sid)
      if (!signal.aborted) await this.load('team', true)
    }
    return saved
  }

  async runSavedReview(id: string): Promise<Json | null> {
    if (this.action || !this.sid) return null
    const signal = this.signal
    await this.runSavedReviews([id])
    return !signal.aborted && this.slot('team').state === 'available' ?
      rows(this.value('team')?.tasks).find(task => task.id === id) ?? null : null
  }

  async runSavedReviews(ids: string[]): Promise<Json | null> {
    if (this.action || !this.sid || !ids.length || ids.length > maxSavedReviews) return null
    const sid = this.sid
    const signal = this.signal
    const queued = rows(this.value('team')?.tasks).filter(task => queuedSavedReview(task, sid))
    if (this.slot('team').state !== 'available' || ids.some(id => !queued.some(task => task.id === id))) {
      this.notice = 'Refresh Tasks to confirm the selected reviews are queued.'
      this.onChange()
      return null
    }
    if (this.slot('budget').state !== 'available' || this.value('budget')?.budget_approved !== true) {
      this.notice = 'Confirm the engagement model budget before starting saved reviews.'
      this.onChange()
      return null
    }
    const single = ids.length === 1
    const path = '/api/team/' + encodeURIComponent(sid) + '/tasks/'
    this.action = single ? 'Running saved-evidence review' : 'Running selected saved-evidence reviews'
    this.notice = ''
    this.onChange()
    let outcome: Json | null = null
    try {
      const result = await request(path + (single ? encodeURIComponent(ids[0]) + '/run' : 'run-internal'), {
        method: 'POST', data: single ? { request_id: crypto.randomUUID() } : { task_ids: ids },
        signal, timeoutMs: 210000
      })
      const states = object(result?.states)
      if (!states || ids.some(id => !text(states[id]))) {
        throw new ApiError(502, 'The API did not confirm the saved review states.')
      }
      outcome = result
      const count = Object.values(states).filter(state => state === 'analyzed').length
      this.notice = single
        ? states[ids[0]] === 'analyzed' ? 'Saved review collected.' :
          'Saved review state · ' + text(states[ids[0]]) + '. Inspect the recorded result or task history for details.'
        : count + ' of ' + Object.keys(states).length + ' saved reviews analyzed.'
    } catch (error) {
      if (!signal.aborted) this.notice = error instanceof ApiError && error.status !== 0 ? error.message :
        'The request outcome could not be confirmed. Check the task ledger before retrying.'
    } finally {
      if (!signal.aborted) {
        await Promise.all(['team', 'budget'].map(key => this.inFlight.get(key + ':' + sid)))
        if (!signal.aborted) {
          await Promise.all([this.load('team', true), this.load('budget', true)])
          if (!signal.aborted) {
            this.action = ''
            this.onChange()
          }
        }
      }
    }
    return signal.aborted ? null : outcome
  }

  private stopSocket() {
    if (this.reconnect) window.clearTimeout(this.reconnect)
    if (this.recheck) window.clearTimeout(this.recheck)
    this.reconnect = undefined
    this.recheck = undefined
    const socket = this.socket
    this.socket = undefined
    socket?.close()
    this.stream = 'Polling retained sources'
  }

  private updateSocket() {
    if (!eventViews.has(this.view) || !this.sid || document.hidden || this.suspended) return
    if (this.value('run')?.active !== true || this.slot('run').state !== 'available') {
      this.stopSocket()
      return
    }
    if (this.socket || this.reconnect) return
    const sid = this.sid
    const credentials = token()
    if (!credentials) return
    const url = new URL('/api/pentest/ws/' + encodeURIComponent(sid) + '/auto', location.origin)
    url.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:'
    const socket = new WebSocket(url)
    this.socket = socket
    this.stream = 'Connecting to run stream'
    this.onChange()
    let received = false
    let highWater = 0
    let run = ''
    socket.onopen = () => { if (this.socket === socket) socket.send(JSON.stringify({ token: credentials })) }
    socket.onmessage = event => {
      if (this.socket !== socket || sid !== this.sid || typeof event.data !== 'string') return
      let record
      try { record = object(JSON.parse(event.data)) } catch { return }
      if (!record || record.session_id !== sid || !text(record.run_id)) return
      const current = text(record.run_id)
      if (run && run !== current) highWater = 0
      run = current
      const sequence = Number.isSafeInteger(record.event_sequence) ? Number(record.event_sequence) : 0
      if (sequence && sequence <= highWater && record.stream_gap !== true) return
      if (record.stream_gap === true || highWater > 0 && sequence > highWater + 1) this.streamGap = true
      highWater = Math.max(highWater, sequence)
      received = true
      this.stream = 'Run stream connected'
      this.attempt = 0
      // Stream payloads are invalidation signals. The owner-scoped API supplies retained details.
      if (this.recheck) return
      this.recheck = window.setTimeout(() => {
        this.recheck = undefined
        if (this.socket === socket) void Promise.all([this.loadEvents(true), this.load('run', true), this.load('campaign', true)])
      }, 450)
      this.onChange()
    }
    socket.onclose = event => {
      if (this.socket !== socket) return
      this.socket = undefined
      if (event.code === 4401) return signIn()
      if (event.code === 4403) { this.stream = 'Run stream access denied'; this.onChange(); return }
      this.stream = 'Run stream reconnecting'
      this.onChange()
      const delay = Math.min(20000, (received ? 750 : 750 * 2 ** Math.min(this.attempt++, 5)))
      this.reconnect = window.setTimeout(() => {
        this.reconnect = undefined
        void this.refresh(true)
      }, delay)
    }
  }
}
