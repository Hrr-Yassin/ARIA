import './mission.css'
import { request, signIn, text } from './api'
import { badge, button, el, empty, icon, link } from './dom'
import { labels, overview, type Detail, type Go, type Lazy } from './panels'
import { MissionStore, views, type View } from './store'
import { agents, analytics, defaultFilters, events, infrastructure, investigation, operations, sessions, settings } from './views'
import { workspace, syncWorkspace } from './workspace'
import { profilePanel } from './profiles'

const root = document.querySelector<HTMLElement>('#app')!
const content = el('main', 'content')
content.id = 'mission-content'
content.tabIndex = -1
const title = el('h1')
title.id = 'mission-title'
title.tabIndex = -1
const subtitle = el('p', 'page-description')
const appNotice = el('div', 'notice')
appNotice.setAttribute('role', 'status')
const contents = el('div', 'view-content')
const sessionPicker = el('select', 'session-picker')
sessionPicker.id = 'session-picker'
sessionPicker.setAttribute('aria-label', 'Current session')
const nav = el('nav', 'navigation')
nav.id = 'primary-navigation'
nav.setAttribute('aria-label', 'Mission Control sections')
const operatorName = el('span', 'operator-name', 'Operator')
const avatar = el('span', 'operator-avatar', 'A')
avatar.setAttribute('aria-hidden', 'true')
const connection = el('span', 'connection')
connection.setAttribute('role', 'status')
const panelTitle = el('h2')
panelTitle.id = 'inspector-title'
const inspector = el('dialog', 'inspector')
inspector.id = 'inspector'
inspector.setAttribute('aria-labelledby', panelTitle.id)
const inspectorBody = el('div', 'inspector-body')
const closeInspector = button('Close inspector', () => inspector.close(), 'button small')
inspector.append(el('div', 'inspector-heading', panelTitle, closeInspector), inspectorBody)
let previousFocus: HTMLElement | SVGElement | null = null
inspector.addEventListener('close', () => {
  inspectorBody.replaceChildren()
  if (previousFocus?.isConnected) previousFocus.focus()
})
const detail: Detail = (label, nodes, compact = false) => {
  if (!inspector.open) previousFocus = document.activeElement as HTMLElement | SVGElement | null
  panelTitle.textContent = label
  inspector.classList.toggle('compact-dialog', compact)
  inspectorBody.replaceChildren(...nodes)
  inspectorBody.scrollTop = 0
  if (!inspector.open) inspector.showModal()
}

let scheduled = 0
const queueRender = () => { if (!scheduled) scheduled = requestAnimationFrame(render) }
const store = new MissionStore(queueRender)
const refresh = button('Refresh', () => void store.refresh(true), 'button', 'refresh')
refresh.id = 'refresh-mission'
const mode = button('Simple mode', () => store.updatePreferences({
  mode: store.preferences.mode === 'simple' ? 'advanced' : 'simple'
}), 'button mode-button')
mode.id = 'display-mode'
const logout = button('Sign out', async () => {
  logout.disabled = true
  try { await request('/api/logout', { method: 'POST' }); signIn() }
  catch (error) { store.notice = error instanceof Error ? error.message : 'Sign-out could not be confirmed.'; queueRender() }
  finally { logout.disabled = false }
}, 'signout', 'signout')

const go: Go = view => {
  store.navigate(view)
  requestAnimationFrame(() => { window.scrollTo(0, 0); title.focus({ preventScroll: true }) })
}
const links = new Map<View, HTMLAnchorElement>()
for (const view of views) {
  const anchor = link(view === 'overview' ? 'Overview' : labels[view], store.href(view), 'nav-link')
  anchor.prepend(icon(view))
  anchor.addEventListener('click', event => {
    if (event.metaKey || event.ctrlKey || event.altKey || event.shiftKey) return
    event.preventDefault()
    go(view)
  })
  links.set(view, anchor)
  nav.append(anchor)
}
const brand = link('', '/dashboard', 'brand')
brand.setAttribute('aria-label', 'ARIA Mission Control home')
brand.append(el('span', 'brand-mark', icon('shield')), el('span', '', el('strong', '', 'ARIA'),
  el('small', '', 'MISSION CONTROL')))
brand.addEventListener('click', event => {
  if (event.metaKey || event.ctrlKey || event.altKey || event.shiftKey) return
  event.preventDefault()
  go('overview')
})
const workLink = link('Research workspace', '/', 'work-link')
workLink.addEventListener('click', event => {
  if (event.metaKey || event.ctrlKey || event.altKey || event.shiftKey) return
  event.preventDefault()
  go('workspace')
})
const sidebar = el('aside', 'sidebar', brand, nav, el('div', 'sidebar-bottom', workLink,
  el('div', 'operator', avatar, el('div', '', operatorName, el('small', '', 'Signed-in operator'))), logout))
const topbar = el('header', 'topbar', el('div', 'topbar-context', el('label', 'session-control',
  el('span', '', 'Session'), sessionPicker)), el('div', 'topbar-actions', connection, mode))
content.append(el('div', 'page-head', el('div', '', title, subtitle), refresh), appNotice, contents)
root.append(el('div', 'shell', sidebar, el('div', 'main-shell', topbar, content)), inspector)
sessionPicker.addEventListener('change', () => { if (sessionPicker.value) store.navigate(store.view, sessionPicker.value) })

const subtitles: Record<View, string> = {
  overview: 'Mission status, resource limits, and retained activity',
  workspace: 'Research chat, proposal review, and existing operational settings',
  sessions: 'Find and organize engagement records',
  agents: 'Recorded specialist assignments, dependencies, and evidence',
  operations: 'Worker receipts, pending review, and containment',
  events: 'Search and replay records from retained event sources',
  investigation: 'Review evidence, findings, topology, and reports',
  analytics: 'Model reservations, measured usage, and recorded outcomes',
  infrastructure: 'Service readiness and advertised worker capabilities',
  settings: 'Display preferences and configuration summaries'
}
const media = matchMedia('(prefers-color-scheme: dark)')
media.addEventListener('change', queueRender)
const contentObserver = new IntersectionObserver(entries => {
  for (const entry of entries) {
    if (!entry.isIntersecting) continue
    contentObserver.unobserve(entry.target)
    const mount = mounts.get(entry.target as HTMLElement)
    mounts.delete(entry.target as HTMLElement)
    if (!mount || !entry.target.isConnected) continue
    void mount().then(dispose => {
      if (!dispose) return
      if (entry.target.isConnected) disposers.add(dispose)
      else dispose()
    }).catch(() => {
      if (entry.target.isConnected) entry.target.replaceChildren(empty('Visualization unavailable. Source records remain available in the list.'))
    })
  }
}, { rootMargin: '100px' })
const mounts = new Map<HTMLElement, () => Promise<(() => void) | undefined>>()
const disposers = new Set<() => void>()
const lazy: Lazy = (node, mount) => { mounts.set(node, mount); contentObserver.observe(node) }
function clearVisuals() {
  contentObserver.disconnect()
  mounts.clear()
  for (const dispose of disposers) dispose()
  disposers.clear()
}

let filters = defaultFilters()
let previousSession = ''
let previousView: View | null = null
let previousContent = ''
let previousOptions = ''
let previousState = ''
const pageKeysWithoutSession = new Set<View>(['sessions', 'infrastructure', 'settings'])

function render() {
  scheduled = 0
  const p = store.preferences
  const theme = p.theme === 'system' ? (media.matches ? 'dark' : 'light') : p.theme
  const doc = document.documentElement
  Object.assign(doc.dataset, { theme, accent: p.accent, density: p.density, mode: p.mode, motion: String(p.motion) })
  doc.style.setProperty('--inspector-width', p.inspectorWidth + 'px')
  if (previousSession !== store.sid) {
    const { sessionQuery, sessionState, sessionDate, renderer } = filters
    filters = { ...defaultFilters(), sessionQuery, sessionState, sessionDate, renderer }
  }
  if ((previousSession !== store.sid || previousView !== store.view) && inspector.open) inspector.close()
  const current = store.view
  const archiveChanged = !!filters.replay?.campaignId && filters.replay.campaignId !== store.campaignSnapshot?.id
  const replayAccessLost = store.eventsDenied || (!filters.replay?.campaignId && store.slot('operations').state === 'denied')
  if (filters.replay && (current !== 'events' || archiveChanged || replayAccessLost)) filters.replay = null
  if (current === 'events' && (archiveChanged || replayAccessLost) && inspector.open) inspector.close()
  title.textContent = labels[current]
  subtitle.textContent = subtitles[current]
  document.title = 'ARIA · ' + labels[current]
  appNotice.textContent = store.action || store.notice
  appNotice.hidden = !appNotice.textContent
  mode.textContent = p.mode === 'simple' ? 'Simple mode' : 'Advanced mode'
  mode.setAttribute('aria-pressed', String(p.mode === 'advanced'))
  refresh.disabled = store.syncing
  refresh.classList.toggle('is-refreshing', store.syncing)
  const readiness = store.slot('sessions').state
  const state = store.syncing ? 'loading' : readiness === 'available' ? 'recorded' : readiness
  const connectionLabel = store.syncing || readiness === 'loading' ? 'Syncing' :
    readiness === 'available' ? (store.sid ? 'Session linked' : 'No session selected') : 'Session index ' + readiness
  if (connection.textContent !== connectionLabel) connection.replaceChildren(badge(state, connectionLabel))
  const profile = store.value('profile')
  const name = text(profile?.username, 'Operator')
  operatorName.textContent = name
  avatar.textContent = name.slice(0, 1).toUpperCase()
  const options = store.sessions()
  const signature = JSON.stringify(options.map(option => [option.session_id, option.name, option.target]))
  if (signature !== previousOptions) {
    const items = options.map(record => {
      const option = el('option', '', text(record.name, text(record.target, 'Unnamed session')))
      option.value = text(record.session_id)
      return option
    })
    if (!items.length) items.push(el('option', '', readiness === 'loading' ? 'Loading sessions…' : 'No session selected'))
    sessionPicker.replaceChildren(...items)
    previousOptions = signature
  }
  sessionPicker.disabled = !options.length
  if (sessionPicker.value !== store.sid) sessionPicker.value = store.sid
  for (const [view, anchor] of links) {
    anchor.href = store.href(view)
    if (view === current) anchor.setAttribute('aria-current', 'page')
    else anchor.removeAttribute('aria-current')
  }
  workLink.href = store.href('workspace')
  document.body.dataset.missionReady = String(!store.syncing && readiness !== 'loading')
  // Keep the loaded document and unsent draft through shell refreshes, theme
  // updates and mode changes. Session and view changes dispose it normally.
  if (current === 'workspace' && previousSession === store.sid && previousView === current) {
    const frame = contents.querySelector<HTMLIFrameElement>('.workspace-frame')
    if (frame) syncWorkspace(frame, store)
    return
  }
  const { replay, ...visibleFilters } = filters
  const evidenceKey = replay ? [replay.capturedAt, replay.campaignId, replay.records.length] : [store.action, store.eventError,
    store.stream, store.streamGap, store.events(), store.feed.team?.state, store.feed.team?.gap, store.feed.campaign?.state,
    store.feed.campaign?.gap, store.feed.team?.has_more, store.feed.campaign?.has_more,
    store.canLoadOlder, store.historyLoading, store.historyError,
    [...store.slots].map(([name, slot]) => [name, slot.state, slot.value, slot.issue, slot.state === 'stale' ? slot.at : null]),
    current === 'events' ? [store.campaignSnapshot, store.olderCampaigns, store.campaignBefore,
      store.olderCampaignLoading, store.olderCampaignError] : null]
  const renderKey = JSON.stringify([current, store.sid, p, theme, visibleFilters, evidenceKey])
  if (renderKey === previousContent) return
  previousContent = renderKey
  const oldScroll = previousSession === store.sid && previousView === current ?
    contents.querySelector<HTMLElement>('[data-scroll="timeline"]')?.scrollTop : 0
  previousSession = store.sid
  previousView = current
  const focused = document.activeElement
  const focus = focused instanceof HTMLElement ? focused.dataset.focus : undefined
  const selection = focused instanceof HTMLInputElement && focused.type === 'search'
    ? { start: focused.selectionStart, end: focused.selectionEnd, direction: focused.selectionDirection }
    : null
  clearVisuals()

  let nodes: HTMLElement[]
  if (!store.sid && !pageKeysWithoutSession.has(current)) {
    const waiting = readiness === 'loading'
    nodes = [el('section', 'card zero-view', el('h2', '', waiting ? 'Loading sessions…' : 'Select an engagement'),
      empty(waiting ? 'Retrieving the session index.' : 'Choose a session to view mission records.'),
      waiting ? null : button('Open Sessions', () => go('sessions'), 'button primary'))]
  } else if (current === 'overview') nodes = overview(store, go, detail)
  else if (current === 'workspace') nodes = workspace(store)
  else if (current === 'sessions') nodes = sessions(store, detail, filters, queueRender)
  else if (current === 'agents') nodes = agents(store, detail, go, lazy, filters, queueRender)
  else if (current === 'operations') nodes = operations(store, detail)
  else if (current === 'events') nodes = events(store, detail, lazy, filters, queueRender)
  else if (current === 'investigation') nodes = investigation(store, detail, lazy)
  else if (current === 'analytics') nodes = analytics(store, detail, lazy, filters, queueRender)
  else if (current === 'infrastructure') nodes = infrastructure(store, detail, lazy)
  else nodes = [...settings(store), profilePanel(store, queueRender)]
  contents.replaceChildren(...nodes)
  for (const panel of contents.querySelectorAll<HTMLElement>('section.card')) {
    const heading = panel.querySelector<HTMLElement>(':scope > .card-heading')
    const label = heading?.querySelector('h2')?.textContent
    if (!heading || !label || ['Execution state and containment', 'Pending proposals', 'Stored web replay state'].includes(label)) continue
    const key = current + ':' + label
    const collapsed = p.collapsedPanels.includes(key)
    panel.classList.toggle('is-collapsed', collapsed)
    const toggle = button((collapsed ? 'Expand ' : 'Collapse ') + label, () => {
      store.updatePreferences({ collapsedPanels: collapsed ? p.collapsedPanels.filter(item => item !== key) : [...p.collapsedPanels, key] })
    }, 'button small panel-toggle')
    toggle.setAttribute('aria-expanded', String(!collapsed))
    toggle.dataset.focus = 'panel-' + key
    heading.append(toggle)
  }
  if (oldScroll) {
    const viewport = contents.querySelector<HTMLElement>('[data-scroll="timeline"]')
    if (viewport) viewport.scrollTop = oldScroll
  }
  if (focus) {
    const replacement = contents.querySelector<HTMLElement>('[data-focus="' + CSS.escape(focus) + '"]')
    replacement?.focus({ preventScroll: true })
    if (replacement instanceof HTMLInputElement && replacement.type === 'search' && selection) {
      replacement.setSelectionRange(selection.start, selection.end, selection.direction ?? undefined)
    }
  }
  const campaignState = String(store.value('campaign')?.state ?? '')
  const identity = store.sid + ':' + campaignState
  if (p.motion && !matchMedia('(prefers-reduced-motion: reduce)').matches && current === 'overview' &&
      campaignState && previousState.startsWith(store.sid + ':') && previousState !== identity) {
    contents.querySelector('.hero [data-state]')?.animate(
      [{ transform: 'scale(1.05)', opacity: 0.65 }, { transform: 'scale(1)', opacity: 1 }],
      { duration: 300, easing: 'ease-out' })
  }
  previousState = identity
}

queueRender()
void store.boot()
