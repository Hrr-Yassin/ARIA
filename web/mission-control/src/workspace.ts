import { signIn } from './api'
import { button, el, link } from './dom'
import type { MissionStore } from './store'

/** Reuse the established chat, review and settings handlers inside the session
 * shell. This document is loaded only while Workspace is open; removing it
 * releases its polling timers and sockets through the browser document lifecycle.
 */
export function workspace(store: MissionStore) {
  const root = el('section', 'workspace-view')
  const frame = el('iframe', 'workspace-frame')
  frame.title = 'Research workspace for the selected session'
  frame.src = '/chat/' + encodeURIComponent(store.sid)
  frame.dataset.session = store.sid
  const state = el('p', 'subtle', 'Loading research workspace…')
  state.setAttribute('role', 'status')
  frame.addEventListener('load', () => {
    if (!frame.isConnected) return
    const doc = frame.contentDocument
    if (!doc || !doc.querySelector('#workspace-main')) {
      if (frame.contentWindow?.location.pathname.startsWith('/login')) return signIn()
      state.textContent = 'Workspace unavailable. Reload to retry.'
      return
    }
    doc.documentElement.dataset.missionEmbedded = 'true'
    const style = doc.createElement('style')
    style.textContent = `
      html[data-mission-embedded] body { --header-h: 60px; }
      html[data-mission-embedded] :is(.app-header .brand, .session-meta, #sidebar, #overview-link) { display: none; }
      html[data-mission-embedded] .app-header { display: flex; justify-content: flex-end; background: var(--aria-surface); padding: 8px 12px; }
      html[data-mission-embedded] .header-actions { width: auto; }
      html[data-mission-embedded] .app-main { grid-template-columns: minmax(0, 1fr) minmax(240px, 32%); }
      html[data-mission-embedded][data-motion=false] *, html[data-mission-embedded][data-motion=false] *::before,
      html[data-mission-embedded][data-motion=false] *::after { animation: none !important; transition: none !important; }
      @media(max-width: 700px) {
        html[data-mission-embedded] .app-main { display: flex; flex-direction: column; overflow: auto; }
        html[data-mission-embedded] .chat-panel { flex: 1 0 480px; min-width: 0; }
        html[data-mission-embedded] .intel-panel { display: block; flex: 0 0 300px; width: 100%; }
        html[data-mission-embedded] .input-actions { flex-wrap: wrap; }
      }`
    doc.head.append(style)
    syncWorkspace(frame, store)
    state.textContent = 'Research workspace uses the selected session and existing authorization controls.'
  })
  root.append(el('div', 'toolbar', state, button('Reload workspace', () => {
    frame.src = '/chat/' + encodeURIComponent(store.sid)
  }, 'button small'), link('Open standalone workspace', frame.src, 'text-link')), frame)
  return [root]
}

export function syncWorkspace(frame: HTMLIFrameElement, store: MissionStore) {
  const doc = frame.contentDocument
  if (!doc?.documentElement?.dataset.missionEmbedded) return
  const parent = document.documentElement
  const palette = getComputedStyle(parent)
  const variables: Record<string, string> = {
    '--aria-bg': '--base', '--aria-surface': '--panel', '--aria-raised': '--panel-2', '--aria-hover': '--panel-2',
    '--aria-border': '--line', '--aria-border-strong': '--dim', '--aria-text': '--ink', '--aria-secondary': '--muted',
    '--aria-muted': '--dim', '--aria-primary': '--accent', '--aria-primary-fill': '--accent-solid',
    '--aria-on-primary': '--accent-ink', '--aria-success': '--good', '--aria-warning': '--warn', '--aria-danger': '--bad'
  }
  for (const [target, source] of Object.entries(variables)) doc.documentElement.style.setProperty(target, palette.getPropertyValue(source))
  doc.documentElement.style.colorScheme = parent.dataset.theme ?? 'dark'
  doc.documentElement.dataset.theme = parent.dataset.theme
  doc.documentElement.dataset.motion = String(store.preferences.motion)
}
