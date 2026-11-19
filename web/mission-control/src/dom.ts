import { number, text, type Slot } from './api'

type Child = Node | string | null | undefined | false
export function el<K extends keyof HTMLElementTagNameMap>(tag: K, className = '', ...children: Child[]): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag)
  node.className = className
  node.append(...children.filter((child): child is Node | string => Boolean(child)))
  return node
}
export const human = (value: unknown, fallback = 'Unknown') =>
  text(value, fallback).replace(/[_-]+/g, ' ').replace(/^./, c => c.toUpperCase())
export const count = (value: unknown, missing = 'Unknown') => number(value)?.toLocaleString() ?? missing
export const money = (value: unknown) => {
  const measured = number(value)
  return measured === null ? 'Unknown' : '$' + (measured / 1e6).toLocaleString(undefined, { maximumFractionDigits: 6, minimumFractionDigits: 2 })
}
export function date(value: unknown) {
  if (typeof value !== 'string' && typeof value !== 'number') return 'Not recorded'
  const time = new Date(value)
  return Number.isFinite(time.getTime()) ? new Intl.DateTimeFormat(undefined, {
    month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', second: '2-digit', timeZoneName: 'short'
  }).format(time) : 'Unknown'
}

const paths: Record<string, string> = {
  overview: 'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
  sessions: 'M4 7h16M4 12h16M4 17h11M3 3h18v18H3z',
  agents: 'M12 7V4m0 3L5 13m7-6 7 6m-14 4h14M2 13h6v7H2zM16 13h6v7h-6zM9 2h6v6H9z',
  operations: 'M4 5h16v14H4zM7 9l3 3-3 3m6 0h4',
  events: 'M4 12h3l3-7 4 14 3-7h3',
  investigation: 'm19 19-4-4m2-4a6 6 0 1 1-12 0 6 6 0 0 1 12 0Z',
  analytics: 'M4 4v16h16M8 16v-4m4 4V8m4 8V5',
  infrastructure: 'M4 4h16v6H4zM4 14h16v6H4zM7 7h.1M7 17h.1',
  settings: 'M4 6h16M4 12h16M4 18h16M9 3v6m6 0v6m-6 0v6',
  refresh: 'M20 7v5h-5M4 17v-5h5M5 8a8 8 0 0 1 13-2l2 6M4 12l2 6a8 8 0 0 0 13-2',
  chevron: 'm9 6 6 6-6 6', close: 'm6 6 12 12M18 6 6 18', plus: 'M12 5v14M5 12h14',
  clock: 'M12 7v5l3 2M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z',
  shield: 'M12 2 4 5v6c0 5 3.5 8.5 8 11 4.5-2.5 8-6 8-11V5zM8 12l3 3 5-6',
  warning: 'M12 3 2 20h20zM12 9v4m0 3h.01',
  signout: 'M13 4H4v16h9m-3-8h11m-4-4 4 4-4 4', menu: 'M4 6h16M4 12h16M4 18h16'
}
export function icon(key: string): SVGSVGElement {
  const node = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
  node.setAttribute('viewBox', '0 0 24 24')
  node.setAttribute('aria-hidden', 'true')
  node.setAttribute('fill', 'none')
  node.setAttribute('stroke', 'currentColor')
  node.setAttribute('stroke-width', '1.65')
  node.setAttribute('stroke-linecap', 'round')
  node.setAttribute('stroke-linejoin', 'round')
  const path = document.createElementNS(node.namespaceURI, 'path')
  path.setAttribute('d', paths[key] ?? paths.overview)
  node.append(path)
  return node
}
export function button(label: string, run: () => void, className = 'button', glyph?: string) {
  const node = el('button', className, glyph ? icon(glyph) : null, label)
  node.type = 'button'
  node.addEventListener('click', run)
  return node
}
export function link(label: string, href: string, className = 'text-link') {
  const node = el('a', className, label)
  node.href = href
  return node
}
export function badge(state: unknown, label = human(state)) {
  const node = el('span', 'badge', el('i', ''), label)
  node.dataset.state = text(state, 'unknown').toLowerCase()
  return node
}
export function card(title: string, body: Node[], options: { action?: Node; id?: string; className?: string } = {}) {
  const node = el('section', 'card ' + (options.className ?? ''), el('div', 'card-heading', el('h2', '', title), options.action), ...body)
  if (options.id) node.id = options.id
  return node
}
export function status(slot: Slot): HTMLElement | null {
  if (slot.state === 'available') return null
  const states: Record<string, string> = {
    loading: 'Loading records…', not_started: 'Not started', unavailable: 'Source unavailable', denied: 'Access denied or record unavailable',
    stale: 'Stale data'
  }
  return el('div', 'source-status', badge(slot.state, states[slot.state]), slot.issue ? el('small', '', slot.issue) : null,
    slot.state === 'stale' && slot.at ? el('small', '', 'Last retrieved ' + date(slot.at)) : null)
}
export const empty = (message: string) => el('p', 'empty', message)

export function fields(items: [string, string][]): HTMLDListElement {
  const node = el('dl', 'fields')
  for (const [label, value] of items) node.append(el('dt', '', label), el('dd', '', value))
  return node
}
export function labelControl(label: string, control: HTMLElement): HTMLLabelElement {
  control.setAttribute('aria-label', label)
  return el('label', 'field', el('span', '', label), control)
}
export function select(choices: [string, string][], selected: string, update: (value: string) => void) {
  const root = el('select')
  for (const [value, label] of choices) {
    const option = el('option', '', label)
    option.value = value
    root.append(option)
  }
  root.value = selected
  root.addEventListener('change', () => update(root.value))
  return root
}
export function meter(label: string, val: unknown, max: unknown, formatter: (value: unknown) => string = count) {
  const value = number(val)
  const limit = number(max)
  const root = el('div', 'meter', el('div', 'meter-label', el('span', '', label),
    el('strong', '', formatter(value) + ' / ' + formatter(limit))))
  if (value !== null && limit !== null && limit > 0) {
    const gauge = el('progress')
    gauge.setAttribute('aria-label', label)
    gauge.max = limit
    gauge.value = Math.min(value, limit)
    root.append(gauge)
  }
  return root
}

export function recordButton(title: string, detail: string, state: unknown, inspect: () => void) {
  const node = el('button', 'record', el('span', 'record-copy', el('strong', '', title), el('small', '', detail)),
    state ? badge(state) : null, icon('chevron'))
  node.type = 'button'
  node.addEventListener('click', inspect)
  return node
}

/** Windowed rows with native focusable controls and keyboard navigation. */
export function windowed<T>(records: T[], render: (record: T) => HTMLElement, label: string, rowHeight = 62) {
  const root = el('div', 'windowed')
  root.setAttribute('role', 'region')
  root.setAttribute('aria-label', label)
  root.tabIndex = 0
  const inner = el('div', 'window-content')
  inner.style.height = records.length * rowHeight + 'px'
  root.style.height = Math.min(records.length * rowHeight + 2, 520) + 'px'
  const layer = el('div', 'window-layer')
  inner.append(layer)
  root.append(inner)
  let start = -1
  let end = -1
  let pending = 0
  function draw() {
    pending = 0
    const first = Math.max(0, Math.floor(root.scrollTop / rowHeight) - 4)
    const last = Math.min(records.length, Math.ceil((root.scrollTop + (root.clientHeight || 520)) / rowHeight) + 4)
    if (first === start && last === end) return
    start = first
    end = last
    const focused = document.activeElement instanceof HTMLElement ? document.activeElement.dataset.position : undefined
    layer.style.transform = 'translateY(' + first * rowHeight + 'px)'
    layer.replaceChildren(...records.slice(first, last).map((record, i) => {
      const row = render(record)
      row.style.height = rowHeight + 'px'
      row.dataset.position = String(first + i)
      return row
    }))
    if (focused) {
      const replacement = [...layer.children].find(child => (child as HTMLElement).dataset.position === focused) as HTMLElement | undefined
      if (replacement) replacement.focus({ preventScroll: true })
      else if (root.isConnected) root.focus({ preventScroll: true })
    }
  }
  function schedule() { if (!pending) pending = requestAnimationFrame(draw) }
  root.addEventListener('scroll', schedule, { passive: true })
  root.addEventListener('keydown', event => {
    if (!['ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return
    event.preventDefault()
    const current = Number((event.target as HTMLElement).closest<HTMLElement>('[data-position]')?.dataset.position ?? -1)
    const next = Math.min(records.length - 1, Math.max(0, event.key === 'End' ? records.length - 1 :
      event.key === 'Home' ? 0 : current + (event.key === 'ArrowDown' ? 1 : -1)))
    if (next * rowHeight < root.scrollTop || (next + 1) * rowHeight > root.scrollTop + root.clientHeight) {
      root.scrollTop = next * rowHeight
    }
    draw()
    layer.querySelector<HTMLElement>('[data-position="' + next + '"]')?.focus({ preventScroll: true })
  })
  draw()
  return root
}
