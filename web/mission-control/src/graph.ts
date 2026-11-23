import { select, zoom, zoomIdentity, type D3ZoomEvent } from 'd3'
import { button, el } from './dom'

export type Node = { id: string; label: string; state: string; column: number; kind: string }
export type Edge = { source: string; target: string; kind: string }
export type Graph = { nodes: Node[]; edges: Edge[]; inspect: (id: string) => void; label: string; motion: boolean; directed?: boolean }

export function mountGraph(root: HTMLElement, graph: Graph) {
  const drawing = el('div', 'graph-drawing')
  const controls = el('div', 'graph-controls')
  root.replaceChildren(controls, drawing)
  const svg = select(drawing).append('svg').attr('role', 'group').attr('aria-label', graph.label)
  const scene = svg.append('g')
  const arrowId = 'graph-arrow-' + crypto.randomUUID()
  if (graph.directed) svg.append('defs').append('marker').attr('id', arrowId)
    .attr('viewBox', '0 0 10 10').attr('refX', 9).attr('refY', 5)
    .attr('markerWidth', 6).attr('markerHeight', 6).attr('orient', 'auto')
    .append('path').attr('d', 'M0,0 L10,5 L0,10 Z').attr('fill', 'var(--muted)')
  const behavior = zoom<SVGSVGElement, unknown>().scaleExtent([0.12, 3.5])
    .filter(event => event.type !== 'wheel' || event.ctrlKey)
    .on('zoom', (event: D3ZoomEvent<SVGSVGElement, unknown>) => scene.attr('transform', event.transform.toString()))
  svg.call(behavior)

  const xStep = 244
  const yStep = 62
  const width = 190
  const columns = new Map<number, number>()
  const nodes = graph.nodes.map(record => {
    const row = columns.get(record.column) ?? 0
    columns.set(record.column, row + 1)
    return { ...record, x: 24 + xStep * record.column, y: 24 + yStep * row }
  })
  const byId = new Map(nodes.map(node => [node.id, node]))
  const maxX = Math.max(width + 48, ...nodes.map(node => node.x + width + 24))
  const maxY = Math.max(80, ...nodes.map(node => node.y + 70))
  drawing.style.setProperty('--plot-height', Math.min(400, Math.max(192, maxY + 30)) + 'px')
  scene.append('g').attr('class', 'graph-edges').selectAll('path').data(graph.edges.filter(edge =>
    byId.has(edge.source) && byId.has(edge.target)), edge => {
      const link = edge as Edge
      return link.source + ':' + link.target + ':' + link.kind
    }).join('path').attr('data-kind', edge => edge.kind)
    .attr('marker-end', graph.directed ? 'url(#' + arrowId + ')' : null)
    .attr('d', edge => {
      const a = byId.get(edge.source)!
      const b = byId.get(edge.target)!
      const backwards = a.x > b.x
      const start = a.x + (backwards ? 0 : width)
      const ax = a.y + 22
      const bx = b.y + 22
      const end = b.x + (a.x >= b.x ? width : 0)
      const turn = a.x === b.x ? start + 28 : (start + end) / 2
      return 'M' + start + ',' + ax + ' C' + turn + ',' + ax + ' ' + turn + ',' + bx + ' ' + end + ',' + bx
    }).append('title').text(edge => edge.kind)
  const selection = scene.append('g').selectAll('g').data(nodes, node => (node as Node).id)
    .join('g').attr('class', 'graph-node')
    .attr('transform', node => 'translate(' + node.x + ',' + node.y + ')')
    .attr('data-state', node => node.state).attr('data-node', node => node.id)
    .attr('tabindex', 0).attr('role', 'button').attr('aria-label', node => node.label + ', ' + node.kind + ', ' + node.state)
    .on('click', (_, node) => graph.inspect(node.id))
    .on('keydown', (event: KeyboardEvent, node) => {
      if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); graph.inspect(node.id) }
    })
  selection.append('rect').attr('width', width).attr('height', 44).attr('rx', 9)
  selection.append('circle').attr('cx', 14).attr('cy', 14).attr('r', 3.4)
  selection.append('text').attr('x', 24).attr('y', 18).text(node => node.label.length > 24 ? node.label.slice(0, 23) + '…' : node.label)
  selection.append('text').attr('x', 24).attr('y', 34).attr('class', 'graph-detail').text(node => node.kind + ' · ' + node.state.replaceAll('_', ' '))
  selection.append('title').text(node => node.label)

  const fit = () => {
    const w = drawing.clientWidth || 600
    const h = drawing.clientHeight || 420
    const scale = Math.max(0.12, Math.min(1.25, (w - 18) / maxX, (h - 18) / maxY))
    svg.call(behavior.transform, zoomIdentity.translate(Math.max(8, (w - maxX * scale) / 2), Math.max(8, (h - maxY * scale) / 2)).scale(scale))
  }
  const nudge = (scale: number) => svg.call(behavior.scaleBy, scale)
  controls.append(button('Zoom in', () => nudge(1.35), 'button small'), button('Zoom out', () => nudge(1 / 1.35), 'button small'),
    button('Fit graph', fit, 'button small'), el('small', '', 'Drag to pan · Ctrl + scroll to zoom'))
  fit()
  let resized = 0
  const observer = new ResizeObserver(() => { cancelAnimationFrame(resized); resized = requestAnimationFrame(fit) })
  observer.observe(drawing)
  if (graph.motion && !matchMedia('(prefers-reduced-motion: reduce)').matches) {
    drawing.animate([{ opacity: 0.45 }, { opacity: 1 }], { duration: 170, easing: 'ease-out' })
  }
  root.dataset.renderer = 'svg'
  return () => { observer.disconnect(); cancelAnimationFrame(resized); svg.on('.zoom', null) }
}
