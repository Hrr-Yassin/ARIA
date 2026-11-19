import { select } from 'd3'
import { canvasPainter, pixiPainter, type Painter, type Point } from './density'

type Renderer = 'svg' | 'canvas' | 'pixi'
const root = document.querySelector<HTMLElement>('#surface')!
const state = document.querySelector<HTMLElement>('#benchmark-state')!
const width = 1050
const height = 320
const colors = [0x76dece, 0xa48aff, 0x6197ff, 0xf6bf77]

function svgPainter(container: HTMLElement): Painter {
  const svg = select(container).append('svg').attr('width', width).attr('height', height)
  return { renderer: 'D3 / SVG', draw(points) {
    svg.selectAll<SVGRectElement, Point>('rect').data(points).join('rect')
      .attr('x', point => point.x - 1.5)
      .attr('y', point => point.y - 5)
      .attr('width', 3).attr('height', 10)
      .attr('fill', point => '#' + point.color.toString(16).padStart(6, '0'))
  }, dispose: () => svg.remove() }
}

const raf = () => new Promise<number>(resolve => requestAnimationFrame(resolve))
function percentile(values: number[], fraction: number) {
  const sorted = [...values].sort((a, b) => a - b)
  return Number(sorted[Math.floor((sorted.length - 1) * fraction)].toFixed(2))
}

async function measure(kind: Renderer, size: number, frames = 60) {
  state.textContent = kind + ' · ' + size.toLocaleString() + ' markers'
  const t0 = performance.now()
  const painter = kind === 'svg' ? svgPainter(root) : kind === 'canvas' ? canvasPainter(root) : await pixiPainter(root, true)
  const initializationMs = performance.now() - t0
  const points = Array.from({ length: size }, (_, index) => ({
    x: (index * 127) % width, y: 25 + (index % 8) * 38,
    index, color: colors[index % colors.length]
  }))
  const intervals = []
  const renderDurations = []
  const first = await raf()
  let last = first
  try {
    for (let index = 0; index <= 12 + frames; index++) {
      const at = await raf()
      for (const point of points) point.x = (point.x + 2) % width
      const started = performance.now()
      painter.draw(points, width, height)
      if (index > 12) {
        renderDurations.push(performance.now() - started)
        intervals.push(at - last)
      }
      last = at
    }
    return {
      renderer: painter.renderer, markers: size, samples: intervals.length, initializationMs: Number(initializationMs.toFixed(2)),
      fps: Number((1000 * intervals.length / intervals.reduce((sum, elapsed) => sum + elapsed, 0)).toFixed(1)),
      frameP50Ms: percentile(intervals, .50), frameP95Ms: percentile(intervals, .95),
      drawP50Ms: percentile(renderDurations, .50), drawP95Ms: percentile(renderDurations, .95),
      longFrames: intervals.filter(ms => ms > 25).length, surfaceNodes: root.querySelectorAll('*').length
    }
  } finally {
    painter.dispose()
  }
}

Object.assign(window, { ariaRendererBenchmark: measure })
state.textContent = 'Ready'
