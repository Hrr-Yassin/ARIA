import { init, use, type EChartsCoreOption } from 'echarts/core'
import { BarChart, LineChart } from 'echarts/charts'
import { AriaComponent, DataZoomComponent, GridComponent, LegendComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import { type Json, number, object, text } from './api'

use([BarChart, LineChart, AriaComponent, DataZoomComponent, GridComponent, LegendComponent, TooltipComponent, CanvasRenderer])
const palette = ['#a288f9', '#42b7a9', '#6197ff', '#eea758', '#e38492', '#72b7d7']
type Series = [name: string, read: (row: Json) => number | null]
const time = (row: Json): number => Date.parse(text(row.timestamp))
const dollar = (value: unknown) => { const amount = number(value); return amount === null ? null : amount / 1e6 }
function nativeCost(row: Json): number | null {
  const cost = object(row.provider_usage)?.cost
  return typeof cost === 'string' && /^\d*(\.\d+)?([eE][+-]?\d+)?$/.test(cost) && cost ? number(Number(cost)) : null
}
export function latency(row: Json): number | null {
  return number(object(row.timings)?.pool_attempt_ms)
}
export function isTimeout(row: Json): boolean {
  return ['timeout', 'client_timeout', 'provider_timeout', 'request_timeout', 'read_timeout'].includes(text(row.error_code))
}
function recorded(name: string, rows: Json[], read: (row: Json) => number | null) {
  const data = rows.map(row => [time(row), read(row)])
  return data.some(row => row[1] !== null) ? { name, data, type: 'line', showSymbol: true, symbolSize: 5,
    connectNulls: false, sampling: 'lttb', emphasis: { focus: 'series' } } : null
}

type AttemptKind = 'tokens' | 'cost' | 'latency' | 'volume' | 'distribution'
const bandEdges = [100, 500, 1000, 5000, 15000, Infinity]
const bandLabels = ['<100 ms', '100–499 ms', '0.5–1 s', '1–5 s', '5–15 s', '≥15 s']
export function seriesFor(kind: AttemptKind, attempts: Json[]) {
  if (kind === 'distribution') {
    const groups = new Map<string, number[]>()
    for (const attempt of attempts) {
      const measured = latency(attempt)
      if (measured === null) continue
      const provider = text(attempt.provider, 'Provider unrecorded') + ' / ' + text(attempt.model, 'Model unrecorded')
      if (!groups.has(provider)) groups.set(provider, bandLabels.map(() => 0))
      groups.get(provider)![bandEdges.findIndex(edge => measured < edge)]++
    }
    return [...groups].map(([name, data]) => ({ name, data, type: 'bar', emphasis: { focus: 'series' } }))
  }
  const series: Record<Exclude<AttemptKind, 'distribution'>, Series[]> = {
    tokens: [['Reserved', row => number(row.reserved_tokens)], ['Reported total', row => number(row.reported_tokens)],
      ['Input', row => number(row.input_tokens)], ['Output', row => number(row.output_tokens)]],
    cost: [['Reserved', row => dollar(row.reserved_cost_microusd)], ['Reported estimate', row => dollar(row.reported_cost_microusd)],
      ['Provider receipt', nativeCost]],
    latency: [['Pool attempt', latency], ['HTTP request', row => number(object(row.timings)?.provider_attempt_ms)],
      ['Provider reported', row => number(object(row.timings)?.provider_reported_total_ms)]],
    volume: [['Reserved', () => 1], ['Succeeded', row => row.state === 'succeeded' ? 1 : 0],
      ['Failed', row => row.state === 'failed' ? 1 : 0], ['Timed out', row => isTimeout(row) ? 1 : 0],
      ['Later physical attempt', row => number(row.attempt_index) === null ? null : (Number(row.attempt_index) > 1 ? 1 : 0)]]
  }
  const source = attempts.filter(row => Number.isFinite(time(row))).sort((a, b) => time(a) - time(b))
  return series[kind].map(([name, read]) => {
    if (kind !== 'volume') return recorded(name, source, read)
    let cumulative = 0
    return recorded(name, source, row => {
      const value = read(row)
      if (value === null) return null
      cumulative += value
      return cumulative
    })
  }).filter(Boolean)
}

export function mountChart(root: HTMLElement, kind: AttemptKind, attempts: Json[]) {
  return mountPlot(root, seriesFor(kind, attempts), kind === 'distribution' ? bandLabels : undefined)
}

export function mountCountChart(root: HTMLElement, label: string, bins: [string, number][]) {
  return mountPlot(root, [{ name: label, data: bins.map(([, value]) => value), type: 'bar', barMaxWidth: 32 }], bins.map(([name]) => name))
}

function mountPlot(root: HTMLElement, series: unknown[], categories?: string[]) {
  const css = getComputedStyle(root)
  const muted = css.getPropertyValue('--muted').trim()
  const border = css.getPropertyValue('--line').trim()
  const background = css.getPropertyValue('--panel').trim()
  const foreground = css.getPropertyValue('--ink').trim()
  root.replaceChildren()
  const chart = init(root, undefined, { renderer: 'canvas', devicePixelRatio: Math.min(devicePixelRatio, 2) })
  const options: EChartsCoreOption = {
    animation: false,
    color: palette,
    textStyle: { color: muted, fontFamily: 'system-ui' },
    aria: { enabled: true },
    grid: { left: 18, right: 22, top: 64, bottom: 58, containLabel: true },
    tooltip: { trigger: 'axis', renderMode: 'richText', backgroundColor: background, textStyle: { color: foreground },
      borderColor: border, confine: true },
    legend: { top: 4, type: 'scroll', textStyle: { color: foreground }, pageTextStyle: { color: muted } },
    xAxis: { type: categories ? 'category' : 'time', data: categories,
      axisLabel: { color: muted, hideOverlap: true }, axisLine: { lineStyle: { color: border } } },
    yAxis: { type: 'value', min: 0, axisLabel: { color: muted }, splitLine: { lineStyle: { color: border } } },
    dataZoom: [{ type: 'inside', filterMode: 'none' }, { type: 'slider', height: 16, bottom: 10, textStyle: { color: muted },
      borderColor: border, fillerColor: 'rgba(151,127,239,.22)', showDetail: false }],
    series
  }
  chart.setOption(options)
  root.dataset.renderer = 'echarts'
  let frame = 0
  const observer = new ResizeObserver(() => { cancelAnimationFrame(frame); frame = requestAnimationFrame(() => chart.resize()) })
  observer.observe(root)
  return () => { observer.disconnect(); cancelAnimationFrame(frame); chart.dispose() }
}
