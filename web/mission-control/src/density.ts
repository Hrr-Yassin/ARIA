export type Point = { x: number; y: number; color: number; index: number }
export type Painter = { draw: (points: Point[], width: number, height: number) => void; dispose: () => void; renderer: string }

export function canvasPainter(root: HTMLElement): Painter {
  const surface = document.createElement('canvas')
  const context = surface.getContext('2d')
  if (!context) throw new Error('Canvas is unavailable')
  root.replaceChildren(surface)
  let lastW = 0
  let lastH = 0
  const ratio = Math.min(window.devicePixelRatio || 1, 2)
  return { renderer: 'Canvas 2D', draw(points, width, height) {
    if (lastW !== width || lastH !== height) {
      lastW = width
      lastH = height
      surface.width = Math.ceil(width * ratio)
      surface.height = Math.ceil(height * ratio)
      surface.style.width = width + 'px'
      surface.style.height = height + 'px'
      context.setTransform(ratio, 0, 0, ratio, 0, 0)
    }
    context.clearRect(0, 0, width, height)
    let previous = -1
    for (const point of points) {
      if (point.color !== previous) context.fillStyle = '#' + point.color.toString(16).padStart(6, '0')
      previous = point.color
      context.fillRect(point.x - 1.5, point.y - 5, 3, 10)
    }
  }, dispose: () => surface.remove() }
}

export async function pixiPainter(root: HTMLElement, allowSoftware = false): Promise<Painter> {
  const { Application, Graphics } = await import('pixi.js')
  const app = new Application()
  try {
    await app.init({ preference: 'webgl', preferWebGLVersion: 2, width: 10, height: 10, antialias: false,
      backgroundAlpha: 0, autoStart: false, autoDensity: true, resolution: Math.min(window.devicePixelRatio || 1, 2) })
  } catch (error) {
    if (app.renderer) app.destroy(true, { children: true, texture: true })
    throw error
  }
  const layers = new Graphics()
  app.stage.addChild(layers)
  const gl = 'gl' in app.renderer ? app.renderer.gl as WebGLRenderingContext : null
  const info = gl?.getExtension('WEBGL_debug_renderer_info')
  const backend = gl && info ? String(gl.getParameter(info.UNMASKED_RENDERER_WEBGL)) : ''
  if (!allowSoftware && /swiftshader|llvmpipe|softpipe|software/i.test(backend)) {
    app.destroy(true, { children: true, texture: true })
    throw new Error('Software WebGL renderer')
  }
  root.replaceChildren(app.canvas)
  let lastW = 0
  let lastH = 0
  return { renderer: backend ? 'PixiJS WebGL · ' + backend : 'PixiJS WebGL', draw(points, width, height) {
    if (lastW !== width || lastH !== height) {
      app.renderer.resize(width, height)
      lastW = width
      lastH = height
    }
    layers.clear()
    // Each colour is submitted as one sequence of rectangles.
    const byColor = new Map<number, Point[]>()
    for (const point of points) {
      if (!byColor.has(point.color)) byColor.set(point.color, [])
      byColor.get(point.color)!.push(point)
    }
    for (const [color, series] of byColor) {
      for (const point of series) layers.rect(point.x - 1.5, point.y - 5, 3, 10)
      layers.fill({ color })
    }
    app.render()
  }, dispose: () => app.destroy(true, { children: true, texture: true }) }
}

export async function mountDensity(root: HTMLElement, records: { timestamp: string; source: string }[], gpu: boolean,
                                   inspect: (index: number) => void) {
  const display = document.createElement('div')
  display.className = 'density-display'
  display.setAttribute('aria-hidden', 'true')
  const note = document.createElement('p')
  note.className = 'subtle'
  root.replaceChildren(display, note)
  let painter: Painter
  try { painter = gpu ? await pixiPainter(display) : canvasPainter(display) }
  catch {
    try { painter = canvasPainter(display) }
    catch { note.textContent = 'Graphical rendering unavailable. Use the event list.'; return () => {} }
  }
  if (!root.isConnected) { painter.dispose(); return () => {} }
  const colors: Record<string, number> = { team: 0x39c7ad, campaign: 0xa181ff, worker: 0x6197ff,
    approval: 0xeea758, authorization: 0xf880a7, model: 0xd0ca72 }
  const recordedSources = new Set(records.map(record => record.source))
  const sources = [...Object.keys(colors).filter(source => recordedSources.has(source)),
    ...[...recordedSources].filter(source => !Object.hasOwn(colors, source)).sort()]
  const lanes = new Map(sources.map((source, index) => [source, (index + 1) * 86 / (sources.length + 1)]))
  note.textContent = (gpu && painter.renderer === 'Canvas 2D' ? 'GPU unavailable · ' : '') + painter.renderer +
    ' · Lanes in order: ' + sources.join(', ')
  root.dataset.renderer = painter.renderer
  const times = records.map(record => Date.parse(record.timestamp))
  const start = Math.min(...times)
  const end = Math.max(...times)
  let points: Point[] = []
  let frame = 0
  const draw = () => {
    const width = Math.max(1, Math.round(display.getBoundingClientRect().width))
    points = records.map((record, index) => ({
      x: 10 + (end === start ? (width - 20) / 2 : ((times[index] - start) / (end - start)) * (width - 20)),
      y: lanes.get(record.source) ?? 43, color: Object.hasOwn(colors, record.source) ? colors[record.source] : 0x9eacc3, index
    }))
    painter.draw(points, width, 86)
  }
  const onPointer = (event: MouseEvent) => {
    const x = event.clientX - display.getBoundingClientRect().left
    const y = event.clientY - display.getBoundingClientRect().top
    let closest: Point | undefined
    let distance = 18
    for (const point of points) {
      const candidate = Math.hypot(point.x - x, point.y - y)
      if (candidate < distance) { closest = point; distance = candidate }
    }
    if (closest) inspect(closest.index)
  }
  display.addEventListener('click', onPointer)
  const observer = new ResizeObserver(() => { cancelAnimationFrame(frame); frame = requestAnimationFrame(draw) })
  observer.observe(display)
  draw()
  return () => { observer.disconnect(); cancelAnimationFrame(frame); display.removeEventListener('click', onPointer); painter.dispose() }
}
