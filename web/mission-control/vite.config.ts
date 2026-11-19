import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vite'

export default defineConfig(({ mode }) => ({
  base: mode === 'bench' ? '/static/mission-bench/' : '/static/mission/',
  build: {
    outDir: fileURLToPath(new URL(mode === 'bench' ? '../static/mission-bench' : '../static/mission', import.meta.url)),
    emptyOutDir: true,
    target: 'es2022',
    chunkSizeWarningLimit: 600,
    rollupOptions: mode === 'bench' ? { input: fileURLToPath(new URL('./bench.html', import.meta.url)) } : undefined
  },
  server: {
    host: '127.0.0.1',
    proxy: { '/api': { target: 'http://127.0.0.1:7000', ws: true }, '/login': 'http://127.0.0.1:7000' }
  }
}))
