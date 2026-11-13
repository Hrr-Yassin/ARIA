// Static and client-contract checks for the owner-facing operations overview.
// The browser-level acceptance is covered separately by integration/dashboard_screenshots.py.
const fs = require('fs');
const vm = require('vm');
const assert = require('assert/strict');

const read = (path) => fs.readFileSync(path, 'utf8');
const html = read('web/dashboard.html');
const css = read('web/static/styles/dashboard.css');
const js = read('web/static/scripts/dashboard.js');
const main = read('api/main.py');
const index = read('web/index.html');

// The client must parse as JavaScript before any browser is involved.
new vm.Script(js, { filename: 'dashboard.js' });

assert.match(js, /^\(function \(\) \{/m, 'Dashboard client is an isolated IIFE');
assert.match(js, /'use strict'/, 'Dashboard client uses strict mode');
assert.match(html, /href="\/static\/styles\/dashboard\.css"/, 'Dashboard stylesheet is linked');
assert.match(html, /src="\/static\/scripts\/dashboard\.js"/, 'Dashboard client is loaded');
assert.match(html, /<main id="dashboard-main"/, 'Dashboard has a main landmark');
assert.match(html, /<nav class="rail-nav"/, 'Dashboard has primary navigation');
assert.match(html, /class="skip-link"/, 'Dashboard has a skip link');
assert.match(html, /aria-live="polite"/, 'Live regions are present');

// Every statically referenced element must exist in the shell.
const referenced = new Set();
for (const pattern of [/\$\('([^']+)'\)/g, /setText\('([^']+)'/g, /getElementById\('([^']+)'\)/g]) {
  for (const match of js.matchAll(pattern)) referenced.add(match[1]);
}
const declared = new Set([...html.matchAll(/id="([^"]+)"/g)].map((match) => match[1]));
const missing = [...referenced].filter((id) => !declared.has(id));
assert.deepEqual(missing, [], 'Every dashboard element id referenced by the client exists');

// The new page must not inject API text through HTML parsing.
assert.ok(!/\.innerHTML\s*=/.test(js), 'Dashboard client never assigns innerHTML');
assert.match(js, /textContent/, 'Dashboard client renders text through textContent');
assert.match(js, /createElementNS\('http:\/\/www\.w3\.org\/2000\/svg'/, 'Graph elements use the SVG namespace');

// The page consumes only existing owner-scoped routes.
for (const route of [
  '/api/session/list',
  '/api/session/',
  '/api/findings/',
  '/api/v8/status/',
  '/api/v8/llm-status',
  '/api/team/',
  '/api/pentest/',
  '/api/capabilities',
  '/api/health',
]) {
  assert.ok(js.includes(route), `Dashboard calls real API route ${route}`);
}
assert.ok(!/Math\.random\(\)/.test(js), 'Dashboard does not synthesize metric values');

// Responsive and accessibility contracts.
for (const token of [
  '@media (max-width: 640px)',
  'prefers-reduced-motion',
  'focus-visible',
  'forced-colors',
  'aria-pressed',
]) {
  assert.ok(css.includes(token), `Dashboard CSS includes ${token}`);
}
assert.match(js, /aria-valuenow/, 'Dashboard meters expose numeric values');
assert.match(css, /--ink-0:/, 'Dashboard defines its dark palette');
assert.match(css, /--brass:/, 'Dashboard defines its primary accent');
assert.match(css, /--font-display: "Instrument Serif"/, 'Dashboard uses its distinctive display face');
assert.match(html, /role="tablist"/, 'Evidence views expose tab semantics');
assert.match(html, /role="progressbar"/, 'Readiness exposes progress semantics');

// Routing and discoverability.
assert.match(main, /@app\.get\("\/dashboard"/, 'FastAPI serves the dashboard route');
assert.match(main, /dashboard\.html/, 'FastAPI serves the dashboard shell');
assert.match(index, /href="\/dashboard"/, 'Workspace header links to the overview');

console.log('Dashboard contracts, real API routes, responsive and accessibility checks passed');
