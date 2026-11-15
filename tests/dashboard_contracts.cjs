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

// Exercise mission wording with the actual pure formatter. No browser or API
// fixture is substituted for visible acceptance by this contract check.
const context = {document: {addEventListener() {}}};
vm.createContext(context);
vm.runInContext(js.replace("document.addEventListener('DOMContentLoaded', boot);",
  'globalThis.missionSummary = missionSummary; globalThis.blockerRows = blockerRows; globalThis.questionReadiness = questionReadiness; globalThis.attemptMetricRows = attemptMetricRows; globalThis.researchLabel = researchLabel; globalThis.verificationLabel = verificationLabel; globalThis.providerCharge = providerCharge;'), context);
const summary = context.missionSummary({run_state:'completed', mission:{
  state:'work_pending', pending_tasks:[{id:'review'}], reason:'Owner review remains pending.',
  objective:'Observe only the approved fixture'}});
assert(summary.includes('Bounded cycle: Completed.'));
assert(summary.includes('Work Pending') || summary.includes('Work pending'));
assert(summary.includes('Pending team tasks: 1.'));
assert(summary.includes('Owner review remains pending.'));
assert(summary.includes('Observe only the approved fixture'));
const unavailable = context.missionSummary({run_state:'completed', mission:{state:'blocked',pending_tasks:null}});
assert(unavailable.includes('count unavailable'));
assert(!unavailable.includes('tasks: 0'));
const blocker = context.blockerRows({mission:{blocker:{reason_code:'worker_command_rejected',
  status:'blocked',component:'worker',explanation:'The worker rejected this command.',
  operator_action:'Review supported ports and the durable receipt.'}}});
assert.deepEqual(Array.from(blocker, row => Array.from(row)), [
  ['Reason code','worker_command_rejected'], ['Status','Blocked'], ['Component','Worker'],
  ['Explanation','The worker rejected this command.'],
  ['Operator action','Review supported ports and the durable receipt.']]);
assert.equal(context.blockerRows({}).length, 0);
for (const readiness of [null, {}, {state:'unknown',questions_total:0,questions_tested:0,percent:0},
  {state:'not_ready',questions_total:2,questions_tested:1,percent:null},
  {state:'not_ready',questions_total:2,questions_tested:1,percent:90}]) {
  assert.equal(context.questionReadiness({progress:{readiness}}), null, 'Unknown or inconsistent readiness is unavailable');
}
assert.equal(context.questionReadiness({progress:{readiness:{state:'not_ready',questions_total:2,questions_tested:0,percent:0}}}), 0);
assert.equal(context.questionReadiness({progress:{readiness:{state:'not_ready',questions_total:2,questions_tested:1,percent:50}}}), 50);
assert.equal(context.questionReadiness({progress:{overall_pct:100}}), null);
const metrics = Object.fromEntries(context.attemptMetricRows({input_tokens:0, output_tokens:null,
  timings:{http_attempts:1, provider_attempt_ms:14.5}}));
assert.equal(metrics['HTTP attempts'], '1');
assert.equal(metrics['HTTP request / response'], '14.50 ms');
assert.equal(metrics['Reported input tokens'], '0');
assert.equal(metrics['Reported output tokens'], 'Unavailable');
assert.equal(metrics['Structured validation'], 'Unavailable');
assert.match(context.researchLabel({state:'CONFIRMED',confirmed:false,context_current:false}), /Unverified.*context stale/);
assert.match(context.verificationLabel({state:'reportable',ready_for_external_submission:false,verification_current:false}), /Unverified/);
assert.match(context.verificationLabel({state:'reportable',ready_for_external_submission:true,verification_current:true}), /^Independently verified/);
assert.equal(context.providerCharge({provider_usage:{cost:'0.0000002'}}), '$0.0000002 USD (provider receipt)');
assert.equal(context.providerCharge({provider_usage:{cost:'private-sentinel'}}), 'Unavailable');
assert.equal(context.providerCharge({}), 'Unavailable');
console.log('Dashboard contracts, mission-state wording, real API routes, responsive and accessibility checks passed');
