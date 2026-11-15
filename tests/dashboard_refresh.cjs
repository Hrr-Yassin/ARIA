// Failed owner-scoped refreshes cannot leave an old successful mission current.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('web/static/scripts/dashboard.js', 'utf8');
const note = {textContent: ''};
let campaignExists = false;
const timingEntries = [];
const context = {
  document: {addEventListener() {}, getElementById(id) {return id === 'hero-note' ? note : null;},
    querySelector() {return null;}, querySelectorAll() {return [];}, body:{dataset:{}}},
  window: {setTimeout, clearTimeout}, console,
  performance: {now: () => 2, getEntriesByName: () => [], clearMeasures() {},
    measure: (name, options) => timingEntries.push({name,...options})},
  fetch: async (url) => {
    if (url.endsWith('/autonomous/status') || url.endsWith('/api/team/owned')
        || url.endsWith('/campaign/health') || url.endsWith('/campaign/events')) {
      return new Response(JSON.stringify({detail:'Fixture storage unavailable'}),
        {status:503, headers:{'content-type':'application/json'}});
    }
    if (url.endsWith('/campaign')) return new Response(JSON.stringify({state:'running'}),
      {status:campaignExists ? 200 : 404, headers:{'content-type':'application/json'}});
    const data = url.endsWith('/api/session/owned')
      ? {session_id:'owned',name:'Fixture',target:'192.0.2.1',scope:{targets:['192.0.2.1']}}
      : {};
    return new Response(JSON.stringify(data), {headers:{'content-type':'application/json'}});
  },
};
vm.createContext(context);
vm.runInContext(source.replace("document.addEventListener('DOMContentLoaded', boot);",
  'globalThis.testDashboard = {state, loadAll, fmtUsdMicro, buildTimelineEvents, recordHttpTiming};'), context);
(async () => {
  const {state, loadAll, fmtUsdMicro, buildTimelineEvents, recordHttpTiming} = context.testDashboard;
  for (const value of [null, '', ' ', 'invalid', '-1']) {
    recordHttpTiming(0, {status:200,headers:{get: key => key === 'x-aria-handler-ms' ? value : null}}, '/api/health');
    assert.equal(timingEntries.at(-1).detail.server_handler_ms, null, 'Missing duration is unavailable');
  }
  recordHttpTiming(0, {status:200,headers:{get: key => key === 'x-aria-handler-ms' ? '0' : null}}, '/api/health');
  assert.equal(timingEntries.at(-1).detail.server_handler_ms, 0, 'A measured zero is retained');
  state.token = 'synthetic-fixture-token'; state.sessionId = 'owned';
  state.data = {autonomous:{run_id:'old',run_state:'completed'}, team:{tasks:[{state:'completed'}]}};
  await loadAll();
  assert.equal(state.data.autonomous, null, 'A failed refresh must retire an old completed run');
  assert.equal(state.data.team, null, 'Unavailable ledger is not a stale successful task list');
  assert.match(note.textContent, /unavailable/i);
  campaignExists = true;
  state.data.campaignHealth = {progress:{steps_taken:12},state:'completed'};
  state.data.campaignEvents = {events:[{type:'campaign_completed'}]};
  await loadAll();
  assert.equal(state.data.campaignHealth, null);
  assert.equal(state.data.campaignEvents, null);
  assert.equal(fmtUsdMicro(null), 'Unavailable');
  assert.equal(fmtUsdMicro(1), '$0.000001', 'Small nonzero charges must remain visible');
  assert.equal(fmtUsdMicro(0), '$0.00');
  const at = '2026-11-15T10:00:00Z';
  state.data.decisions = {entries:[
    {id:'shared',type:'team_event',created_at:at},
    {id:'distinct-a',type:'execution',created_at:at,action:'Same description'},
    {id:'distinct-b',type:'execution',created_at:at,action:'Same description'}]};
  const teamEvent = {id:'shared',collection:'tasks',timestamp:at,data:{state:'completed',reviewed_by:'owner'}};
  state.data.teamEvents = {events:[teamEvent, teamEvent]};
  state.data.campaignEvents = null;
  const timeline = buildTimelineEvents();
  assert.equal(timeline.length, 3, 'One durable event delivered by two sources must appear once');
  assert.equal(timeline.filter(event => event.category === 'decision').length, 2,
    'Distinct event IDs remain distinct even with identical descriptions/timestamps');
  console.log('Dashboard failed-refresh retirement and precise micro-USD display passed');
})().catch(error => {console.error(error); process.exitCode = 1;});
