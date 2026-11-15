// Execute the real client with a fake DOM, storage, worker API and WebSocket.
const fs = require('fs');
const vm = require('vm');
const assert = require('assert/strict');
const created = [];
function element() {
 const classes=new Set();
 const node={textContent:'',value:'',style:{},dataset:{},children:[],classList:{add(v){classes.add(v);},remove(v){classes.delete(v);},contains(v){return classes.has(v);},toggle(v){if(classes.has(v))classes.delete(v);else classes.add(v);}},
  appendChild(child){this.children.push(child);},append(...children){this.children.push(...children);},
  remove(){},querySelectorAll(){return [];},addEventListener(){}};
 created.push(node);return node;
}
const elements = new Map();
const requests=[];
const storage=new Map();
const command='hydra -l test -p test 192.0.2.1 ssh';
const context = {
 document:{getElementById(id){if(!elements.has(id))elements.set(id,element());return elements.get(id);},querySelectorAll(){return [];},createElement:element,addEventListener(){}},
 localStorage:{getItem(k){return storage.get(k)||null;},setItem(k,v){storage.set(k,v);},removeItem(k){storage.delete(k);}},
 location:{protocol:'http:',host:'testserver'},window:{location:{}},
 prompt(message){return message.startsWith('Target')?'192.0.2.1':'';},confirm(){return true;},setTimeout(){},setInterval(){},console,atob,TextDecoder,
 WebSocket:class {constructor(url){this.url=url;}send(data){this.sent=JSON.parse(data);}close(){}},
 async fetch(path,opts){
  requests.push({path,opts});
  const data={
   '/api/login':{token:'test-token',user_id:'owner',username:'owner',role:'pentester'},
   '/api/session/new':{session_id:'s1',name:'test',target:'192.0.2.1'},
   '/api/session/list':{sessions:[{session_id:'s1',name:'test',phase:'scan'}]},
   '/api/keys/':{keys:[{id:'key1',provider:'groq',is_active:true}]},
   '/api/v8/input':{type:'plan',commands:[{command,tool:'hydra',risk_color:'green'}],suggested_reply:'test plan'},
   '/api/execution/proposals':{action_id:'a1',command,tool:'hydra',risk_color:'red',status:'pending'},
   '/api/execution/a1/decision':{status:'approved'},
   '/api/kali/execute':{stdout:'mock worker output',stderr:'',exit_code:0},
  }[path] || {};
  return {ok:true,status:200,headers:{get(){return 'application/json';}},async json(){return data;}};
 }
};
let source=fs.readFileSync('web/static/scripts/app.js','utf8');
source=source.replace("document.addEventListener('DOMContentLoaded', boot);",'globalThis.testHooks={loadSessions,createNewSession,loadLLMKeys,connectAutoWS,sendMessage,runCommand,startAuto,stopAuto,commandForReview,showApprovalBanner,restoreRunStatus,updateAutoUI,handleAutoEvent,api,state};');
vm.createContext(context);
(async()=>{
 vm.runInContext(fs.readFileSync('web/static/scripts/login.js','utf8'),context);
 context.document.getElementById('username').value='test-user';
 context.document.getElementById('password').value='test-only-input';
 await context.doLogin();
 assert.equal(storage.get('pentestai_token'),'test-token');
 vm.runInContext(source,context);
 const h=context.testHooks;
 assert.equal(h.state.token,'test-token');
 h.state.booting=false;
 await h.loadSessions();await h.createNewSession();await h.loadLLMKeys();
 assert.equal(h.state.sessionId,'s1');
 for(const path of ['/api/session/list','/api/session/new','/api/keys/'])assert(requests.some(r=>r.path===path),path);
 elements.get('user-input').value='scan the target';await h.sendMessage();
 assert(requests.some(r=>r.path==='/api/v8/input'));
 assert(created.some(n=>n.className==='cmd-card'),'Top-level backend plan renders commands');
 await h.runCommand({command,tool:'hydra',risk_color:'green'});
 const proposal=requests.findIndex(r=>r.path==='/api/execution/proposals');
 const approval=requests.findIndex(r=>r.path==='/api/execution/a1/decision');
 const execution=requests.findIndex(r=>r.path==='/api/kali/execute');
 assert(proposal>=0 && approval>proposal && execution>approval,'Server approval precedes dispatch');
 assert.equal(JSON.parse(requests[execution].opts.body).action_id,'a1');
 assert(requests.some(r=>r.path==='/api/tool-results'));
 context.confirm=()=>false;
 const count=requests.filter(r=>r.path==='/api/kali/execute').length;
 await h.runCommand({command,tool:'hydra',risk_color:'green'});
 assert.equal(requests.filter(r=>r.path==='/api/kali/execute').length,count,'Rejected command is not dispatched');
 h.connectAutoWS();assert(!h.state.ws.url.includes('token='));h.state.ws.onopen();assert.equal(h.state.ws.sent.token,'test-token');
 h.state.autoStep=0;h.state.autoMaxSteps=2;h.updateAutoUI();
 assert.equal(elements.get('auto-log-counter').textContent,'step 0 / 2','Zero-step run displays selected budget');
 context.fetch=async()=>({status:200,ok:true,headers:{get(){return 'application/json';}},async json(){return {active:false,run_state:'blocked',max_steps:2,steps_taken:0};}});
 h.state.autoStep=5;h.state.autoMaxSteps=12;
 await h.restoreRunStatus();
 assert.equal(elements.get('auto-log-counter').textContent,'step 0 / 2','Restored run displays saved budget and step');
 assert.equal(elements.get('max-steps').value,2);
 assert.equal(elements.get('max-steps-value').textContent,2);
 assert.equal(elements.get('auto-label').textContent,'AUTONOMOUS — BLOCKED','Restored blocked run remains visibly labeled');
 h.state.autoRunStatus='';h.state.autoActive=true;h.handleAutoEvent({type:'auto_complete',status:'completed',action:'done'});
 assert.equal(elements.get('auto-label').textContent,'BOUNDED OBJECTIVE — COMPLETE','Bounded completion is distinguished from the mission');
 h.handleAutoEvent({type:'auto_complete',action:'Status omitted'});
 assert.equal(elements.get('auto-label').textContent,'AUTONOMOUS — STATUS UNAVAILABLE','Missing terminal status cannot become successful completion');
 // Auto must carry the owner's draft without a separate chat/provider call.
 const objective='Assess the authorized host without destructive actions; distinguish evidence from hypotheses.';
 context.fetch=async(path,opts)=>{requests.push({path,opts});return {ok:true,status:200,headers:{get(){return 'application/json';}},async json(){return {run_state:'blocked',reason:'Configure an engagement tariff.'};}};};
 h.state.autoActive=false;h.state.autoStarting=false;h.state.target='192.0.2.1';
 elements.get('user-input').value='  '+objective+'  ';
 let before=requests.length;
 await h.startAuto();
 assert.equal(requests.length,before+1,'Starting with an objective makes only the start request');
 let body=JSON.parse(requests.at(-1).opts.body);
 assert.equal(body.objective,objective,'Exact owner objective reaches autonomous start');
 assert.equal(body.target,'192.0.2.1');
 assert.equal(body.auto_risk_threshold,'green_only','Objective does not change approval policy');
 assert(elements.get('auto-log-lines').children.some(n=>n.children.some(c=>c.textContent==='Configure an engagement tariff.')),'Immediate blocked reason remains in activity log after toast expires');
 elements.get('user-input').value='  ';
 await h.startAuto();
 assert(!Object.hasOwn(JSON.parse(requests.at(-1).opts.body),'objective'),'Empty draft preserves backend default');
 elements.get('user-input').value='x'.repeat(2001);
 before=requests.length;await h.startAuto();
 assert.equal(requests.length,before,'Oversized objective cannot dispatch a start request');
 const typed='aria-tool '+Buffer.from(JSON.stringify({schema_version:1,tool:'nmap',parameters:{host:'192.0.2.1',ports:[22,80]}})).toString('base64url');
 const reviewed=h.commandForReview(typed);
 assert(reviewed.includes('nmap (typed operation)')&&reviewed.includes('192.0.2.1')&&reviewed.includes('22'),'Typed approval exposes the actual operation and scoped parameters');
 assert(reviewed.endsWith(typed),'Readable review retains the exact authorization binding');
 assert.equal(h.commandForReview('aria-tool invalid!'),'aria-tool invalid!','Malformed encoding remains visible without throwing');
 assert.equal(h.commandForReview('curl -I http://192.0.2.1'),'curl -I http://192.0.2.1');
 h.state.autoActive=true;h.handleAutoEvent({type:'waiting_approval',step:1,command:typed,action_id:'typed-action'});
 assert.equal(elements.get('auto-log-counter').textContent,'step 1 / 2','Approval step agrees with backend proposal count');
 assert.equal(elements.get('auto-label').textContent,'AUTONOMOUS — AWAITING APPROVAL');
 assert.equal(elements.get('approval-command').textContent,reviewed);
 assert.equal(elements.get('approval-approve').dataset.command,typed,'Review formatting never changes the command submitted for approval');
 context.fetch=async()=>({status:200,ok:true,headers:{get(){return 'application/json';}},async json(){return {pending:1};}});
 await h.stopAuto();
 assert(h.state.autoActive&&!elements.get('approval-banner').classList.contains('hidden'),'Pending worker termination cannot be shown as a completed stop');
 context.fetch=async()=>({status:200,ok:true,headers:{get(){return 'application/json';}},async json(){return {pending:0,status:'stopped'};}});
 await h.stopAuto();
 assert.equal(elements.get('auto-label').textContent,'AUTONOMOUS — STOPPED');
 assert(elements.get('approval-banner').classList.contains('hidden')&&h.state.pendingApprovals.length===0,'Confirmed cancellation removes stale approval controls');
 elements.get('user-input').value=objective;elements.get('auto-log-lines').textContent='old blocked run';
 context.fetch=async()=>({status:200,ok:true,headers:{get(){return 'application/json';}},async json(){return {status:'started'};}});
 await h.startAuto();
 assert.equal(elements.get('auto-log-lines').textContent,'','A new run clears previous activity');
 assert.equal(h.state.autoRunStatus,'');
 assert.equal(h.state.autoStep,0);
 context.fetch=async(path,opts)=>{requests.push({path,opts});return {status:200,ok:true,headers:{get(){return 'application/json';}},async json(){return {};}};};
 context.prompt=message=>message.startsWith('Target')?'192.0.2.1':'21,22,80,139,445,80';
 await h.createNewSession();
 const scoped=JSON.parse(requests.filter(r=>r.path==='/api/session/new').at(-1).opts.body);
 assert.deepEqual(scoped.scope,{targets:['192.0.2.1'],exclusions:[],ports:[21,22,80,139,445]},'Session UI persists the operator port restriction without selecting commands');
 for(const ports of ['0','65536','22,','22-80','80;curl',null]){
   context.prompt=message=>message.startsWith('Target')?'192.0.2.1':ports;
   const count=requests.filter(r=>r.path==='/api/session/new').length;
   await h.createNewSession();
   assert.equal(requests.filter(r=>r.path==='/api/session/new').length,count,'Invalid or cancelled port restriction cannot create a session');
 }
 const archive={zip:true};
 context.fetch=async(path,opts)=>{requests.push({path,opts});return {status:200,ok:true,async blob(){return archive;}};};
 assert.equal(await h.api('/api/report/s1/drafts/r1/export',{responseType:'blob'}),archive);
 assert.equal(requests.at(-1).opts.headers.Authorization,'Bearer test-token');
 context.fetch=async()=>({status:401});
 await h.api('/expired-session');
 assert.equal(storage.get('pentestai_token'),undefined);
 assert.equal(storage.get('current_session'),undefined);
 assert.equal(context.window.location.href,'/login.html');
 // An older run or an out-of-order delivery cannot terminate the current run.
 h.state.autoRunId='current-fixture-run';h.state.autoEventSequence=0;h.state.autoActive=true;
 h.handleAutoEvent({type:'auto_complete',status:'completed',run_id:'older-fixture-run',session_id:h.state.sessionId,event_sequence:9});
 assert.equal(h.state.autoActive,true,'A terminal event from another run is ignored');
 h.state.pendingApprovals=[];
 const waiting={type:'waiting_approval',status:'waiting_approval',run_id:'current-fixture-run',session_id:h.state.sessionId,event_sequence:2,action_id:'ordered-approval',command:'curl -I http://192.0.2.1',step:1};
 h.handleAutoEvent(waiting);h.handleAutoEvent(waiting);
 assert.equal(h.state.pendingApprovals.length,1,'Duplicate delivery does not duplicate approval controls');
 h.handleAutoEvent({type:'auto_complete',status:'completed',run_id:'current-fixture-run',session_id:h.state.sessionId,event_sequence:1});
 assert.equal(h.state.autoActive,true,'An older sequence cannot end the active run');
 h.handleAutoEvent({type:'auto_complete',status:'blocked',run_id:'current-fixture-run',session_id:h.state.sessionId,event_sequence:3});
 assert.equal(h.state.autoActive,false,'The current terminal transition is applied');
 h.state.autoRunId='before-new-start';h.state.autoEventSequence=0;h.state.autoActive=true;
 h.connectAutoWS();h.state.autoStarting=true;
 h.state.ws.onmessage({data:JSON.stringify({type:'auto_complete',status:'completed',run_id:'before-new-start',session_id:h.state.sessionId,event_sequence:1})});
 assert.equal(h.state.autoActive,true,'Old socket events cannot change a start in progress');
 h.state.autoStarting=false;
 // Multiple gap notifications share one read-only reconciliation request.
 await Promise.resolve();await Promise.resolve();
 h.state.autoReconciling=false;h.state.autoRunId='gap-run';h.state.autoEventSequence=0;
 let gapReads=0;let releaseGap;
 context.fetch=async()=>{gapReads++;return await new Promise(resolve=>{releaseGap=resolve;});};
 h.handleAutoEvent({type:'auto_activity',status:'running',action:'fixture',run_id:'gap-run',stream_gap:true,event_sequence:1});
 h.handleAutoEvent({type:'auto_activity',status:'running',action:'fixture',run_id:'gap-run',stream_gap:true,event_sequence:2});
 assert.equal(gapReads,1,'Gap notifications do not create an unbounded status request queue');
 releaseGap({ok:true,status:200,headers:{get(){return 'application/json';}},async json(){return {active:false,run_id:'gap-run',run_state:'blocked',event_sequence:2,reason:'Fixture prerequisite unavailable'};}});
 await new Promise(resolve=>setImmediate(resolve));
 assert.equal(h.state.autoActive,false,'Reconciliation restores actual blocked state');
 assert.equal(h.state.autoReconciling,false,'Reconciliation finishes without leaving a stuck flag');
 console.log('Frontend contracts, plan rendering, approval/rejection and socket authentication passed');
})().catch(e=>{console.error(e);process.exitCode=1;});
