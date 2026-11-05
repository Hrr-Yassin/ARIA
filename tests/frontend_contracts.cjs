// Execute the real client with a fake DOM, storage, worker API and WebSocket.
const fs = require('fs');
const vm = require('vm');
const assert = require('assert/strict');
const created = [];
function element() {
 const node={textContent:'',value:'',style:{},dataset:{},children:[],classList:{add(){},remove(){},toggle(){}},
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
 prompt(){return '192.0.2.1';},confirm(){return true;},setTimeout(){},setInterval(){},console,
 WebSocket:class {constructor(url){this.url=url;}send(data){this.sent=JSON.parse(data);}},
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
source=source.replace("document.addEventListener('DOMContentLoaded', boot);",'globalThis.testHooks={loadSessions,createNewSession,loadLLMKeys,connectAutoWS,sendMessage,runCommand,api,state};');
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
 context.fetch=async()=>({status:401});
 await h.api('/expired-session');
 assert.equal(storage.get('pentestai_token'),undefined);
 assert.equal(storage.get('current_session'),undefined);
 assert.equal(context.window.location.href,'/login.html');
 console.log('Frontend contracts, plan rendering, approval/rejection and socket authentication passed');
})().catch(e=>{console.error(e);process.exitCode=1;});
