// Exercise the real report UI: exact sign-off, literal evidence, and engagement isolation.
const fs=require('fs'),vm=require('vm'),assert=require('assert/strict');
class Element {
  constructor(tag='div'){this.tag=tag;this.children=[];this.textContent='';this.value='';this.checked=false;this.disabled=false;this.dataset={};this.handlers={};this.classes=new Set();
    this.classList={add:x=>this.classes.add(x),remove:x=>this.classes.delete(x),contains:x=>this.classes.has(x)};}
  appendChild(child){this.children.push(child);return child;}
  replaceChildren(...children){this.children=children;}
  addEventListener(event,handler){this.handlers[event]=handler;}
  querySelectorAll(){return this.children.flatMap(child=>[child,...child.querySelectorAll()]).filter(child=>child.tag==='input'&&child.checked);}
  async click(){if(this.handlers.click)return await this.handlers.click();}
}
const elements=new Map(),get=id=>{if(!elements.has(id))elements.set(id,new Element());return elements.get(id);};
const requests=[],downloads=[];
let active={sessionId:'s1',epoch:1}, signed=false, exportDeferred=null;
const report={id:'r1',revision:1,package_sha256:'f'.repeat(64),scope_digest:'a'.repeat(64),template:'bug_bounty',document:{findings:[{id:'f1',title:'Private object disclosure'}]}};
const saved=()=>({report_drafts:[report],report_signoffs:signed?[{report_id:'r1'}]:[],report_outcomes:[]});
async function api(path,opts={}) {
  requests.push({path,opts});
  if(path==='/api/team/s1/findings')return {findings:[{id:'f1',title:'Private object disclosure',state:'reportable',ready_for_external_submission:true},
    {id:'f2',title:'Unverified success page',state:'observation',ready_for_external_submission:false}]};
  if(path==='/api/report/s1/drafts'&&opts.method==='POST')return {data:report};
  if(path==='/api/report/s1/drafts')return saved();
  if(path.endsWith('/preview'))return {report,files:{'report.md':'<img src=x onerror=alert(1)> literal evidence','manifest.json':'{"complete":true}'},signed};
  if(path.endsWith('/signoff')){signed=true;return {data:{report_id:'r1'}};}
  if(path.endsWith('/export'))return exportDeferred?await exportDeferred.promise:{zip:true};
  if(path.endsWith('/triage-answer'))return {data:{text:'DRAFT: historical evidence, no request sent.'}};
  throw new Error('Unexpected request '+path);
}
const context={document:{getElementById:get,createElement:tag=>new Element(tag)},window:{},crypto:{randomUUID:()=> 'test-request-id'},
 URL:{createObjectURL:blob=>{downloads.push(blob);return 'blob:owned';},revokeObjectURL(){}},setTimeout(){}};
vm.createContext(context);vm.runInContext(fs.readFileSync('web/static/scripts/reports.js','utf8'),context);
(async()=>{
 context.window.AriaReports.init({api,getContext:()=>active});
 get('reports-template').value='bug_bounty';
 await get('reports-refresh').click();
 get('reports-candidates').children[0].children[0].checked=true;
 await get('reports-create').click();
 const created=requests.find(item=>item.opts.method==='POST'&&item.path.endsWith('/drafts'));
 assert.deepEqual(Array.from(created.opts.body.finding_ids),['f1']);
 assert.deepEqual(Array.from(created.opts.body.observation_ids),[]);
 assert.equal(get('reports-preview').children[0].textContent,'<img src=x onerror=alert(1)> literal evidence');
 await get('reports-signoff').click();
 assert(!requests.some(item=>item.path.endsWith('/signoff')),'No implicit human sign-off');
 for(const id of ['reports-reviewed','reports-reproduced','reports-redacted'])get(id).checked=true;
 get('reports-reason').value='Reproduced from report and checked redactions';
 await get('reports-signoff').click();
 const signoff=requests.find(item=>item.path.endsWith('/signoff'));
 assert.equal(signoff.opts.body.package_sha256,report.package_sha256);
 assert.equal(signoff.opts.body.reproduced_from_report,true);
 assert.equal(get('reports-signoff').disabled,true);
 await get('reports-export').click();
 assert.equal(downloads.length,1);
 assert.equal(requests.find(item=>item.path.endsWith('/export')).opts.responseType,'blob');
 get('reports-finding').value='f1';get('reports-triage-topic').value='impact';
 await get('reports-triage').click();
 assert.equal(get('reports-triage-preview').textContent,'DRAFT: historical evidence, no request sent.');
 let resolve;exportDeferred={promise:new Promise(done=>resolve=done)};
 const pending=get('reports-export').click();
 active={sessionId:'s2',epoch:2};context.window.AriaReports.reset();resolve({zip:true});await pending;
 assert.equal(downloads.length,1,'Do not download another engagement’s delayed export');
 assert.equal(get('reports-preview').children.length,0);
 assert(get('reports-signed-actions').classList.contains('hidden'));
 assert.equal(get('reports-reason').value,'');
 assert(!requests.some(item=>/execute|kali|worker|submit/.test(item.path)),'Reports never dispatch tools or submit externally');
 console.log('Report UI preview, exact human sign-off, binary export and stale engagement isolation passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
