// Regression: approval must work without first clicking Load saved team work.
const vm=require('node:vm'),fs=require('node:fs'),assert=require('node:assert/strict');
const nodes=new Map();
function node(id){if(!nodes.has(id))nodes.set(id,{value:'',textContent:'',disabled:false,addEventListener(type,fn){this[type]=fn;}});return nodes.get(id);}
const requests=[];
const budget={limits:{tariffs:[{provider:'groq',model:'kept',microusd_per_million:10}]}};
const context={document:{getElementById:node},window:{},setInterval(){},crypto:{randomUUID(){return 'id';}}};
vm.createContext(context);vm.runInContext(fs.readFileSync('web/static/scripts/team.js','utf8'),context);
context.window.AriaTeam.init({getContext:()=>({sessionId:'owned',epoch:1}),api:async(path,opts)=>{
 requests.push({path,opts});if(!opts&&path.endsWith('/model-budget'))return budget;return null;
}});
for(const [id,value] of Object.entries({'model-provider':'openrouter','model-name':'deepseek/deepseek-v4-flash','model-rate':'0.18','model-cost':'2','model-tokens':'200000','model-calls':'20'}))node('team-'+id).value=value;
(async()=>{await node('team-save-budget').click();const put=requests.find(r=>r.opts?.method==='PUT');assert.ok(put);assert.equal(put.opts.body.max_cost_microusd,2000000);assert.equal(put.opts.body.tariffs.length,2);assert.equal(put.opts.body.tariffs[1].microusd_per_million,180000);console.log('Budget click works without prior load and preserves tariffs');})().catch(e=>{console.error(e);process.exitCode=1;});
