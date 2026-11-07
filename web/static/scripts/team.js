/* Durable team workspace. Render all source/model text with textContent. */
(function () {
'use strict';
function init({api, getContext}) {
  const $ = id => document.getElementById(id);
  if (!$('team-panel')) return;
  const status = text => { $('team-status').textContent=text; };
  const textNode=(tag,text)=>{const el=document.createElement(tag);el.textContent=text;return el;};
  const list=id=>$(id).value.split(/[\n,]/).map(x=>x.trim()).filter(Boolean);
  const requestId=()=>crypto.randomUUID();
  let generation=0, loaded=null;
  window.AriaTeam.reset=()=>{
    generation+=1;loaded=null;
    for(const key of ['tasks','evidence','knowledge','coverage'])$('team-'+key).replaceChildren();
    $('team-model-usage').textContent='';
    for(const id of ['objective','dependencies','evidence-inputs','source-id','knowledge-text','knowledge-refs',
      'uncertainty','contradicts','coverage-key','question','feature','gap','coverage-refs',
      'model-calls','model-tokens','model-cost','model-name','model-rate'])$('team-'+id).value='';
    status('Load this engagement’s saved team work.');
  };
  function context() {
    const ctx=getContext();
    if (!ctx.sessionId) throw new Error('Select an engagement first.');
    return ctx;
  }
  const same=ctx=>{const now=getContext();return ctx.sessionId===now.sessionId&&ctx.epoch===now.epoch;};
  const base=ctx=>'/api/team/'+encodeURIComponent(ctx.sessionId);
  async function send(ctx,path,body,method='POST') {
    return api(base(ctx)+path,{method,body});
  }
  async function refresh() {
    const ctx=context(), gen=++generation;
    const [view,budget]=await Promise.all([api(base(ctx)),api(base(ctx)+'/model-budget')]);
    if (!view||!budget||!same(ctx)||gen!==generation) return;
    loaded={ctx,view,budget};
    status('Saved event '+view.cursor+'. Results need human review; proposed commands use the existing execution workflow.');
    $('team-tasks').replaceChildren();
    view.tasks.forEach(task=>{
      const card=textNode('article','');card.className='team-card';
      card.appendChild(textNode('strong',task.owner_role+' · '+task.state+' · '+task.objective));
      card.appendChild(textNode('p','Task ID: '+task.id));
      card.appendChild(textNode('p','Expected: '+task.expected_output+' · Criteria: '+task.completion_criteria.join('; ')));
      if(task.reason)card.appendChild(textNode('p',task.reason));
      if(task.result) card.appendChild(textNode('pre',JSON.stringify(task.result,null,2)));
      const actions=task.state==='queued'?['run','cancelled']:task.state==='awaiting_review'?['completed','blocked','cancelled']:task.state==='running'?['cancelled']:task.state==='blocked'?['queued','cancelled']:[];
      actions.forEach(action=>{
        const button=textNode('button',({run:'Delegate analysis',completed:'Mark reviewed and complete',blocked:'Request more work',queued:'Queue after review',cancelled:'Cancel task'})[action]);
        button.className='btn btn-ghost';
        button.addEventListener('click',async()=>{
          if(!same(ctx))return;
          button.disabled=true;
          try {
            let response;
            if(action==='run') response=await send(ctx,'/tasks/'+task.id+'/run',{request_id:requestId()});
            else {
              const reason=window.prompt('Record your review or reason:');
              if(!reason)return;
              response=await send(ctx,'/tasks/'+task.id+'/transition',{request_id:requestId(),expected_revision:task.revision,state:action,reason});
            }
            if(response&&same(ctx))await refresh();
          } catch(error){if(same(ctx))status(error.message);}
          finally{button.disabled=false;}
        });
        card.appendChild(button);
      });
      $('team-tasks').appendChild(card);
    });
    for(const key of ['evidence','knowledge','coverage']) {
      $('team-'+key).replaceChildren();
      view[key].forEach(item=>$('team-'+key).appendChild(textNode('pre',JSON.stringify(item,null,2))));
    }
    $('team-model-usage').textContent=JSON.stringify(budget,null,2);
    $('team-model-calls').value=budget.limits.max_calls;
    $('team-model-tokens').value=budget.limits.max_tokens;
    $('team-model-cost').value=budget.limits.max_cost_microusd/1000000;
    const tariff=budget.limits.tariffs[0];
    $('team-model-provider').value=tariff?tariff.provider:'groq';
    $('team-model-name').value=tariff?tariff.model:'';
    $('team-model-rate').value=tariff?tariff.microusd_per_million/1000000:'';
  }
  function guarded(id,action) {
    $(id).addEventListener('click',async()=>{
      const button=$(id),ctx=getContext();button.disabled=true;
      try{await action();}catch(error){if(same(ctx))status(error.message||'Team operation failed.');}
      finally{button.disabled=false;}
    });
  }
  async function change(path,body,method) {
    const ctx=context();
    const response=await send(ctx,path,body,method);
    if(response&&same(ctx))await refresh();
  }
  guarded('team-refresh',refresh);
  guarded('team-create',()=>change('/tasks',{request_id:requestId(),task:{
    owner_role:$('team-role').value,objective:$('team-objective').value,
    expected_output:$('team-expected').value,completion_criteria:list('team-criteria'),
    evidence_inputs:list('team-evidence-inputs'),dependencies:list('team-dependencies'),
  }}));
  guarded('team-catalog',()=>change('/evidence',{request_id:requestId(),source_kind:$('team-source-kind').value,source_id:$('team-source-id').value}));
  guarded('team-save-knowledge',()=>change('/knowledge',{request_id:requestId(),kind:$('team-knowledge-kind').value,
    text:$('team-knowledge-text').value,evidence_references:list('team-knowledge-refs'),
    uncertainty:$('team-uncertainty').value,disposition:$('team-disposition').value,contradicts:list('team-contradicts')}));
  guarded('team-save-coverage',()=>change('/coverage',{request_id:requestId(),key:$('team-coverage-key').value,
    question:$('team-question').value,feature:$('team-feature').value,status:$('team-coverage-state').value,
    gap_reason:$('team-gap').value,evidence_references:list('team-coverage-refs')}));
  guarded('team-save-budget',()=>{
    const ctx=context();
    if(!loaded||!same(loaded.ctx))throw new Error('Load this engagement’s saved model budget first.');
    let tariffs=loaded.budget.limits.tariffs;
    const provider=$('team-model-provider').value,model=$('team-model-name').value.trim();
    if(model) tariffs=[...tariffs.filter(t=>t.provider!==provider||t.model!==model),
      {provider,model,microusd_per_million:Math.ceil(Number($('team-model-rate').value)*1000000)}];
    return change('/model-budget',{max_calls:Number($('team-model-calls').value),
      max_tokens:Number($('team-model-tokens').value),max_cost_microusd:Math.floor(Number($('team-model-cost').value)*1000000),tariffs},'PUT');
  });
  // Poll persisted events only. Cursor/generation checks suppress stale engagement responses.
  setInterval(async()=>{
    if(!loaded||!same(loaded.ctx)||!$('settings-panel')||$('settings-panel').classList.contains('hidden'))return;
    const ctx=loaded.ctx;
    try{
      const update=await api(base(ctx)+'/events?after='+loaded.view.cursor);
      if(update&&same(ctx)&&update.events.length)await refresh();
    }catch(error){if(same(ctx))status('Event refresh failed. Reload saved team work to retry.');}
  },5000);
}
window.AriaTeam={init};
})();
