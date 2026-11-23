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
  let quotes={};
  function tariffState() {
    const provider=$('team-model-provider').value,model=$('team-model-name').value.trim();
    const quote=quotes[model];
    const valid=provider!=='openrouter'||(quote&&quote.provider===provider&&Date.parse(quote.expires_at)>Date.now());
    if($('team-effective-tariff'))$('team-effective-tariff').textContent=provider==='openrouter'?
      (valid?`${model} via ${quote.endpoint}: input $${Number(quote.input_usd_per_million)}/M; output $${Number(quote.output_usd_per_million)}/M. Conservative reservation $${quote.microusd_per_million/1000000}/M. Expires ${quote.expires_at}`:
        'Pricing unavailable or expired. Verify the OpenRouter key and refresh tariff before approval.'):'Owner-entered conservative tariff.';
    $('team-model-rate').readOnly=provider==='openrouter';
    if(provider==='openrouter'&&valid)$('team-model-rate').value=quote.microusd_per_million/1000000;
    $('team-save-budget').disabled=!valid;
  }
  window.AriaTeam.reset=()=>{
    generation+=1;loaded=null;
    quotes={};
    if($('team-effective-tariff'))$('team-effective-tariff').textContent='Load engagement pricing before approval.';
    if($('team-budget-approval'))$('team-budget-approval').textContent='';
    for(const key of ['tasks','evidence','knowledge','coverage'])$('team-'+key).replaceChildren();
    if($('team-research'))$('team-research').replaceChildren();
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
    const [view,budget,research]=await Promise.all([api(base(ctx)),api(base(ctx)+'/model-budget'),api(base(ctx)+'/research')]);
    if (!view||!budget||!same(ctx)||gen!==generation) return;
    loaded={ctx,view,budget};
    if($('team-research')&&research) {
      const panel=$('team-research');panel.replaceChildren();
      const model=research.application_model||{};
      panel.appendChild(textNode('p',`Application model: ${(model.nodes||[]).length} entities, ${(model.edges||[]).length} relationships. ${research.application_model_current===false?'Context changed; revalidation required.':'Evidence-linked assertions.'}`));
      (research.hypotheses||[]).forEach(item=>{
        const card=textNode('article','');card.className='team-card';
        card.appendChild(textNode('strong',`${item.state} · ${item.title}`));
        card.appendChild(textNode('p',`Priority ${item.priority}; confidence ${item.confidence}. ${item.confirmed?'Independently verified with human signoff.':item.context_current?'Unverified research.':'Context changed; revalidation required.'}`));
        card.appendChild(textNode('p',item.claim));
        card.appendChild(textNode('pre',JSON.stringify({evidence:item.supporting_evidence,
          alternatives:item.alternative_explanations,prerequisites:item.prerequisites,
          strategy:item.validation_strategy,positive_controls:item.positive_controls,
          negative_controls:item.negative_controls,uncertainty:item.uncertainty,history:item.history},null,2)));
        panel.appendChild(card);
      });
      if(!(research.hypotheses||[]).length)panel.appendChild(textNode('p','No persistent hypotheses recorded for this engagement.'));
    }
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
    quotes=budget.tariff_quotes||{};
    const selection=budget.configured_selection;
    const tariff=budget.limits.tariffs.find(t=>selection&&t.provider===selection.provider&&t.model===selection.model)||budget.limits.tariffs[0];
    $('team-model-provider').value=selection?selection.provider:tariff?tariff.provider:'openrouter';
    $('team-model-name').value=selection?selection.model:tariff?tariff.model:'';
    $('team-model-rate').value=tariff?tariff.microusd_per_million/1000000:'';
    const approvalCurrent=budget.approved_at&&budget.limits.tariffs.every(t=>t.provider!=='openrouter'||
      (quotes[t.model]?.id===t.quote_id&&Date.parse(quotes[t.model].expires_at)>Date.now()));
    if($('team-budget-approval'))$('team-budget-approval').textContent=approvalCurrent?
      `Saved approval: $${(budget.limits.max_cost_microusd/1000000).toFixed(2)} ceiling (${budget.approved_at}).`:
      'Pending owner approval. Displayed limits are proposals; no hosted spending is authorized.';
    tariffState();
  }
  function guarded(id,action) {
    $(id).addEventListener('click',async()=>{
      const button=$(id),ctx=getContext();button.disabled=true;
      try{await action();}catch(error){if(same(ctx))status(error.message||'Team operation failed.');}
      finally{button.disabled=false;if(id==='team-save-budget')tariffState();}
    });
  }
  async function change(path,body,method) {
    const ctx=context();
    const response=await send(ctx,path,body,method);
    if(response&&same(ctx))await refresh();
  }
  guarded('team-refresh',refresh);
  if($('team-refresh-tariff'))guarded('team-refresh-tariff',async()=>{
    const ctx=context();status('Verifying key and retrieving current pricing…');
    const quote=await send(ctx,'/model-tariff/refresh',{});
    if(quote&&same(ctx)){await refresh();status('Tariff verified and saved. Owner approval is still required.');}
  });
  for(const id of ['team-model-provider','team-model-name'])$(id).addEventListener('change',tariffState);
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
  guarded('team-save-budget',async()=>{
    const ctx=context();
    status('Saving spending approval…');
    const saved=await api(base(ctx)+'/model-budget');
    if(!saved||!same(ctx))return;
    let tariffs=saved.limits.tariffs;
    const provider=$('team-model-provider').value,model=$('team-model-name').value.trim();
    if(model) tariffs=[...tariffs.filter(t=>t.provider!==provider||t.model!==model),
      {provider,model,microusd_per_million:Math.ceil(Number($('team-model-rate').value)*1000000),
        ...(provider==='openrouter'?{quote_id:quotes[model]?.id}:{})}];
    if(!model)throw new Error('Enter the exact configured model and tariff before approving spending.');
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
