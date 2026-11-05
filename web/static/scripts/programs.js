/* Owner-reviewed program research. Source text is always rendered as text. */
(function () {
'use strict';
const categories = ['included_assets','exclusions','eligible_issue_classes','account_requirements','automation_restrictions','prerequisites'];
const fitOptions = {
  technical_fit: ['unknown','good','partial','poor'],
  accessible_accounts: ['unknown','yes','no'], eligible_classes: ['unknown','yes','no'],
  automation_compatibility: ['unknown','yes','no'], research_cost: ['unknown','low','medium','high'],
  participation_eligibility: ['unknown','confirmed','ineligible'],
};
const labels = {included_assets:'Included assets',exclusions:'Exclusions (including third parties)',
  eligible_issue_classes:'Eligible issue classes: HTTP observation',account_requirements:'Account requirements',
  automation_restrictions:'Automation restrictions and traffic limits',prerequisites:'Participation prerequisites'};
function init({api, getContext}) {
  const $ = id => document.getElementById(id);
  if (!$('program-policy-panel')) return;
  let snapshot = null, reviewId = '', loadedSession = '', loadedEpoch = -1, generation = 0;
  const status = text => { $('program-status').textContent = text; };
  const node = (tag, text) => { const el = document.createElement(tag); el.textContent = text; return el; };
  const isCurrent = ctx => getContext().sessionId === ctx.sessionId && getContext().epoch === ctx.epoch;
  function context() {
    const current = getContext();
    if (!current.sessionId) throw new Error('Select or create an engagement first.');
    return current;
  }
  function currentSnapshot() {
    const ctx = context();
    if (!snapshot || (loadedSession !== ctx.sessionId || loadedEpoch !== ctx.epoch)) throw new Error('Load this engagement’s current policy first.');
    return snapshot;
  }
  function base(sid) { return '/api/programs/' + encodeURIComponent(sid); }
  async function refresh() {
    const ctx = context(), gen = ++generation;
    const [history, catalog] = await Promise.all([api(base(ctx.sessionId)+'/history'), api('/api/programs/catalog')]);
    if (!history || !catalog || gen !== generation || !isCurrent(ctx)) return;
    loadedSession = ctx.sessionId; loadedEpoch = ctx.epoch;
    const snapshots = history.history.filter(row => row.type === 'program_policy_snapshot');
    snapshot = snapshots.reduce((best,row) => !best || row.data.revision > best.revision ? row.data : best, null);
    const reviews = history.history.filter(row => row.type === 'program_policy_review' && snapshot && row.data.snapshot_id === snapshot.id);
    const latestReview = reviews[reviews.length-1];
    reviewId = latestReview && latestReview.data.decision === 'reviewed' ? latestReview.id : '';
    $('program-source').textContent = snapshot ? snapshot.source_text : 'No policy imported for this engagement.';
    const activation = history.history.filter(row => row.type === 'program_policy_activation').pop();
    status(snapshot ? `Revision ${snapshot.revision} · ${snapshot.program_type} · ${snapshot.source_url}\n`+
      `Retrieval: ${snapshot.retrieved_at || 'unknown'} · ${snapshot.content_sha256}\n`+
      (history.policy ? `Program policy: ${history.policy.state}. Requests: ${history.policy.requests_used}/${history.policy.request_limit ?? 'unset'}.`+(history.policy.overloaded ? ' Stopped after overload.' : '') : activation && activation.data.snapshot_id === snapshot.id ? 'Activation recorded; live execution checks scope and budgets.' : 'Draft/review only; this snapshot has no active testing permission.') : 'Import a policy to begin.');
    categories.forEach(category => {
      const rules = snapshot ? snapshot.rules[category] : [];
      $('program-quote-'+category).value = rules.length ? rules.map(rule=>rule.quote).join('\n') : '';
      $('program-interpretation-'+category).value = '';
    });
    // Clear confirmation and permissions when source or engagement is reloaded.
    ['accounts','prerequisites','permission'].forEach(key => { $('program-'+key).checked=false; });
    $('program-automation').value='unknown';
    $('program-assets').value=''; $('program-exclusions').value=''; $('program-third-party').value='';
    $('program-catalog').replaceChildren();
    catalog.programs.forEach(candidate => {
      const card = node('article','');
      card.appendChild(node('strong',candidate.name+' · '+candidate.program_type));
      card.appendChild(node('p',`Fit score ${candidate.score}/10. Unknown: ${candidate.unknown.join(', ') || 'none'}.`));
      card.appendChild(node('p','Participation: '+candidate.fit.participation_eligibility+'. '+candidate.fit.basis));
      card.appendChild(node('p','Prerequisites: '+(candidate.prerequisites.map(rule=>rule.quote).join('; ') || 'unknown')));
      card.appendChild(node('p',Object.entries(candidate.fit).filter(([key])=>key!=='basis').map(([key,value])=>key.replaceAll('_',' ')+': '+value).join(' · ')));
      $('program-catalog').appendChild(card);
    });
  }
  function guarded(id, action) {
    $(id).addEventListener('click',async () => {
      const button=$(id); button.disabled=true;
      const ctx=getContext();
      try { await action(); }
      catch(error) { if (isCurrent(ctx)) status(error.message || 'Policy operation failed.'); }
      finally { button.disabled=false; }
    });
  }
  categories.forEach(category => {
    const section=node('div',''); section.appendChild(node('h4',labels[category]));
    [['quote','Exact source excerpt (missing rules remain unknown)'],['interpretation','Your interpretation']].forEach(([key,label])=>{
      const container=node('label',label), input=document.createElement('textarea');
      input.id='program-'+key+'-'+category; input.rows=3; container.appendChild(input); section.appendChild(container);
    });
    $('program-rule-review').appendChild(section);
  });
  Object.entries(fitOptions).forEach(([key,values])=>{
    const label=node('label',key.replaceAll('_',' ')), select=document.createElement('select');
    select.id='program-fit-'+key;
    values.forEach(value=>{const option=node('option',value);option.value=value;select.appendChild(option);});
    label.appendChild(select);$('program-fit-fields').appendChild(label);
  });
  $('program-policy-panel').addEventListener('input', event => {
    if (event.target.id && !event.target.id.startsWith('program-fit-')) reviewId='';
  });
  guarded('program-refresh',refresh);
  ['text','page'].forEach(method=>guarded('program-import-'+method,async()=>{
    const ctx=context();
    const body={name:$('program-name').value,source_url:$('program-url').value,program_type:$('program-type').value};
    if(method==='text') body.text=$('program-text').value;
    const result=await api(base(ctx.sessionId)+'/import-'+method,{method:'POST',body});
    if(result && isCurrent(ctx)) await refresh();
  }));
  function reviewedRules() {
    const source=currentSnapshot();
    return categories.map(category=>{
      const quote=$('program-quote-'+category).value, interpretation=$('program-interpretation-'+category).value;
      if(!quote || !interpretation) throw new Error('Provide an exact source excerpt and interpretation for every permission category.');
      const start=source.source_text.indexOf(quote);
      if(start<0) throw new Error('A source excerpt does not match the imported text.');
      return {category,quote,start,interpretation};
    });
  }
  function assets(id,sourceRule) {
    return $(id).value.split('\n').filter(line=>line.trim()).map(line=>{
      const pieces=line.split('|').map(piece=>piece.trim());
      if(pieces.length!==4) throw new Error('Each asset needs hostname | path | ports | schemes.');
      return {host:pieces[0],path:pieces[1],ports:pieces[2].split(',').map(Number),schemes:pieces[3].split(',').map(x=>x.trim()),source_rule:sourceRule};
    });
  }
  async function saveReview(decision) {
    const ctx=context(), source=currentSnapshot();
    const rules=decision==='reviewed'?reviewedRules():[];
    const execution=decision==='reviewed'?{
      assets:assets('program-assets',0),exclusions:assets('program-exclusions',1),third_party_exclusions:assets('program-third-party',1),
      automation:$('program-automation').value,accounts_confirmed:$('program-accounts').checked,
      prerequisites_confirmed:$('program-prerequisites').checked,permission_confirmed:$('program-permission').checked,
      eligible_classes:['http_observation'],max_requests:Number($('program-requests').value),
      concurrency:Number($('program-concurrency').value),min_interval_seconds:Number($('program-interval').value),
      automation_source_rule:4,budget_source_rule:4,accounts_source_rule:3,prerequisites_source_rule:5,classes_source_rule:2,exclusions_source_rule:1,
    }:null;
    const result=await api(base(ctx.sessionId)+'/'+source.id+'/review',{method:'POST',body:{
      content_sha256:source.content_sha256,rules,decision,note:$('program-note').value,execution,
    }});
    if(result && isCurrent(ctx)) {
      reviewId=decision==='reviewed'?result.id:'';
      status(decision==='reviewed'?'Human review saved. Explicit activation is still required.':'Policy rejected.');
    }
  }
  guarded('program-review',()=>saveReview('reviewed'));
  guarded('program-reject',()=>saveReview('rejected'));
  guarded('program-activate',async()=>{
    const ctx=context(), source=currentSnapshot();
    if(!reviewId) throw new Error('Save an explicit review before activation.');
    if(!window.confirm('Activate this reviewed policy and replace the engagement execution scope?')) return;
    const result=await api(base(ctx.sessionId)+'/'+source.id+'/activate',{method:'POST',body:{review_id:reviewId,confirm:true}});
    if(result && isCurrent(ctx)) status('Policy activated. Only scoped, budgeted curl GET/HEAD observations are enabled.');
  });
  guarded('program-fit-save',async()=>{
    const ctx=context(), source=currentSnapshot(), body={basis:$('program-fit-basis').value};
    Object.keys(fitOptions).forEach(key=>{body[key]=$('program-fit-'+key).value;});
    const result=await api(base(ctx.sessionId)+'/'+source.id+'/fit',{method:'POST',body});
    if(result && isCurrent(ctx)) await refresh();
  });
}
window.AriaPrograms={init};
})();
