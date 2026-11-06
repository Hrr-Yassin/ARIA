/* Evidence-bound reports. All target and researcher text is displayed literally. */
(function () {
'use strict';
function init({api, getContext}) {
  const $=id=>document.getElementById(id);
  if(!$('reports-panel'))return;
  let generation=0, preview=null, listing=null;
  const node=(tag,text)=>{const value=document.createElement(tag);value.textContent=text;return value;};
  const same=ctx=>{const now=getContext();return now.sessionId===ctx.sessionId&&now.epoch===ctx.epoch;};
  const status=text=>{$('reports-status').textContent=text;};
  const base=ctx=>'/api/report/'+encodeURIComponent(ctx.sessionId)+'/drafts';
  const context=()=>{const ctx=getContext();if(!ctx.sessionId)throw new Error('Select an engagement first.');return ctx;};
  const list=id=>$(id).value.split(/[\n,]/).map(value=>value.trim()).filter(Boolean);
  function clearPreview() {
    preview=null;
    $('reports-preview').replaceChildren();
    $('reports-actions').classList.add('hidden');
    $('reports-signed-actions').classList.add('hidden');
    for(const id of ['reports-reviewed','reports-reproduced','reports-redacted'])$(id).checked=false;
    for(const id of ['reports-reason','reports-platform','reports-outcome-note','reports-amount','reports-currency',
      'reports-retest-refs','reports-retest-reason'])$(id).value='';
    $('reports-finding').replaceChildren();
    $('reports-triage-preview').textContent='';
  }
  window.AriaReports.reset=()=>{
    generation+=1;listing=null;clearPreview();
    $('reports-candidates').replaceChildren();$('reports-drafts').replaceChildren();
    $('reports-previous').value='';status('Load this engagement’s verified findings and saved report drafts.');
  };
  function action(id, handler) {
    $(id).addEventListener('click',async()=>{
      const button=$(id);button.disabled=true;let ctx;
      try{ctx=context();await handler(ctx);}catch(error){if(!ctx||same(ctx))status(error.message||'Report operation failed.');}
      finally{button.disabled=id==='reports-signoff'&&Boolean(preview&&preview.result.signed);}
    });
  }
  async function openPreview(ctx, reportId) {
    const version=++generation;
    clearPreview();
    const result=await api(base(ctx)+'/'+encodeURIComponent(reportId)+'/preview');
    if(!result||!same(ctx)||version!==generation)return;
    clearPreview();preview={ctx,result};
    $('reports-preview').appendChild(node('pre',result.files['report.md']));
    $('reports-preview').appendChild(node('pre','Package SHA-256: '+result.report.package_sha256));
    for(const [path,text] of Object.entries(result.files)) {
      if(path==='report.md')continue;
      const details=node('details','');details.appendChild(node('summary',path));details.appendChild(node('pre',text));
      $('reports-preview').appendChild(details);
    }
    for(const finding of result.report.document.findings) {
      const option=node('option',finding.title);option.value=finding.id;$('reports-finding').appendChild(option);
    }
    $('reports-signoff').disabled=result.signed;
    if(result.signed){
      $('reports-signed-actions').classList.remove('hidden');
      if(result.signoff)$('reports-preview').appendChild(node('p','Signed by '+result.signoff.actor+': '+result.signoff.review.reason));
    } else $('reports-actions').classList.remove('hidden');
    status('Preview revision '+result.report.revision+'. '+(result.signed?'Signed; export rechecks current evidence.':'Inspect the full report and attachments before signing.'));
  }
  async function refresh(ctx) {
    const version=++generation;
    const [findings,saved]=await Promise.all([
      api('/api/team/'+encodeURIComponent(ctx.sessionId)+'/findings'),api(base(ctx))]);
    if(!findings||!saved||!same(ctx)||version!==generation)return;
    clearPreview();listing={ctx,findings:findings.findings,saved,recommendations:new Map()};
    $('reports-candidates').replaceChildren();$('reports-drafts').replaceChildren();
    for(const finding of findings.findings) {
      const label=node('label','');const input=node('input','');input.type='checkbox';input.value=finding.id;
      input.dataset.verified=String(finding.ready_for_external_submission);
      label.appendChild(input);label.appendChild(node('span',finding.title+' · '+(finding.ready_for_external_submission?'verified finding':'unverified observation ('+finding.state+')')));
      $('reports-candidates').appendChild(label);
      if(finding.ready_for_external_submission) {
        const details=node('details','');details.appendChild(node('summary','Priority and remediation recommendation'));
        const priority=node('select','');
        for(const value of ['unrated','critical','high','medium','low','info']) {
          const option=node('option',value);option.value=value;priority.appendChild(option);
        }
        priority.value='unrated';
        const remediation=node('textarea','');remediation.rows=3;
        remediation.value='Enforce server-side object authorization on every read; verify owner and outsider controls.';
        const priorityLabel=node('label','Priority (human recommendation)');priorityLabel.appendChild(priority);
        const remediationLabel=node('label','Remediation recommendation');remediationLabel.appendChild(remediation);
        details.appendChild(priorityLabel);details.appendChild(remediationLabel);$('reports-candidates').appendChild(details);
        listing.recommendations.set(finding.id,{priority,remediation});
      }
    }
    const signed=new Set(saved.report_signoffs.map(item=>item.report_id));
    for(const report of saved.report_drafts) {
      const card=node('article','');card.className='team-card';
      card.appendChild(node('strong',report.template+' · revision '+report.revision+' · '+(signed.has(report.id)?'signed':'awaiting report review')));
      card.appendChild(node('p',report.id));
      const button=node('button','Open preview');button.className='btn btn-ghost';
      button.addEventListener('click',async()=>{
        if(!same(ctx))return;button.disabled=true;
        try{await openPreview(ctx,report.id);}catch(error){if(same(ctx))status(error.message);}
        finally{button.disabled=false;}
      });
      card.appendChild(button);
      const outcome=saved.report_outcomes.find(item=>item.report_id===report.id);
      if(outcome)card.appendChild(node('pre',JSON.stringify(outcome,null,2)));
      $('reports-drafts').appendChild(card);
    }
    status('Loaded '+findings.findings.length+' candidates and '+saved.report_drafts.length+' report revisions. Submission remains your action.');
  }
  function selectedPreview(ctx) {
    if(!preview||!same(preview.ctx)||!same(ctx))throw new Error('Open a current report preview first.');
    return preview.result;
  }
  action('reports-refresh',refresh);
  action('reports-create',async ctx=>{
    if(!listing||!same(listing.ctx))throw new Error('Load verified findings first.');
    const inputs=Array.from($('reports-candidates').querySelectorAll('input:checked'));
    const result=await api(base(ctx),{method:'POST',body:{request_id:crypto.randomUUID(),
      template:$('reports-template').value,
      finding_ids:inputs.filter(input=>input.dataset.verified==='true').map(input=>input.value),
      observation_ids:inputs.filter(input=>input.dataset.verified!=='true').map(input=>input.value),
      recommendations:inputs.filter(input=>input.dataset.verified==='true').map(input=>{
        const recommendation=listing.recommendations.get(input.value);
        return {finding_id:input.value,priority:recommendation.priority.value,remediation:recommendation.remediation.value};
      }),
      previous_report_id:$('reports-previous').value.trim()||null}});
    if(result&&same(ctx)){await refresh(ctx);if(same(ctx))await openPreview(ctx,result.data.id);}
  });
  action('reports-signoff',async ctx=>{
    const value=selectedPreview(ctx);
    if(!['reports-reviewed','reports-reproduced','reports-redacted'].every(id=>$(id).checked))
      throw new Error('Confirm report review, reproduction from this report, and credential redaction.');
    const result=await api(base(ctx)+'/'+value.report.id+'/signoff',{method:'POST',body:{request_id:crypto.randomUUID(),
      package_sha256:value.report.package_sha256,human_review:true,reproduced_from_report:true,redactions_reviewed:true,
      reason:$('reports-reason').value}});
    if(result&&same(ctx)){await refresh(ctx);if(same(ctx))await openPreview(ctx,value.report.id);}
  });
  action('reports-export',async ctx=>{
    const value=selectedPreview(ctx);
    if(!value.signed)throw new Error('Sign this exact report revision before export.');
    const blob=await api(base(ctx)+'/'+value.report.id+'/export',{responseType:'blob'});
    if(!blob||!same(ctx))return;
    const url=URL.createObjectURL(blob),link=node('a','');link.href=url;link.download='aria-report-'+value.report.id+'.zip';link.click();
    setTimeout(()=>URL.revokeObjectURL(url),1000);status('Downloaded the signed report package. Nothing was submitted externally.');
  });
  action('reports-outcome',async ctx=>{
    const value=selectedPreview(ctx);
    const saved=await api(base(ctx));if(!saved||!same(ctx))return;
    const previous=saved.report_outcomes.find(item=>item.report_id===value.report.id);
    const state=$('reports-outcome-state').value;
    const result=await api(base(ctx)+'/'+value.report.id+'/outcomes',{method:'POST',body:{request_id:crypto.randomUUID(),
      expected_revision:previous?previous.revision:0,status:state,external_action_recorded:true,
      platform_reference:$('reports-platform').value,note:$('reports-outcome-note').value,
      amount:state==='paid'?$('reports-amount').value:null,currency:state==='paid'?$('reports-currency').value:null}});
    if(result&&same(ctx))status('Recorded '+state+' as a human-reported platform outcome.');
  });
  action('reports-retest',async ctx=>{
    const value=selectedPreview(ctx);
    const result=await api(base(ctx)+'/'+value.report.id+'/retests',{method:'POST',body:{request_id:crypto.randomUUID(),
      finding_id:$('reports-finding').value,expected_scope_digest:value.report.scope_digest,
      result:$('reports-retest-result').value,evidence_references:list('reports-retest-refs'),human_review:true,
      rationale:$('reports-retest-reason').value}});
    if(result&&same(ctx)){clearPreview();status('Recorded the saved retest. Create a new report revision to include it. No test was run.');}
  });
  action('reports-triage',async ctx=>{
    const value=selectedPreview(ctx);
    const result=await api(base(ctx)+'/'+value.report.id+'/triage-answer',{method:'POST',body:{request_id:crypto.randomUUID(),
      finding_id:$('reports-finding').value,topic:$('reports-triage-topic').value}});
    if(result&&same(ctx)){$('reports-triage-preview').textContent=result.data.text;status('Saved a triage reply draft. Review it before sending manually.');}
  });
}
window.AriaReports={init};
})();
