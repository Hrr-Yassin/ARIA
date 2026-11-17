"""One owner-approved HEAD observation through real shared authorization/worker.

Prepare a concrete pending proposal first. Execution requires a subsequently
recorded explicit owner decision;never infer approval from time or a model.
"""
from __future__ import annotations

import argparse
import asyncio
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import time

COMMAND='curl -I -s --max-time 10 http://192.168.77.20:80/'
ROOT=Path(__file__).resolve().parents[1]


def validate_owner_approval(value: dict, proposal_id: str, command: str) -> None:
    if (not isinstance(value,dict) or value.get('source')!='explicit_project_owner_reply_in_conversation'
            or value.get('proposal_id')!=proposal_id or value.get('command')!=command
            or value.get('approved') is not True or type(value.get('maximum_submissions')) is not int
            or value['maximum_submissions']!=1 or not isinstance(value.get('owner_reply'),str)
            or not value['owner_reply'].strip()):
        raise PermissionError('Fresh explicit command-bound owner approval required')
    received=datetime.fromisoformat(value['received_at'])
    if received.tzinfo is None or not 0 <= (datetime.now(timezone.utc)-received).total_seconds() <= 600:
        raise PermissionError('Owner approval record is absent or stale')


async def main(args) -> int:
    from memory.execution_authorization import execution_authorization
    from memory.worker_jobs import worker_jobs
    from llm.engagement_budget import model_accounting
    from memory.database_models import engine
    from orchestrator.worker_preflight import worker_preflight
    from evaluation.agent_intelligence import digest
    args.output.mkdir(mode=0o700,parents=True,exist_ok=True)
    state_path=args.output/'pending-proposal.json'
    result_path=args.output/'result.json'
    identity=json.loads((ROOT/'.local-lab/operational-reliability/resume-cycle21/intelligence-model-admission.json').read_text())
    sid,owner=identity['session_id'],identity['owner_id']
    try:
        context=await execution_authorization._context(owner,sid)
        checked=execution_authorization._validate(COMMAND,context,'curl')
        caps=await worker_jobs.client.capabilities()
        compatibility=worker_preflight(checked.command,context['scope'],caps)
        if compatibility['status']!='compatible':raise RuntimeError('Worker compatibility not established')
        seed=json.loads((ROOT/'.local-lab/operational-reliability/intelligence-v2/local-qwen08b-v1/run.json').read_text())
        candidate=next(c for c in seed['cases'] if c['case_id']=='recon-http')
        if not candidate.get('actual_model_success'):raise RuntimeError('Actual model proposal unavailable')
        evidence={'model':seed['model'],'case_id':candidate['case_id'],'response_sha256':digest(candidate),
            'operator_correction':'HEAD and explicit ten-second deadline added to the model GET candidate',
            'model_quality_verified':False,'independent_senior_comparison':'BLOCKED'}
        if args.mode=='inspect':
            pending=json.loads(state_path.read_text()) if state_path.exists() else None
            value={'status':'REVIEWABLE','command':checked.command,'worker_compatibility':compatibility,
                'target_submissions':0,'new_model_calls':0,'model_provenance':evidence,
                'pending_proposal':pending,'owner_approval_required':True}
            (args.output/'preflight.json').write_text(json.dumps(value,indent=2)+'\n')
            print(json.dumps(value));return 0
        if args.mode=='prepare':
            if state_path.exists() or result_path.exists():raise RuntimeError('Retain existing attempt;never renew automatically')
            proposal=await execution_authorization.propose(owner,sid,checked.command,'curl',
                require_approval=True,turn_id='p13-supervised-head')
            assert proposal.status=='pending'
            value={'recorded_at':datetime.now(timezone.utc).isoformat(),'proposal':asdict(proposal),
                'model_provenance':evidence,'maximum_submissions':1,'new_model_calls':0,'target_submissions':0}
            state_path.write_text(json.dumps(value,indent=2)+'\n')
            print(json.dumps({'status':'PENDING_OWNER_APPROVAL','proposal_id':proposal.id,
                'command':proposal.command,'expires_at':proposal.expires_at,'target_submissions':0}));return 0
        if not args.approval or not args.approval.is_file():raise PermissionError('Owner decision is missing')
        if result_path.exists():raise RuntimeError('A result already exists;inspect it instead of replaying')
        state=json.loads(state_path.read_text());proposal=state['proposal']
        validate_owner_approval(json.loads(args.approval.read_text()),proposal['id'],checked.command)
        current=await execution_authorization.store.get(proposal['id'])
        if not current or current.status!='pending' or current.expires_at<=time.time():
            raise PermissionError('Proposal expired or no longer pending;no automatic renewal')
        before=await model_accounting.status(sid,owner)
        start=time.monotonic()
        result={'status':'IN_PROGRESS','started_at':datetime.now(timezone.utc).isoformat(),
            'proposal_id':current.id,'command':checked.command,'maximum_submissions':1,
            'model_provenance':evidence,'new_model_calls':0}
        result_path.write_text(json.dumps(result,indent=2)+'\n')
        await execution_authorization.decide(owner,sid,current.id,'approve')
        output=await execution_authorization.execute(owner,sid,checked.command,'curl',
            action_id=current.id,timeout=10)
        stdout,stderr=output.get('stdout',''),output.get('stderr','')
        exit_code=output.get('exit_code')
        assert type(exit_code) is int and output.get('job_id')==current.id
        await worker_jobs.verify_receipt(owner,sid,current.id,stdout,stderr,exit_code)
        native=await worker_jobs.store.get(current.id)
        bound=await execution_authorization.store.get(current.id)
        assert bound.status=='consumed' and native['state'] in {'succeeded','failed','cancelled'}
        raw=args.output/'headers-private.txt';raw.write_text(stdout);raw.chmod(0o600)
        status=re.search(r'^HTTP/\S+\s+([1-5]\d\d)\b',stdout,re.M)
        after=await model_accounting.status(sid,owner)
        assert before['usage']==after['usage'],'Unexpected model accounting change during noninference observation'
        result.update(status='VERIFIED' if exit_code==0 and status else 'FAILED',
            finished_at=datetime.now(timezone.utc).isoformat(),elapsed_seconds=time.monotonic()-start,
            worker_job_id=current.id,worker_terminal_state=native['state'],exit_code=exit_code,
            authorization_consumed=True,receipt_bound=True,stdout_sha256=hashlib.sha256(stdout.encode()).hexdigest(),
            stderr_sha256=hashlib.sha256(stderr.encode()).hexdigest(),
            observed_http_status=int(status.group(1)) if status else None,
            model_usage_before=before['usage'],model_usage_after=after['usage'],
            target_submissions=1,automatic_retries=0,operational_8_5_readiness_demonstrated=False,
            limitation='One operator-corrected real-model candidate and supervised real lab observation;no post-result inference or autonomous expertise proof.')
        result_path.write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result));return 0 if result['status']=='VERIFIED' else 1
    except Exception as error:
        failure={'status':'BLOCKED','error_type':type(error).__name__,
            'result_present':result_path.exists(),'automatic_retry':False}
        (args.output/'blocked-observation.json').write_text(json.dumps(failure,indent=2)+'\n')
        print(json.dumps(failure));return 1
    finally:await engine.dispose()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('inspect','prepare','run'))
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--approval',type=Path)
    raise SystemExit(asyncio.run(main(parser.parse_args())))
