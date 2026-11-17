"""Read a specific authorized lab run into a closed, sanitized evidence view.

PostgreSQL transaction is explicitly read-only. Never prints a connection URL,
credentials, prompts, raw worker output, sealed evidence or private metadata.
This does not substitute for the graphical acceptance interactions.
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path

from sqlalchemy import select, text

from memory.database_models import AutonomousRun, DecisionLog, PentestSession, async_session, engine


def fields(data: dict, keys: tuple[str, ...]) -> dict:
    return {key: data.get(key) for key in keys}


async def collect(session_id: str, run_id: str, directory: Path) -> dict:
    async with async_session() as db:
        await db.execute(text('SET TRANSACTION READ ONLY'))
        session = await db.get(PentestSession, session_id)
        run = await db.get(AutonomousRun, run_id)
        if not session or session.target != '192.168.77.20' or not run or run.session_id != session_id:
            raise ValueError('Exact existing lab session and bound run are required')
        rows = (await db.execute(select(DecisionLog).where(DecisionLog.session_id == session_id,
            DecisionLog.decision_type.in_(('execution_authorization','worker_job','model_attempt',
                'investigation_review_state'))).order_by(DecisionLog.created_at))).scalars().all()
        authorizations = [row.metadata_ for row in rows if row.decision_type == 'execution_authorization'
            and (row.metadata_ or {}).get('turn_id') == run_id]
        job_ids = {item['id'] for item in authorizations}
        result = {'schema':'aria.reliability.lab-evidence.v1',
            'collected_at':datetime.now(timezone.utc).isoformat(), 'read_only':True,
            'session_id':session_id,'run_id':run_id,'target':session.target,
            'run':fields(run.snapshot,('run_id','run_state','reason_code','reason','original_objective',
                'evidence_job_ids','completed_observations','reviewed_evidence_job_ids','steps_taken',
                'model_calls','snapshot_revision','snapshot_generation','event_sequence')),
            'authorizations':[fields(item,('id','tool','risk','status','decision','turn_id','revision','expires_at'))
                for item in authorizations], 'jobs':[], 'model_attempts':[], 'reviews':[],
            'session_usage':fields((session.metadata_ or {}).get('model_usage') or {},('calls',
                'reserved_tokens','reported_tokens','reserved_cost_microusd','reported_cost_microusd',
                'unknown_usage_calls','unknown_cost_calls','stopped','stop_reason'))}
        for row in rows:
            data=row.metadata_ or {}
            if row.decision_type == 'worker_job' and data.get('job_id') in job_ids:
                result['jobs'].append(fields(data,('job_id','session_id','state','revision','exit_code',
                    'cancel_requested','output_hash','stderr_hash','worker_preflight','adapter_attestation')))
            elif row.decision_type == 'model_attempt' and data.get('run_id') == run_id:
                item=fields(data,('id','logical_request_id','attempt_index','run_id','provider','model',
                    'state','error_code','timestamp','finished_at','reserved_tokens','reserved_cost_microusd',
                    'reported_tokens','reported_cost_microusd','input_tokens','output_tokens','timings'))
                usage=data.get('provider_usage') or {}
                cost=usage.get('cost') if isinstance(usage,dict) else None
                item['provider_reported_cost_usd']=cost if type(cost) in (int,float) and cost>=0 else None
                result['model_attempts'].append(item)
            elif row.decision_type == 'investigation_review_state' and data.get('run_id') == run_id:
                result['reviews'].append(fields(data,('id','run_id','state','reason_code',
                    'response_sha256','evidence_job_ids')))
        result['events']=[fields(item,('type','event_sequence','step','status','run_state','reason_code',
            'action_id','timings','structured_validation_ms')) for item in run.snapshot.get('activity_log',[])]
    directory.mkdir(parents=True,exist_ok=True)
    (directory/'durable-evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


async def main(args):
    try:
        result=await collect(args.owner_session,args.run_id,Path(args.output))
        print(json.dumps({'run_id':result['run_id'],'run_state':result['run'].get('run_state'),
            'model_attempts':len(result['model_attempts']),'worker_jobs':len(result['jobs']),
            'authorization_states':[a['status'] for a in result['authorizations']],
            'read_only':True,'output':args.output}))
    finally:
        await engine.dispose()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner-session',required=True)
    parser.add_argument('--run-id',required=True)
    parser.add_argument('--output',required=True)
    asyncio.run(main(parser.parse_args()))
