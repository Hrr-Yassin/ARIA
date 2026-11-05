"""Bounded live planning + real worker receipts in aria_test.
Reads encrypted owner provider records, never changes them, and clones only encrypted
credentials into a disposable test identity. Hard budget persists across invocations.
"""
import asyncio
import fcntl
import json
import os
import uuid
from pathlib import Path
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine
from config.settings import settings
from llm.validation_budget import ValidationBudget,current_budget

ROOT=Path(__file__).resolve().parents[1]
OUTPUT=ROOT/'.local-lab/live-validation'


async def main():
    if os.environ.get('ARIA_LIVE_VALIDATION')!='1': raise SystemExit('Set ARIA_LIVE_VALIDATION=1 for bounded live model/lab validation')
    OUTPUT.mkdir(mode=0o700,exist_ok=True)
    with (OUTPUT/'budget.lock').open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        ledger=OUTPUT/'budget.json'
        used=json.loads(ledger.read_text()) if ledger.exists() else {}
        budget=ValidationBudget(calls=used.get('calls',0),reserved_tokens=used.get('reserved_token_ceiling',0),actual_tokens=used.get('reported_actual_tokens',0),ledger_path=str(ledger))
        production=settings.DATABASE_URL
        settings.DATABASE_URL=make_url(production).set(database='aria_test').render_as_string(hide_password=False)
        settings.REDIS_URL=make_url(settings.REDIS_URL).set(database='15').render_as_string(hide_password=False)
        from memory.database_models import User,UserAPIKey,PentestSession,async_session,engine
        from agents.autonomous_engine import AutonomousEngine
        from memory.worker_jobs import worker_jobs
        from memory.autonomous_runs import run_store
        source=create_async_engine(production,echo=False)
        try:
            async with source.connect() as connection:
                rows=(await connection.execute(text("SELECT provider, encrypted_key FROM user_api_keys WHERE is_active=true AND user_id=(SELECT id FROM users WHERE username=:owner)"),{'owner':'labadmin'})).mappings().all()
        finally: await source.dispose()
        uid,sid=str(uuid.uuid4()),str(uuid.uuid4())
        async with async_session() as db:
            db.add(User(id=uid,username='bounded-live-'+uid,password_hash='unused')); await db.flush()
            for row in rows:
                db.add(UserAPIKey(user_id=uid,provider=row['provider'],encrypted_key=row['encrypted_key'],requests_limit=20,label='Bounded live validation'))
            db.add(PentestSession(id=sid,user_id=uid,name='Bounded discovery validation',target='192.168.77.20',scope={'targets':['192.168.77.20'],'ports':[80]}))
            await db.commit()
        runner=AutonomousEngine(); report={'environment':'live provider and real worker; disposable database identity','session_id':sid}
        context=current_budget.set(budget)
        try:
            await worker_jobs.resume_session(uid,sid)
            started=await runner.start(sid,uid,goal='discovery',target='192.168.77.20',max_steps=4,auto_risk_threshold='green_orange')
            if started.get('active') is False: report['result']=started
            else:
                task=runner._tasks.get(sid)
                if task is not None:
                    deadline=asyncio.get_running_loop().time()+240
                    while not task.done() and asyncio.get_running_loop().time()<deadline:
                        state=runner._runs[sid]
                        if state.pending_approval and state.pending_approval.decision is None:
                            import shlex
                            from worker.policy import validate_worker_command
                            request=state.pending_approval
                            checked=validate_worker_command(request.command,{'targets':['192.168.77.20'],'ports':[80]})
                            argv=shlex.split(checked.command)
                            permitted=checked.tool in {'nmap','curl'} and not any(flag in argv for flag in ['-X','--request','-d','--data','--data-raw','-H','--header'])
                            if permitted:
                                await runner.provide_approval_decision(sid,request.action_id,'approve',user_id=uid)
                                report.setdefault('fixture_approvals',[]).append({'command':checked.command,'authorization':'pre-authorized bounded lab observation profile'})
                            else:
                                await runner.provide_approval_decision(sid,request.action_id,'reject',user_id=uid)
                        await asyncio.sleep(.1)
                    if not task.done(): await runner.request_stop(sid,user_id=uid)
                    else: await task
                report['result']=runner.get_status(sid)
            result=report['result']
            if result.get('run_state')=='completed':
                assert len(result['evidence_job_ids'])>=2 and set(result['completed_observations'])=={'port_discovery','http_response'}
                jobs=await worker_jobs.list_status(uid,sid)
                assert all(job['state']=='succeeded' for job in jobs)
                report['case_status']='passed'
            elif result.get('run_state')=='blocked': report['case_status']='blocked'
            else: report['case_status']='failed'
            report['durable_snapshot']=await run_store.latest(sid)
        except Exception as exc:
            report.update(case_status='blocked',reason=type(exc).__name__)
        finally:
            await runner.shutdown(); current_budget.reset(context)
            budget.persist(); report['budget']=budget.snapshot()
            from security.redaction import redact
            (OUTPUT/'report.json').write_text(json.dumps(redact(report),indent=2))
            (OUTPUT/('run-'+sid+'.json')).write_text(json.dumps(redact(report),indent=2))
            await engine.dispose()
        print(json.dumps({'case_status':report['case_status'],'run_state':report.get('result',{}).get('run_state'),'budget':budget.snapshot()},indent=2))


if __name__=='__main__': asyncio.run(main())
