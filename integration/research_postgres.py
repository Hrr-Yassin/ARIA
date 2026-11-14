"""Disposable PostgreSQL acceptance for the research event projection.

Creates/migrates a new aria_research_*_test database. No production data writes,
provider calls, target requests or worker jobs. Retains the test DB for review.
"""
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

import asyncpg
from fastapi import HTTPException
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from config.settings import settings
from memory.database_models import ChatLog, PentestSession, User
from memory.research import (ApplicationModel, CreateHypothesis, Hypothesis, ModelNode,
    ModelEdge, ResearchStore, ResearchTransition)
from memory.team_tasks import EvidenceInput, team_store


async def main():
    output=Path('.local-lab/research-benchmark');output.mkdir(parents=True,exist_ok=True)
    original=make_url(settings.DATABASE_URL)
    name='aria_research_'+uuid.uuid4().hex[:10]+'_test'
    db=await asyncpg.connect(original.set(drivername='postgresql').render_as_string(hide_password=False))
    await db.execute('CREATE DATABASE "'+name+'"');await db.close()
    url=original.set(database=name).render_as_string(hide_password=False)
    with (output/'postgres-migrations.log').open('w') as log:
        subprocess.run([sys.executable,'-m','alembic','upgrade','head'],check=True,
            env={**os.environ,'DATABASE_URL':url},stdout=log,stderr=log)
    engine=create_async_engine(url)
    factory=async_sessionmaker(engine,expire_on_commit=False)
    import memory.team_tasks as team_module
    team_module.async_session=factory  # This process only; test database guard above.
    owner,other,sid,source=[str(uuid.uuid4()) for _ in range(4)]
    try:
        async with factory() as db:
            db.add_all([User(id=owner,username='research-owner',password_hash='unused'),
                        User(id=other,username='research-other',password_hash='unused')]);await db.flush()
            db.add(PentestSession(id=sid,user_id=owner,target='lab.invalid',scope={'targets':['lab.invalid']}));await db.flush()
            db.add(ChatLog(id=source,session_id=sid,role='tool_output',msg_type='synthetic_lab',
                content='Synthetic owner baseline; no external target was contacted.',data={'source':'synthetic_lab'}))
            await db.commit()
        catalog=await team_store.catalog(sid,owner,EvidenceInput(request_id=uuid.uuid4(),source_kind='chat',source_id=source))
        ref=catalog['data']['id']
        store=ResearchStore()
        node=lambda key,kind:ModelNode(id=key,kind=kind,label=key,evidence_references=[ref])
        await store.save_model(sid,owner,ApplicationModel(request_id=uuid.uuid4(),expected_revision=0,
            nodes=[node('alice','identity'),node('private-object','object'),node('gateway','service'),node('tenant','trust_boundary')],
            edges=[ModelEdge(source='alice',target='private-object',relation='owns',condition='Controlled ownership assertion',evidence_references=[ref]),
                   ModelEdge(source='gateway',target='tenant',relation='crosses_boundary',condition='Tenant boundary requires downstream authorization',evidence_references=[ref])],
            uncertainty=['Synthetic graph; permissions require controlled testing']))
        body=CreateHypothesis(request_id=uuid.uuid4(),hypothesis=Hypothesis(title='Ownership consistency',
            claim='A downstream endpoint may omit the object owner check',vulnerability_class='cross_service_trust',
            supporting_evidence=[ref],alternative_explanations=['The response may be public metadata'],
            related_assets=['private-object'],related_components=['gateway'],
            prerequisites=['Controlled owner and outsider identities'],validation_strategy='Compare original private content across gateway and downstream',
            positive_controls=['Owner read succeeds'],negative_controls=['Outsider missing-object read has no private content'],
            confidence=.2,uncertainty=['No unauthorized disclosure has been reproduced']))
        created=await store.create(sid,owner,body)
        duplicate=await store.create(sid,owner,body)
        assert duplicate['duplicate'] and duplicate['id']==created['id']
        hid=created['entity_id']
        async def advance():
            try:return await store.transition(sid,owner,hid,ResearchTransition(request_id=uuid.uuid4(),expected_revision=1,state='HYPOTHESIZED',reason='Evaluate alternatives'))
            except HTTPException as exc:return exc.status_code
        concurrent=await asyncio.gather(advance(),advance())
        assert sum(isinstance(r,dict) for r in concurrent)==1 and 409 in concurrent
        await engine.dispose()
        restored=await ResearchStore().view(sid,owner)
        assert len(restored['hypotheses'])==1 and restored['hypotheses'][0]['revision']==2
        assert len(restored['application_model']['edges'])==2 and len(restored['queue'])==1
        try:await store.view(sid,other)
        except HTTPException as exc:assert exc.status_code in (403,404)
        else:raise AssertionError('Other owner read research')
        async with factory() as db:
            session=await db.get(PentestSession,sid);session.scope={'targets':['different.invalid']};await db.commit()
        invalidated=await store.view(sid,owner)
        assert not invalidated['queue'] and invalidated['hypotheses'][0]['requires_revalidation']
        result={'status':'passed','database':name,'session_id':sid,'checks':[
            'real SQL evidence catalog and semantic graph','idempotent creation','concurrent revision conflict',
            'reconstruction after connection pool restart','cross-owner denial','scope change invalidates priorities'],
            'provider_calls':0,'target_requests':0}
        (output/'postgres-result.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
    finally:await engine.dispose()


if __name__=='__main__':asyncio.run(main())
